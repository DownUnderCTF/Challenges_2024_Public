package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/netip"
	"os"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

func getFlag() string {
	return os.Getenv("FLAG")
}

func randomMac() tcpip.LinkAddress {
	var buf [3]byte

	rand.Read(buf[:])

	return tcpip.LinkAddress(append([]byte{0x88, 0x75, 0x56}, buf[:]...))
}

type VPNConnection struct {
	id      string
	stack   *stack.Stack
	channel *channel.Endpoint
}

func (vpn *VPNConnection) startNetwork() error {
	listen, err := gonet.ListenTCP(vpn.stack, tcpip.FullAddress{
		Addr: tcpip.AddrFromSlice([]byte{10, 0, 0, 1}),
		Port: 80,
	}, ipv4.ProtocolNumber)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()

	// Start a internal server to provide the application.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		slog.Info("client made request for flag", "id", vpn.id)
		fmt.Fprintf(w, "%s", getFlag())
	})

	// Create the http.Server with the mux as the handler.
	server := http.Server{
		Handler: mux,
	}

	go func() {
		// Listen on the new internal listener we created.
		if err := server.Serve(listen); err != nil {
			slog.Warn("failed to serve HTTP", "id", vpn.id, "err", err)
		}
	}()

	return nil
}

func CreateConnection(conn *websocket.Conn) error {
	vpn := &VPNConnection{}

	// Set a unique id for the VPN for error corelation.
	vpn.id = uuid.NewString()

	slog.Info("got VPN connection", "from", conn.RemoteAddr().String(), "id", vpn.id)

	// Create the main TCP/IP stack supporting IPv4, ARP, TCP, and ICMP.
	vpn.stack = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, icmp.NewProtocol4},
		HandleLocal:        true,
	})

	// Create a channel to insert and pull packets from.
	vpn.channel = channel.New(32, 1500, randomMac())

	// Bind the channel to the network stack.
	if err := vpn.stack.CreateNIC(1, vpn.channel); err != nil {
		return fmt.Errorf("(id=%s) error creating NIC: %s", vpn.id, err)
	}

	// Add a IP Address (10.0.0.1/8)
	if err := vpn.stack.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			PrefixLen: 8,
			Address:   tcpip.AddrFromSlice([]byte{10, 0, 0, 1}),
		},
	}, stack.AddressProperties{}); err != nil {
		return fmt.Errorf("(id=%s) error adding IP address: %s", vpn.id, err)
	}

	// Add a defaUlt route.
	remoteAddr, err := netip.ParseAddr("0.0.0.0")
	if err != nil {
		log.Fatal(err)
	}

	subnet, err := tcpip.NewSubnet(tcpip.AddrFromSlice(remoteAddr.AsSlice()), tcpip.MaskFromBytes([]byte{0x00, 0x00, 0x00, 0x00}))
	if err != nil {
		log.Fatal(err)
	}

	vpn.stack.AddRoute(tcpip.Route{
		Destination: subnet,
		Gateway:     subnet.ID(),
		NIC:         1,
	})

	// Finally start applications inside the network.
	if err := vpn.startNetwork(); err != nil {
		return fmt.Errorf("(id=%s) failed to start network: %s", vpn.id, err)
	}

	// Write packets from the stack to the websocket.
	go func() {
		for {
			// Read the packet from the stack.
			pkt := vpn.channel.ReadContext(context.Background())
			if pkt == nil {
				continue
			}

			// Make sure to release the packet buffer back into the pool after were done with it.
			defer pkt.DecRef()

			// Convert the packet into a slice.
			bytes := pkt.ToView().AsSlice()

			// Write the message to the websocket.
			if err := conn.WriteMessage(websocket.BinaryMessage, bytes); err != nil {
				slog.Warn("failed to write message to websocket", "client", vpn.id, "err", err)
				return
			}
		}
	}()

	// Write a message to the client to notify them that they have connected.
	conn.WriteJSON(&struct {
		Message string
	}{
		Message: "Connected to WSVPN: Host is http://10.0.0.1",
	})

	// Read messages from the websocket and write them into the TCP/IP stack.
	for {
		// Read the message.
		typ, msg, err := conn.ReadMessage()
		if err != nil {
			return fmt.Errorf("(id=%s) failed to read message: %s", vpn.id, err)
		}

		// Check that it's a binary message.
		if typ != websocket.BinaryMessage {
			return fmt.Errorf("(id=%s) message was not a binary message: %d", vpn.id, typ)
		}

		// Make a packet buffer from the bytes sent by the client.
		// This is a raw L3 packet.
		buf := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(msg),
		})

		// Actually deliver the packet to the TCP/IP stack.
		vpn.channel.InjectInbound(ipv4.ProtocolNumber, buf)
	}
}

var (
	addr = flag.String("addr", "localhost:1337", "The web address for the server to listen on.")
)

func main() {
	flag.Parse()

	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}

	http.HandleFunc("/connect", func(w http.ResponseWriter, r *http.Request) {
		// Upgrade the connection to a websocket.
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			slog.Error("error upgrading websocket", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer conn.Close()

		// Start the WSVPN client.
		if err := CreateConnection(conn); err != nil {
			slog.Error("error handling vpn connection", "err", err)
			return
		}
	})

	// Give the user a simple homepage if they access with a regular browser.
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "please connect with the wsvpn client.\n")
	})

	slog.Info("listening", "addr", " http://"+*addr)

	log.Fatal(http.ListenAndServe(*addr, nil))
}
