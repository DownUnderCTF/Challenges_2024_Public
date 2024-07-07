package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

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

func randomMac() tcpip.LinkAddress {
	var buf [3]byte

	rand.Read(buf[:])

	return tcpip.LinkAddress(append([]byte{0x88, 0x75, 0x56}, buf[:]...))
}

var addr = flag.String("addr", "127.0.0.1:1337", "the address of the wsvpn server to connect to.")

func main() {
	flag.Parse()

	// Dial the server.
	conn, _, err := websocket.DefaultDialer.Dial(fmt.Sprintf("wss://%s/connect", *addr), nil)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	// Read the hello message.
	var msg struct {
		Message string
	}
	if err := conn.ReadJSON(&msg); err != nil {
		log.Fatal(err)
	}

	slog.Info("Connected", "hello", msg.Message)

	// Create the TCP/IP Stack.
	ns := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, icmp.NewProtocol4},
		HandleLocal:        true,
	})

	// Create a channel for packets.
	nsChannel := channel.New(32, 1500, randomMac())

	if err := ns.CreateNIC(1, nsChannel); err != nil {
		log.Fatal("error creating nic", err)
	}

	// Assign 10.0.0.2 as the IP address.
	if err := ns.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			PrefixLen: 8,
			Address:   tcpip.AddrFromSlice([]byte{10, 0, 0, 2}),
		},
	}, stack.AddressProperties{}); err != nil {
		log.Fatal("error adding IP address", err)
	}

	// Add a default route.
	remoteAddr, err := netip.ParseAddr("0.0.0.0")
	if err != nil {
		log.Fatal(err)
	}

	subnet, err := tcpip.NewSubnet(tcpip.AddrFromSlice(remoteAddr.AsSlice()), tcpip.MaskFromBytes([]byte{0x00, 0x00, 0x00, 0x00}))
	if err != nil {
		log.Fatal(err)
	}

	ns.AddRoute(tcpip.Route{
		Destination: subnet,
		Gateway:     subnet.ID(),
		NIC:         1,
	})

	// Read packets from the stack and send them over the websocket.
	go func() {
		for {
			pkt := nsChannel.ReadContext(context.Background())
			if pkt == nil {
				continue
			}
			defer pkt.DecRef()

			bytes := pkt.ToView().AsSlice()

			if err := conn.WriteMessage(websocket.BinaryMessage, bytes); err != nil {
				slog.Warn("failed to write message to websocket", "err", err)
				return
			}
		}
	}()

	// Read packets from the websocket and send them to the stack.
	go func() {
		for {
			typ, msg, err := conn.ReadMessage()
			if err != nil {
				log.Fatal("failed to read message", err)
			}

			if typ != websocket.BinaryMessage {
				log.Fatal("message was not a binary message", typ)
			}

			buf := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(msg),
			})

			nsChannel.InjectInbound(ipv4.ProtocolNumber, buf)
		}
	}()

	// Create a HTTP client that establishes connections using the TCP/IP stack.
	client := http.Client{
		Transport: &http.Transport{Dial: func(network, addr string) (net.Conn, error) {
			tokens := strings.Split(addr, ":")

			ip, err := netip.ParseAddr(tokens[0])
			if err != nil {
				return nil, err
			}

			port, err := strconv.Atoi(tokens[1])
			if err != nil {
				return nil, err
			}

			return gonet.DialTCP(ns, tcpip.FullAddress{
				Addr: tcpip.AddrFromSlice(ip.AsSlice()),
				Port: uint16(port),
			}, ipv4.ProtocolNumber)
		}},
	}

	resp, err := client.Get("http://10.0.0.1/")
	if err != nil {
		log.Fatal(err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	slog.Info("got flag", "body", body)
}
