package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "embed"

	"github.com/charmbracelet/log"
	"github.com/charmbracelet/ssh"
	"github.com/charmbracelet/wish"
	"github.com/charmbracelet/wish/elapsed"
	// "github.com/charmbracelet/wish/logging"
)

const (
	host = "0.0.0.0"
	port = "1337"
)

//go:embed greeting.txt
var banner string

type Logger interface {
	Printf(format string, v ...interface{})
}

func MiddlewareWithLogger(logger Logger) wish.Middleware {
	return func(next ssh.Handler) ssh.Handler {
		return func(sess ssh.Session) {
			ct := time.Now()
			hpk := sess.PublicKey() != nil
			pty, _, _ := sess.Pty()
			logger.Printf(
				"%s connect %s %v %v %s %v %v %v",
				sess.User(),
				sess.RemoteAddr().String(),
				hpk,
				sess.Command(),
				pty.Term,
				pty.Window.Width,
				pty.Window.Height,
				sess.Context().ClientVersion(),
			)
			if len(sess.Command()) > 0 {
				Log.Info(sess.Command())
				Log.Info(sess.Command()[0])
				if sess.Command()[0] == "UnlockTheCells" {
					wish.Printf(sess, fmt.Sprintf("%v\n%v", "Welcome Warden, running command", os.Getenv("WARDEN")))
				}
			}
			next(sess)
			logger.Printf(
				"%s disconnect %s\n",
				sess.RemoteAddr().String(),
				time.Since(ct),
			)
		}
	}
}

func RunSSH() {
	s, err := wish.NewServer(
		wish.WithAddress(net.JoinHostPort(host, port)),
		wish.WithHostKeyPath(".ssh/ided25519"),
		// A banner is always snown, even before authentication.
		wish.WithBannerHandler(func(ctx ssh.Context) string {
			return fmt.Sprintf(banner, ctx.User())
		}),
		wish.WithPasswordAuth(func(ctx ssh.Context, password string) bool {
			return password == "ManIReallyHateThoseDamnKookaburras!"
		}),
		wish.WithMiddleware(
			func(next ssh.Handler) ssh.Handler {
				return func(sess ssh.Session) {
					wish.Println(sess, fmt.Sprintf("Welcome, %s!", sess.User()))
					wish.Println(sess, fmt.Sprintf("This is the Kookaburra holding cells.\n\tContained: 11912 Kookaburras\n\t-> No valid command"))
					next(sess)
				}
			},
			MiddlewareWithLogger(log.StandardLog()),
			// logging.Middleware(),
			// This middleware prints the session duration before disconnecting
			elapsed.Middleware(),
		),
	)
	if err != nil {
		Log.Error("Could not start servre", "error", err)
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	Log.Info("Starting SSH Server", "host", host, "port", port)
	go func() {
		if err = s.ListenAndServe(); err != nil && !errors.Is(err, ssh.ErrServerClosed) {
			Log.Error("Could not start server", "error", err)
			done <- nil
		}
	}()

	<-done
	Log.Info("Stopping SSH server")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer func() { cancel() }()
	if err := s.Shutdown(ctx); err != nil && !errors.Is(err, ssh.ErrServerClosed) {
		Log.Error("Could not stop server", "error", err)
	}
}

func main() {
	StartLogger("")
	RunSSH()
}
