//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/daeipc"
)

func TestOpenExternalPolicySessionRegistration(t *testing.T) {
	listener := newExternalPolicyTestListener(t, false)
	defer closeExternalPolicyTestListener(listener)
	socketPath := filepath.Join(t.TempDir(), "policy.sock")
	server, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: socketPath, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	serverDone := make(chan error, 1)
	go func() {
		conn, err := server.AcceptUnix()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		message, files, err := daeipc.Read(conn)
		if err != nil {
			serverDone <- err
			return
		}
		defer closeExternalPolicyFiles(files)
		if message.Type != daeipc.TypeRegister {
			serverDone <- fmt.Errorf("message type = %q", message.Type)
			return
		}
		if message.Generation == 0 {
			serverDone <- errors.New("registration generation is zero")
			return
		}
		if message.TProxyPort != listener.port {
			serverDone <- fmt.Errorf("registration port = %d, want %d", message.TProxyPort, listener.port)
			return
		}
		if message.OutputMark != 0x73ae {
			serverDone <- fmt.Errorf("registration mark = %#x", message.OutputMark)
			return
		}
		wantKinds := []string{daeipc.ListenerTCP4, daeipc.ListenerTCP6, daeipc.ListenerUDP4}
		if strings.Join(message.Listeners, ",") != strings.Join(wantKinds, ",") {
			serverDone <- fmt.Errorf("listener kinds = %v, want %v", message.Listeners, wantKinds)
			return
		}
		if len(files) != len(wantKinds) {
			serverDone <- fmt.Errorf("descriptor count = %d, want %d", len(files), len(wantKinds))
			return
		}
		if err := verifyExternalPolicyListenerDescriptors(files, wantKinds, listener.port); err != nil {
			serverDone <- err
			return
		}
		ack := daeipc.NewMessage(daeipc.TypeRegisterAck)
		ack.Generation = message.Generation
		serverDone <- daeipc.Write(conn, ack)
	}()

	controlPlane := &ControlPlane{
		ctx:                  context.Background(),
		externalPolicySocket: socketPath,
		externalPolicyUID:    uint32(os.Geteuid()),
		soMarkFromDae:        0x73ae,
	}
	session, err := controlPlane.openExternalPolicySession(listener)
	if err != nil {
		t.Fatal(err)
	}
	defer session.conn.Close()
	if session.generation == 0 {
		t.Fatal("session generation is zero")
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}

	// Descriptor handoff duplicates listeners; it must not retire dae's copy.
	if err := listener.tcp4Listener.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("original TCP4 listener was closed: %v", err)
	}
	if err := listener.tcp4Listener.(*net.TCPListener).SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
}

func TestOpenExternalPolicySessionRejectsInvalidPeerAndAcknowledgement(t *testing.T) {
	t.Run("peer uid", func(t *testing.T) {
		listener := newExternalPolicyTestListener(t, false)
		defer closeExternalPolicyTestListener(listener)
		socketPath := filepath.Join(t.TempDir(), "policy.sock")
		server, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: socketPath, Net: "unixpacket"})
		if err != nil {
			t.Fatal(err)
		}
		defer server.Close()
		accepted := make(chan error, 1)
		go func() {
			conn, err := server.AcceptUnix()
			if err == nil {
				_ = conn.Close()
			}
			accepted <- err
		}()
		controlPlane := &ControlPlane{
			ctx:                  context.Background(),
			externalPolicySocket: socketPath,
			externalPolicyUID:    uint32(os.Geteuid()) + 1,
		}
		if session, err := controlPlane.openExternalPolicySession(listener); err == nil {
			_ = session.conn.Close()
			t.Fatal("unexpected peer uid was accepted")
		}
		if err := <-accepted; err != nil {
			t.Fatal(err)
		}
	})

	tests := []struct {
		name    string
		respond func(register daeipc.Message) (daeipc.Message, *os.File, error)
		wantErr string
	}{
		{
			name: "wrong type",
			respond: func(register daeipc.Message) (daeipc.Message, *os.File, error) {
				message := daeipc.NewMessage(daeipc.TypePong)
				message.Generation = register.Generation
				return message, nil, nil
			},
			wantErr: "unexpected external policy response",
		},
		{
			name: "wrong generation",
			respond: func(register daeipc.Message) (daeipc.Message, *os.File, error) {
				message := daeipc.NewMessage(daeipc.TypeRegisterAck)
				message.Generation = register.Generation + 1
				return message, nil, nil
			},
			wantErr: "acknowledged generation",
		},
		{
			name: "explicit rejection",
			respond: func(register daeipc.Message) (daeipc.Message, *os.File, error) {
				message := daeipc.NewMessage(daeipc.TypeRegisterAck)
				message.Generation = register.Generation
				message.Error = "listener conflict"
				return message, nil, nil
			},
			wantErr: "listener conflict",
		},
		{
			name: "unexpected descriptor",
			respond: func(register daeipc.Message) (daeipc.Message, *os.File, error) {
				message := daeipc.NewMessage(daeipc.TypeRegisterAck)
				message.Generation = register.Generation
				file, err := os.Open("/dev/null")
				if err != nil {
					return message, nil, err
				}
				return message, file, nil
			},
			wantErr: "unexpected file descriptors",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			listener := newExternalPolicyTestListener(t, false)
			defer closeExternalPolicyTestListener(listener)
			socketPath := filepath.Join(t.TempDir(), "policy.sock")
			server, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: socketPath, Net: "unixpacket"})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			serverDone := make(chan error, 1)
			go func() {
				conn, err := server.AcceptUnix()
				if err != nil {
					serverDone <- err
					return
				}
				defer conn.Close()
				register, files, err := daeipc.Read(conn)
				closeExternalPolicyFiles(files)
				if err != nil {
					serverDone <- err
					return
				}
				response, file, responseErr := test.respond(register)
				if responseErr != nil {
					serverDone <- responseErr
					return
				}
				if file != nil {
					defer file.Close()
					serverDone <- daeipc.Write(conn, response, file)
				} else {
					serverDone <- daeipc.Write(conn, response)
				}
			}()
			controlPlane := &ControlPlane{
				ctx:                  context.Background(),
				externalPolicySocket: socketPath,
				externalPolicyUID:    uint32(os.Geteuid()),
				soMarkFromDae:        0x100,
			}
			session, err := controlPlane.openExternalPolicySession(listener)
			if session != nil {
				_ = session.conn.Close()
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("openExternalPolicySession() = %v, want error containing %q", err, test.wantErr)
			}
			if err := <-serverDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDialExternalPolicyCancellationAndRetry(t *testing.T) {
	t.Run("cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		started := time.Now()
		if conn, err := dialExternalPolicy(ctx, filepath.Join(t.TempDir(), "missing.sock")); err == nil {
			_ = conn.Close()
			t.Fatal("dial succeeded for missing socket")
		}
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("cancelled dial took %v", elapsed)
		}
	})

	t.Run("listener appears", func(t *testing.T) {
		socketPath := filepath.Join(t.TempDir(), "late.sock")
		listenerReady := make(chan *net.UnixListener, 1)
		listenerError := make(chan error, 1)
		go func() {
			time.Sleep(2 * externalPolicyConnectMinDelay)
			listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: socketPath, Net: "unixpacket"})
			if err != nil {
				listenerError <- err
				return
			}
			listenerReady <- listener
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		conn, err := dialExternalPolicy(ctx, socketPath)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
		select {
		case listener := <-listenerReady:
			_ = listener.Close()
		case err := <-listenerError:
			t.Fatal(err)
		case <-time.After(time.Second):
			t.Fatal("late listener was not created")
		}
	})

	if conn, err := dialExternalPolicy(context.Background(), "   "); err == nil {
		_ = conn.Close()
		t.Fatal("empty socket path was accepted")
	}
}

func TestServeExternalPolicySessionProtocol(t *testing.T) {
	t.Run("ping and invalid lookup", func(t *testing.T) {
		server, client := externalPolicyPacketPair(t)
		defer client.Close()
		ctx, cancel := context.WithCancel(context.Background())
		controlPlane := &ControlPlane{ctx: ctx}
		done := make(chan error, 1)
		go func() {
			done <- controlPlane.serveExternalPolicySession(&externalPolicySession{conn: server, generation: 77})
		}()

		ping := daeipc.NewMessage(daeipc.TypePing)
		ping.RequestID = 41
		if err := daeipc.Write(client, ping); err != nil {
			t.Fatal(err)
		}
		pong, files, err := daeipc.Read(client)
		closeExternalPolicyFiles(files)
		if err != nil {
			t.Fatal(err)
		}
		if pong.Type != daeipc.TypePong || pong.RequestID != 41 || pong.Generation != 77 {
			t.Fatalf("pong = %#v", pong)
		}

		lookup := daeipc.NewMessage(daeipc.TypeLookup)
		lookup.RequestID = 42
		lookup.Generation = 76
		if err := daeipc.Write(client, lookup); err != nil {
			t.Fatal(err)
		}
		response, files, err := daeipc.Read(client)
		closeExternalPolicyFiles(files)
		if err != nil {
			t.Fatal(err)
		}
		if response.Type != daeipc.TypeLookupResponse || response.RequestID != 42 || !strings.Contains(response.Error, "generation mismatch") {
			t.Fatalf("lookup response = %#v", response)
		}
		cancel()
		if err := <-done; err != nil {
			t.Fatalf("serve after cancellation: %v", err)
		}
	})

	tests := []struct {
		name     string
		message  daeipc.Message
		withFile bool
		wantErr  string
	}{
		{name: "unsupported type", message: daeipc.NewMessage("unsupported"), wantErr: "unsupported external policy message type"},
		{name: "unexpected descriptor", message: daeipc.NewMessage(daeipc.TypePing), withFile: true, wantErr: "unexpected file descriptors"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, client := externalPolicyPacketPair(t)
			defer client.Close()
			controlPlane := &ControlPlane{ctx: context.Background()}
			done := make(chan error, 1)
			go func() {
				done <- controlPlane.serveExternalPolicySession(&externalPolicySession{conn: server, generation: 1})
			}()
			if test.withFile {
				file, err := os.Open("/dev/null")
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				if err := daeipc.Write(client, test.message, file); err != nil {
					t.Fatal(err)
				}
			} else if err := daeipc.Write(client, test.message); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("serveExternalPolicySession() = %v, want %q", err, test.wantErr)
			}
		})
	}

	if err := new(ControlPlane).serveExternalPolicySession(nil); err == nil {
		t.Fatal("invalid session was accepted")
	}
}

func TestExternalPolicyLookupRequestValidation(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*daeipc.Message)
		wantErr string
	}{
		{name: "generation", mutate: func(message *daeipc.Message) { message.Generation = 8 }, wantErr: "generation mismatch"},
		{name: "request id", mutate: func(message *daeipc.Message) { message.RequestID = 0 }, wantErr: "missing request_id"},
		{name: "network", mutate: func(message *daeipc.Message) { message.Network = "icmp" }, wantErr: "unsupported network"},
		{name: "source", mutate: func(message *daeipc.Message) { message.Source = "invalid" }, wantErr: "invalid source"},
		{name: "destination", mutate: func(message *daeipc.Message) { message.Destination = "invalid" }, wantErr: "invalid destination"},
		{name: "missing core", mutate: func(message *daeipc.Message) {}, wantErr: "control plane is unavailable"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := daeipc.NewMessage(daeipc.TypeLookup)
			request.RequestID = 1
			request.Generation = 9
			request.Network = daeipc.NetworkTCP
			request.Source = "127.0.0.1:1234"
			request.Destination = "1.1.1.1:443"
			test.mutate(&request)
			response := (&ControlPlane{ctx: context.Background()}).externalPolicyLookupResponse(request, 9)
			if response.Type != daeipc.TypeLookupResponse || response.RequestID != request.RequestID || response.Generation != 9 {
				t.Fatalf("response envelope = %#v", response)
			}
			if !strings.Contains(response.Error, test.wantErr) {
				t.Fatalf("response error = %q, want %q", response.Error, test.wantErr)
			}
		})
	}
}

func newExternalPolicyTestListener(t *testing.T, udp6 bool) *Listener {
	t.Helper()
	tcp4, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(tcp4.Addr().(*net.TCPAddr).Port)
	tcp6, err := net.Listen("tcp6", net.JoinHostPort("::1", strconv.Itoa(int(port))))
	if err != nil {
		_ = tcp4.Close()
		t.Skipf("IPv6 listener unavailable: %v", err)
	}
	udpNetwork := "udp4"
	udpAddress := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
	if udp6 {
		udpNetwork = "udp6"
		udpAddress = net.JoinHostPort("::1", strconv.Itoa(int(port)))
	}
	udp, err := net.ListenPacket(udpNetwork, udpAddress)
	if err != nil {
		_ = tcp4.Close()
		_ = tcp6.Close()
		t.Fatal(err)
	}
	return &Listener{tcp4Listener: tcp4, tcp6Listener: tcp6, packetConn: udp, port: port}
}

func closeExternalPolicyTestListener(listener *Listener) {
	if listener == nil {
		return
	}
	if listener.tcp4Listener != nil {
		_ = listener.tcp4Listener.Close()
	}
	if listener.tcp6Listener != nil {
		_ = listener.tcp6Listener.Close()
	}
	if listener.packetConn != nil {
		_ = listener.packetConn.Close()
	}
}

func verifyExternalPolicyListenerDescriptors(files []*os.File, kinds []string, port uint16) error {
	for index, kind := range kinds {
		switch kind {
		case daeipc.ListenerTCP4, daeipc.ListenerTCP6:
			listener, err := net.FileListener(files[index])
			if err != nil {
				return err
			}
			address := listener.Addr()
			_ = listener.Close()
			if uint16(address.(*net.TCPAddr).Port) != port {
				return fmt.Errorf("listener %s port = %d, want %d", kind, address.(*net.TCPAddr).Port, port)
			}
		case daeipc.ListenerUDP4, daeipc.ListenerUDP6:
			packetConn, err := net.FilePacketConn(files[index])
			if err != nil {
				return err
			}
			address := packetConn.LocalAddr()
			_ = packetConn.Close()
			if uint16(address.(*net.UDPAddr).Port) != port {
				return fmt.Errorf("listener %s port = %d, want %d", kind, address.(*net.UDPAddr).Port, port)
			}
		default:
			return fmt.Errorf("unexpected listener kind %q", kind)
		}
	}
	return nil
}

func externalPolicyPacketPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pair.sock")
	listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	clientChannel := make(chan *net.UnixConn, 1)
	errorChannel := make(chan error, 1)
	go func() {
		client, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: path, Net: "unixpacket"})
		if err != nil {
			errorChannel <- err
			return
		}
		clientChannel <- client
	}()
	_ = listener.SetDeadline(time.Now().Add(5 * time.Second))
	server, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	select {
	case client := <-clientChannel:
		return server, client
	case err := <-errorChannel:
		_ = server.Close()
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		_ = server.Close()
		t.Fatal("timed out creating unixpacket pair")
	}
	return nil, nil
}
