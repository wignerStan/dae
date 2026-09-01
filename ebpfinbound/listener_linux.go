//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only

package ebpfinbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type listenerSet struct {
	port uint16
	tcp4 net.Listener
	tcp6 net.Listener
	udp *net.UDPConn
	closeOnce sync.Once
	closeErr error
}

func (s *listenerSet) TCP4() net.Listener { if s == nil { return nil }; return s.tcp4 }
func (s *listenerSet) TCP6() net.Listener { if s == nil { return nil }; return s.tcp6 }
func (s *listenerSet) UDP() *net.UDPConn { if s == nil { return nil }; return s.udp }
func (s *listenerSet) Port() uint16 { if s == nil { return 0 }; return s.port }

func (s *listenerSet) close() error {
	if s == nil { return nil }
	s.closeOnce.Do(func() {
		var errs []error
		if s.tcp4 != nil { wakeTCPListener(s.tcp4); if err := s.tcp4.Close(); err != nil && !errors.Is(err, net.ErrClosed) { errs = append(errs, err) } }
		if s.tcp6 != nil { wakeTCPListener(s.tcp6); if err := s.tcp6.Close(); err != nil && !errors.Is(err, net.ErrClosed) { errs = append(errs, err) } }
		if s.udp != nil { wakeUDPConn(s.udp); if err := s.udp.Close(); err != nil && !errors.Is(err, net.ErrClosed) { errs = append(errs, err) } }
		s.closeErr = errors.Join(errs...)
	})
	return s.closeErr
}

func openListenerSet(ctx context.Context, port uint16, logger interface{ Warn(string, ...any) }) (*listenerSet, error) {
	if ctx == nil { ctx = context.Background() }; if err := ctx.Err(); err != nil { return nil, err }
	tcpConfig := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error { return transparentSocketControl(raw) }}
	udpConfig := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error { if err := transparentSocketControl(raw); err != nil { return err }; return enableDualStack(raw) }}
	portString := strconv.Itoa(int(port))
	tcp4, err := tcpConfig.Listen(ctx, "tcp4", net.JoinHostPort("0.0.0.0", portString)); if err != nil { return nil, fmt.Errorf("listen TCP4: %w", err) }
	tcp6, err := tcpConfig.Listen(ctx, "tcp6", net.JoinHostPort("::", portString)); if err != nil { _ = tcp4.Close(); return nil, fmt.Errorf("listen TCP6: %w", err) }
	packetConn, err := udpConfig.ListenPacket(ctx, "udp6", net.JoinHostPort("::", portString))
	if err != nil {
		if logger != nil { logger.Warn("dual-stack UDP listener unavailable; falling back to IPv4", "error", err) }
		packetConn, err = tcpConfig.ListenPacket(ctx, "udp4", net.JoinHostPort("0.0.0.0", portString))
		if err != nil { _ = tcp4.Close(); _ = tcp6.Close(); return nil, fmt.Errorf("listen UDP: %w", err) }
	}
	udp, ok := packetConn.(*net.UDPConn); if !ok { _ = tcp4.Close(); _ = tcp6.Close(); _ = packetConn.Close(); return nil, fmt.Errorf("unexpected UDP listener type %T", packetConn) }
	return &listenerSet{port: port, tcp4: tcp4, tcp6: tcp6, udp: udp}, nil
}

func transparentSocketControl(raw syscall.RawConn) error {
	var socketErr error
	controlErr := raw.Control(func(fd uintptr) {
		ipv4Err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TRANSPARENT, 1)
		ipv6Err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_TRANSPARENT, 1)
		if ipv4Err != nil && ipv6Err != nil { socketErr = fmt.Errorf("set transparent socket options: IPv4=%v, IPv6=%v", ipv4Err, ipv6Err); return }
		if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil { socketErr = fmt.Errorf("set SO_REUSEADDR: %w", err); return }
		orig4Err := unix.SetsockoptInt(int(fd), syscall.SOL_IP, unix.IP_RECVORIGDSTADDR, 1)
		orig6Err := unix.SetsockoptInt(int(fd), syscall.SOL_IPV6, unix.IPV6_RECVORIGDSTADDR, 1)
		if orig4Err != nil && orig6Err != nil { socketErr = fmt.Errorf("enable original-destination control messages: IPv4=%v, IPv6=%v", orig4Err, orig6Err) }
	})
	if controlErr != nil { return fmt.Errorf("invoke socket control: %w", controlErr) }
	return socketErr
}

func enableDualStack(raw syscall.RawConn) error { var socketErr error; controlErr := raw.Control(func(fd uintptr) { if err := unix.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, unix.IPV6_V6ONLY, 0); err != nil { socketErr = fmt.Errorf("disable IPV6_V6ONLY: %w", err) } }); if controlErr != nil { return fmt.Errorf("invoke dual-stack socket control: %w", controlErr) }; return socketErr }
func wakeTCPListener(listener net.Listener) { if tcp, ok := listener.(*net.TCPListener); ok && tcp != nil { _ = tcp.SetDeadline(time.Now()) } }
func wakeUDPConn(conn *net.UDPConn) { if conn == nil { return }; now := time.Now(); _ = conn.SetReadDeadline(now); _ = conn.SetWriteDeadline(now) }
func duplicateTCPListener(listener net.Listener) (*os.File, error) { tcp, ok := listener.(*net.TCPListener); if !ok || tcp == nil { return nil, fmt.Errorf("unexpected TCP listener type %T", listener) }; raw, err := tcp.SyscallConn(); if err != nil { return nil, err }; return duplicateRawConn(raw, "dae-ebpfinbound-tcp") }
func duplicateUDPConn(conn *net.UDPConn) (*os.File, error) { if conn == nil { return nil, errors.New("nil UDP connection") }; raw, err := conn.SyscallConn(); if err != nil { return nil, err }; return duplicateRawConn(raw, "dae-ebpfinbound-udp") }
func duplicateRawConn(raw syscall.RawConn, name string) (*os.File, error) { var duplicate int; var duplicateErr error; if err := raw.Control(func(fd uintptr) { duplicate, duplicateErr = unix.Dup(int(fd)); if duplicateErr == nil { unix.CloseOnExec(duplicate) } }); err != nil { return nil, err }; if duplicateErr != nil { return nil, duplicateErr }; return os.NewFile(uintptr(duplicate), name), nil }
