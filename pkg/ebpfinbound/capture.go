// SPDX-License-Identifier: AGPL-3.0-only

package ebpfinbound

import (
	"errors"
	"fmt"
	"net"
)

const (
	DefaultTProxyPort       = uint16(12345)
	DefaultOutputMark       = uint32(0x100)
	DefaultConnStateEntries = uint32(262144)
)

// CaptureConfig contains only Linux capture-datapath settings. It has no DNS,
// routing, sniffing, outbound, or proxy-protocol options; those belong to the
// importing traffic engine.
type CaptureConfig struct {
	TProxyPort                uint16
	LANInterfaces             []string
	WANInterfaces             []string
	OutputMark                uint32
	AutoConfigureKernel       bool
	ConnectionStateMapEntries uint32
}

func (c CaptureConfig) WithDefaults() CaptureConfig {
	c.LANInterfaces = append([]string(nil), c.LANInterfaces...)
	c.WANInterfaces = append([]string(nil), c.WANInterfaces...)
	if c.TProxyPort == 0 {
		c.TProxyPort = DefaultTProxyPort
	}
	if c.OutputMark == 0 {
		c.OutputMark = DefaultOutputMark
	}
	if c.ConnectionStateMapEntries == 0 {
		c.ConnectionStateMapEntries = DefaultConnStateEntries
	}
	return c
}

func (c CaptureConfig) Validate() error {
	c = c.WithDefaults()
	if len(c.LANInterfaces) == 0 && len(c.WANInterfaces) == 0 {
		return errors.New("at least one LAN or WAN interface is required")
	}
	if c.ConnectionStateMapEntries < 1024 {
		return fmt.Errorf("connection-state map size %d is too small", c.ConnectionStateMapEntries)
	}
	return nil
}

// SocketGeneration adapts transparent sockets owned by another userspace
// engine. Close is intentionally a no-op because that engine retains socket
// ownership. Runtime-created generations have their own closing implementation.
type SocketGeneration struct {
	TCP4Listener net.Listener
	TCP6Listener net.Listener
	UDPConn      *net.UDPConn
	ListenPort   uint16
}

func (g *SocketGeneration) TCP4() net.Listener { return g.TCP4Listener }
func (g *SocketGeneration) TCP6() net.Listener { return g.TCP6Listener }
func (g *SocketGeneration) UDP() *net.UDPConn  { return g.UDPConn }
func (g *SocketGeneration) Port() uint16       { return g.ListenPort }
func (g *SocketGeneration) Close() error       { return nil }

func NewSocketGeneration(tcp4, tcp6 net.Listener, udp *net.UDPConn, port uint16) (Generation, error) {
	if tcp4 == nil || tcp6 == nil || udp == nil {
		return nil, errors.New("TCP4, TCP6, and UDP listeners are required")
	}
	return &SocketGeneration{
		TCP4Listener: tcp4,
		TCP6Listener: tcp6,
		UDPConn:      udp,
		ListenPort:   port,
	}, nil
}
