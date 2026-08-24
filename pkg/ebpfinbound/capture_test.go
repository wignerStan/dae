// SPDX-License-Identifier: AGPL-3.0-only

package ebpfinbound

import (
	"net"
	"testing"
)

func TestCaptureConfigDefaultsAndValidation(t *testing.T) {
	original := CaptureConfig{WANInterfaces: []string{"eth0"}}
	config := original.WithDefaults()
	if config.TProxyPort != DefaultTProxyPort {
		t.Fatalf("TProxyPort = %d", config.TProxyPort)
	}
	if config.OutputMark != DefaultOutputMark {
		t.Fatalf("OutputMark = %#x", config.OutputMark)
	}
	if config.ConnectionStateMapEntries != DefaultConnStateEntries {
		t.Fatalf("ConnectionStateMapEntries = %d", config.ConnectionStateMapEntries)
	}
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	config.WANInterfaces[0] = "changed"
	if original.WANInterfaces[0] != "eth0" {
		t.Fatal("WithDefaults aliased caller slice")
	}
}

func TestCaptureConfigRequiresInterface(t *testing.T) {
	if err := (CaptureConfig{}).Validate(); err == nil {
		t.Fatal("Validate() = nil")
	}
}

func TestNewSocketGeneration(t *testing.T) {
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tcp.Close() }()
	udpPacket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = udpPacket.Close() }()
	udp := udpPacket.(*net.UDPConn)
	generation, err := NewSocketGeneration(tcp, tcp, udp, 12345)
	if err != nil {
		t.Fatal(err)
	}
	if generation.TCP4() != tcp || generation.TCP6() != tcp || generation.UDP() != udp {
		t.Fatal("generation did not preserve listener identity")
	}
}
