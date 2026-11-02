//go:build linux && integration && !dae_stub_ebpf

// SPDX-License-Identifier: AGPL-3.0-only

package ebpfinbound

import (
	"context"
	"net"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// Transparent reply writers bind the remote peer's address without connecting.
// Marked wildcard sockets also match transit destinations sharing their port.
// Neither output mark must cause a subsequent LAN client request to bypass
// policy. Disable WAN capture so a second interception cannot hide LAN failure.
func TestPrivilegedTransparentReplySocketDoesNotBypassLAN(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	if err := CleanupStale(context.Background()); err != nil {
		t.Fatal(err)
	}
	prepareIntegrationNetwork(t)
	options := integrationOptions()
	options.Capture.WANInterfaces = nil
	// LAN client namespaces intentionally have no host process metadata.
	options.Capture.RequireProcessMetadata = false
	runtime, err := New(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	for _, flow := range []struct{ network, destination string }{
		{"udp4", "198.18.0.2:53"}, {"udp6", "[2001:db8:dae::2]:53"},
	} {
		for _, socketKind := range []string{"transparent-specific", "wildcard-unconnected"} {
			t.Run(flow.network+"/"+socketKind, func(t *testing.T) {
				address, err := net.ResolveUDPAddr(flow.network, flow.destination)
				if err != nil {
					t.Fatal(err)
				}
				family := unix.AF_INET
				if flow.network == "udp6" {
					family = unix.AF_INET6
				}
				fd, err := unix.Socket(family, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.IPPROTO_UDP)
				if err != nil {
					t.Fatal(err)
				}
				defer unix.Close(fd)
				if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, 0x1ee0); err != nil {
					t.Fatal(err)
				}
				var bindAddress unix.Sockaddr
				if family == unix.AF_INET {
					if socketKind == "transparent-specific" {
						if err := unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
							t.Fatal(err)
						}
					}
					socketAddress := &unix.SockaddrInet4{}
					if socketKind == "transparent-specific" {
						copy(socketAddress.Addr[:], address.IP.To4())
					}
					bindAddress = socketAddress
				} else {
					if socketKind == "transparent-specific" {
						if err := unix.SetsockoptInt(fd, unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1); err != nil {
							t.Fatal(err)
						}
					}
					if err := unix.SetsockoptInt(fd, unix.SOL_IPV6, unix.IPV6_V6ONLY, 1); err != nil {
						t.Fatal(err)
					}
					socketAddress := &unix.SockaddrInet6{}
					if socketKind == "transparent-specific" {
						copy(socketAddress.Addr[:], address.IP.To16())
					}
					bindAddress = socketAddress
				}
				if err := unix.Bind(fd, bindAddress); err != nil {
					t.Fatal(err)
				}
				bound, err := unix.Getsockname(fd)
				if err != nil {
					t.Fatal(err)
				}
				switch bound := bound.(type) {
				case *unix.SockaddrInet4:
					address.Port = bound.Port
				case *unix.SockaddrInet6:
					address.Port = bound.Port
				default:
					t.Fatalf("unexpected socket address %T", bound)
				}
				testCapturedUDP(t, runtime, flow.network, address.String(), "unconnected-marked-socket-must-not-bypass", integrationLANNetNS)
			})
		}
	}
}
