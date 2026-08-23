//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only

package ebpfinbound

import (
	"encoding/binary"
	"net/netip"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestOriginalDestination(t *testing.T) {
	tests := []struct {
		name string
		want netip.AddrPort
		oob  []byte
	}{
		{
			name: "IPv4",
			want: netip.MustParseAddrPort("1.2.3.4:443"),
		},
		{
			name: "IPv6",
			want: netip.MustParseAddrPort("[2001:db8::1]:853"),
		},
	}
	tests[0].oob = buildOriginalDestinationIPv4(tests[0].want)
	tests[1].oob = buildOriginalDestinationIPv6(tests[1].want)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := OriginalDestination(test.oob); got != test.want {
				t.Fatalf("OriginalDestination() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestOriginalDestinationSkipsUnknownMessage(t *testing.T) {
	want := netip.MustParseAddrPort("9.9.9.9:53")
	oob := append(buildDummyControlMessage(), buildOriginalDestinationIPv4(want)...)
	if got := OriginalDestination(oob); got != want {
		t.Fatalf("OriginalDestination() = %v, want %v", got, want)
	}
}

func TestOriginalDestinationRejectsMalformedMessage(t *testing.T) {
	if got := OriginalDestination([]byte{1, 2, 3}); got.IsValid() {
		t.Fatalf("OriginalDestination() = %v, want invalid", got)
	}
}

func buildDummyControlMessage() []byte {
	oob := make([]byte, unix.CmsgSpace(4))
	header := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	header.Level = syscall.SOL_SOCKET
	header.Type = 0
	header.SetLen(unix.CmsgLen(4))
	binary.NativeEndian.PutUint32(oob[unix.CmsgSpace(0):unix.CmsgSpace(0)+4], 0x11223344)
	return oob
}

func buildOriginalDestinationIPv4(address netip.AddrPort) []byte {
	oob := make([]byte, unix.CmsgSpace(unix.SizeofSockaddrInet4))
	header := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	header.Level = syscall.SOL_IP
	header.Type = syscall.IP_RECVORIGDSTADDR
	header.SetLen(unix.CmsgLen(unix.SizeofSockaddrInet4))

	data := oob[unix.CmsgSpace(0) : unix.CmsgSpace(0)+unix.SizeofSockaddrInet4]
	binary.NativeEndian.PutUint16(data[0:2], unix.AF_INET)
	binary.BigEndian.PutUint16(data[2:4], address.Port())
	ip := address.Addr().As4()
	copy(data[4:8], ip[:])
	return oob
}

func buildOriginalDestinationIPv6(address netip.AddrPort) []byte {
	oob := make([]byte, unix.CmsgSpace(unix.SizeofSockaddrInet6))
	header := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	header.Level = syscall.SOL_IPV6
	header.Type = unix.IPV6_RECVORIGDSTADDR
	header.SetLen(unix.CmsgLen(unix.SizeofSockaddrInet6))

	data := oob[unix.CmsgSpace(0) : unix.CmsgSpace(0)+unix.SizeofSockaddrInet6]
	binary.NativeEndian.PutUint16(data[0:2], unix.AF_INET6)
	binary.BigEndian.PutUint16(data[2:4], address.Port())
	ip := address.Addr().As16()
	copy(data[8:24], ip[:])
	return oob
}
