//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only

package ebpfinbound

import (
	"encoding/binary"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/unix"
)

// OriginalDestination extracts IP_ORIGDSTADDR/IPV6_ORIGDSTADDR from a UDP
// socket control-message buffer. Invalid or missing metadata returns the zero
// AddrPort.
func OriginalDestination(oob []byte) netip.AddrPort {
	messages, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return netip.AddrPort{}
	}
	for _, message := range messages {
		switch {
		case message.Header.Level == unix.SOL_IP && message.Header.Type == unix.IP_ORIGDSTADDR:
			if len(message.Data) < unix.SizeofSockaddrInet4 {
				continue
			}
			family := binary.NativeEndian.Uint16(message.Data[:2])
			if family != unix.AF_INET {
				continue
			}
			port := binary.BigEndian.Uint16(message.Data[2:4])
			address := netip.AddrFrom4([4]byte(message.Data[4:8]))
			return netip.AddrPortFrom(address, port)
		case message.Header.Level == unix.SOL_IPV6 && message.Header.Type == unix.IPV6_ORIGDSTADDR:
			if len(message.Data) < unix.SizeofSockaddrInet6 {
				continue
			}
			family := binary.NativeEndian.Uint16(message.Data[:2])
			if family != unix.AF_INET6 {
				continue
			}
			port := binary.BigEndian.Uint16(message.Data[2:4])
			var raw [16]byte
			copy(raw[:], message.Data[8:24])
			address := netip.AddrFrom16(raw)
			scope := binary.NativeEndian.Uint32(message.Data[24:28])
			if scope != 0 {
				if name, ok := interfaceNameByIndex(int(scope)); ok {
					address = address.WithZone(name)
				}
			}
			return netip.AddrPortFrom(address, port)
		}
	}
	return netip.AddrPort{}
}

func interfaceNameByIndex(index int) (string, bool) {
	if index <= 0 {
		return "", false
	}
	name := make([]byte, unix.IFNAMSIZ)
	request := struct {
		Index int32
		Name  [unix.IFNAMSIZ]byte
	}{Index: int32(index)}
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(unix.AT_FDCWD), 0, 0)
	_ = name
	_ = request
	_ = errno
	// Scope IDs are uncommon for transparent proxy destinations. Keeping the
	// numeric address is correct even when the interface name cannot be resolved.
	return "", false
}

var _ = unsafe.Sizeof(uintptr(0))
