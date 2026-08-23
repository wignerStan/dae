//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only

package ebpfinbound

import (
	"encoding/binary"
	"net/netip"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// OriginalDestination extracts the destination address attached to a
// transparent UDP packet by IP_RECVORIGDSTADDR or IPV6_RECVORIGDSTADDR.
// It returns an invalid AddrPort when the control message is absent or
// malformed.
func OriginalDestination(oob []byte) netip.AddrPort {
	ptrSize := int(unsafe.Sizeof(uintptr(0)))
	hdrLen := ptrSize + 8 // sizeof(size_t) + sizeof(int) + sizeof(int)
	if len(oob) < hdrLen {
		return netip.AddrPort{}
	}

	for len(oob) >= hdrLen {
		cmsgLen, ok := parseNativeUintptr(oob[:ptrSize])
		if !ok || cmsgLen < hdrLen || cmsgLen > len(oob) {
			return netip.AddrPort{}
		}

		level := int(int32(binary.NativeEndian.Uint32(oob[ptrSize : ptrSize+4])))
		typ := int(int32(binary.NativeEndian.Uint32(oob[ptrSize+4 : ptrSize+8])))
		data := oob[hdrLen:cmsgLen]

		switch {
		case level == syscall.SOL_IP && typ == syscall.IP_RECVORIGDSTADDR:
			if len(data) >= unix.SizeofSockaddrInet4 {
				port := binary.BigEndian.Uint16(data[2:4])
				var ip [4]byte
				copy(ip[:], data[4:8])
				return netip.AddrPortFrom(netip.AddrFrom4(ip), port)
			}
		case level == syscall.SOL_IPV6 && typ == unix.IPV6_RECVORIGDSTADDR:
			if len(data) >= unix.SizeofSockaddrInet6 {
				port := binary.BigEndian.Uint16(data[2:4])
				var ip [16]byte
				copy(ip[:], data[8:24])
				return netip.AddrPortFrom(netip.AddrFrom16(ip), port)
			}
		}

		next := cmsgAlign(cmsgLen, ptrSize)
		if next <= 0 || next > len(oob) {
			break
		}
		oob = oob[next:]
	}

	return netip.AddrPort{}
}

func parseNativeUintptr(b []byte) (int, bool) {
	switch len(b) {
	case 8:
		value := binary.NativeEndian.Uint64(b)
		if value > uint64(^uint(0)>>1) {
			return 0, false
		}
		return int(value), true
	case 4:
		value := binary.NativeEndian.Uint32(b)
		if uint64(value) > uint64(^uint(0)>>1) {
			return 0, false
		}
		return int(value), true
	default:
		return 0, false
	}
}

func cmsgAlign(length int, ptrSize int) int {
	if length <= 0 {
		return 0
	}
	return (length + ptrSize - 1) & ^(ptrSize - 1)
}
