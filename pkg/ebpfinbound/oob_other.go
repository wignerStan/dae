//go:build !linux

// SPDX-License-Identifier: AGPL-3.0-only

package ebpfinbound

import "net/netip"

// OriginalDestination is unavailable outside Linux.
func OriginalDestination([]byte) netip.AddrPort {
	return netip.AddrPort{}
}
