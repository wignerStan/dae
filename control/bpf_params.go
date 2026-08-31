//go:build linux && dae_stub_ebpf

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import "structs"

// bpfDaeParam mirrors struct dae_param in control/kern/tproxy.c.
//
// The real eBPF build gets the same type from bpf2go. The stub build needs a
// local copy so compile-only tests continue to exercise the exact ABI instead
// of silently drifting to an anonymous, differently padded struct.
type bpfDaeParam struct {
	_                    structs.HostLayout
	TproxyPort           uint32
	ControlPlanePid      uint32
	Dae0Ifindex          uint32
	DaeNetnsId           uint32
	Dae0peerMac          [6]uint8
	PaddingAfterMac      [2]uint8
	UseRedirectPeer      uint8 // 0=use bpf_redirect(), 1=use bpf_redirect_peer() when safe
	HasBpfGetCurrentTask uint8
	ExternalPolicy       uint8 // 1=send all captured flows to the external userspace policy engine
	Padding2             uint8
	DaeSocketMark        uint32 // mark set on dae's own sockets to identify them in eBPF
}
