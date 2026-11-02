//go:build linux && integration && !dae_stub_ebpf

// SPDX-License-Identifier: AGPL-3.0-only

package ebpfinbound

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// Run the actual generated TC programs through the kernel. Verify that no
// direction overwrites the mark used by the host's existing policy routing.
func TestPrivilegedBypassPreservesPacketMark(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec, err := loadBpf()
	if err != nil {
		t.Fatal(err)
	}
	if err := spec.Variables["PARAM"].Set(bpfDaeParam{BypassMark: 0x80000, BypassMarkMask: 0xff0000}); err != nil {
		t.Fatal(err)
	}
	if err := pruneCaptureSpec(spec); err != nil {
		t.Fatal(err)
	}
	for _, item := range spec.Maps {
		item.Pinning = ebpf.PinNone
		if item.Type == ebpf.RingBuf {
			item.MaxEntries = uint32(os.Getpagesize())
		} else if item.MaxEntries > 1024 {
			item.MaxEntries = 1024
		}
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer collection.Close()
	for _, direction := range []string{"lan_ingress", "lan_egress", "wan_ingress", "wan_egress"} {
		for _, layer := range []string{"l2", "l3"} {
			for _, mark := range []uint32{0x80000, 0x80042, 0xa5080042} {
				name := "tproxy_" + direction + "_" + layer
				// __sk_buff's first three u32 fields are len, pkt_type, mark.
				// The zero-filled full context does not carry any kernel pointers.
				var input, output [48]uint32
				input[2] = mark
				result, err := collection.Programs[name].Run(&ebpf.RunOptions{Data: make([]byte, 64), Context: input, ContextOut: &output})
				if err != nil {
					t.Fatalf("%s mark %#x: %v", name, mark, err)
				}
				if result != 3 || output[2] != mark {
					t.Fatalf("%s mark %#x: action=%d mark_out=%#x, want TC_ACT_PIPE and unchanged mark", name, mark, result, output[2])
				}
			}
		}
	}
}
