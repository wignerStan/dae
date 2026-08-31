//go:build linux && dae_bpf_tests

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package tests

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

// TestExternalPolicyBpfGuards exercises the two guards that are easy to break
// when the capture path is refactored:
//   - marked sing-box sockets must bypass cookie_pid_map lookup;
//   - the reserved external-policy result must not depend on dae's health map.
//
// The negative reserved-policy case is intentionally included. It prevents a
// future change from making the reserved result unconditionally "alive" in
// normal dae routing mode.
func TestExternalPolicyBpfGuards(t *testing.T) {
	cases := []struct {
		name         string
		param        bpfTestParam
		program      string
		wantPass     bool
		externalMode bool
	}{
		{
			name:     "marked_socket_precedes_cookie_lookup",
			param:    bpfTestParam{DaeSocketMark: 0x1234},
			program:  "BugExternalPolicyMarkPrecedence",
			wantPass: true,
		},
		{
			name:         "reserved_outbound_external_mode",
			param:        bpfTestParam{ExternalPolicy: 1},
			program:      "BugExternalPolicyReservedOutbound",
			wantPass:     true,
			externalMode: true,
		},
		{
			name:     "reserved_outbound_normal_mode_uses_health_map",
			program:  "BugExternalPolicyReservedOutbound",
			wantPass: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			obj, programs, err := collectProgramsWithParam(t, &tc.param)
			if err != nil {
				t.Fatalf("collect BPF programs: %v", err)
			}
			defer obj.Close()
			if !tc.wantPass {
				// wan_outbound_is_alive selects the IPv4/IPv6 slot from
				// skb->protocol. bpf_prog_test_run does not permit writing
				// that context field, so make both reserved-outbound slots
				// explicitly dead for the normal-mode negative probe.
				for _, key := range []uint32{253*6 + 0, 253*6 + 1} {
					alive := uint32(0)
					if err := obj.OutboundConnectivityMap.Update(key, alive, ebpf.UpdateAny); err != nil {
						t.Fatalf("initialize reserved outbound health slot %d: %v", key, err)
					}
				}
			}

			var target *programSet
			for index := range programs {
				if strings.EqualFold(programs[index].id, tc.program) {
					target = &programs[index]
					break
				}
			}
			if target == nil {
				t.Fatalf("program set %q not found", tc.program)
			}

			data := make([]byte, 4096-256-320)
			ctx := make([]byte, 256)
			status, data, ctx, err := runBpfProgram(target.pktgen, data, ctx)
			if err != nil {
				t.Fatalf("run pktgen: %v", err)
			}
			if status != 0 {
				t.Fatalf("pktgen status = %d, want 0", status)
			}
			status, data, ctx, err = runBpfProgram(target.setup, data, ctx)
			if err != nil {
				t.Fatalf("run setup: %v", err)
			}
			if status != 0 {
				t.Fatalf("setup status = %d, want 0", status)
			}
			status, _, _, err = runBpfProgram(target.check, data, ctx)
			if err != nil {
				t.Fatalf("run check: %v", err)
			}
			if tc.wantPass && status != 0 {
				t.Fatalf("check status = %d, want TC_ACT_OK (external=%t mark=%#x)", status, tc.externalMode, tc.param.DaeSocketMark)
			}
			if !tc.wantPass && status == 0 {
				t.Fatalf("check status = 0, want a drop in normal mode")
			}
		})
	}
}
