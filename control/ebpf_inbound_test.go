/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"testing"
)

func TestMetadataFromRoutingResult(t *testing.T) {
	result := &bpfRoutingResult{
		Pid:   42,
		Mac:   [6]uint8{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		Dscp:  46,
		Pname: [16]uint8{'b', 'r', 'o', 'w', 's', 'e', 'r'},
	}

	metadata := metadataFromRoutingResult(result)
	if metadata.ProcessID != result.Pid {
		t.Fatalf("ProcessID = %d, want %d", metadata.ProcessID, result.Pid)
	}
	if metadata.ProcessName != "browser" {
		t.Fatalf("ProcessName = %q, want %q", metadata.ProcessName, "browser")
	}
	if metadata.SourceMAC != result.Mac || !metadata.HasSourceMAC {
		t.Fatalf("SourceMAC = %v (present=%v), want %v (present=true)", metadata.SourceMAC, metadata.HasSourceMAC, result.Mac)
	}
	if metadata.DSCP != result.Dscp {
		t.Fatalf("DSCP = %d, want %d", metadata.DSCP, result.Dscp)
	}
}

func TestMetadataFromRoutingResultWithoutMAC(t *testing.T) {
	metadata := metadataFromRoutingResult(&bpfRoutingResult{})
	if metadata.HasSourceMAC {
		t.Fatal("HasSourceMAC = true, want false")
	}
}

func TestControlPlaneEBPFInboundOutputMark(t *testing.T) {
	plane := &ControlPlane{soMarkFromDae: 0x1234}
	if got := plane.EBPFInbound().OutputMark(); got != plane.soMarkFromDae {
		t.Fatalf("OutputMark() = %#x, want %#x", got, plane.soMarkFromDae)
	}
}

func TestContextError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := contextError(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("contextError(cancelled) = %v, want %v", err, context.Canceled)
	}
}
