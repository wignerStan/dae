//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"
	"unsafe"
)

func TestBpfDaeParamExternalPolicyABI(t *testing.T) {
	var value bpfDaeParam
	if got, want := unsafe.Sizeof(value), uintptr(32); got != want {
		t.Fatalf("bpfDaeParam size = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(value.ExternalPolicy), uintptr(26); got != want {
		t.Fatalf("ExternalPolicy offset = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(value.DaeSocketMark), uintptr(28); got != want {
		t.Fatalf("DaeSocketMark offset = %d, want %d", got, want)
	}
}
