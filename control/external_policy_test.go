/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"net"
	"os"
	"testing"

	"github.com/daeuniverse/dae/common/daeipc"
)

func TestExternalPolicyListenerFiles(t *testing.T) {
	tcp4, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tcp4.Close() }()
	tcp6, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 unavailable: %v", err)
	}
	defer func() { _ = tcp6.Close() }()
	udp, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 UDP unavailable: %v", err)
	}
	defer func() { _ = udp.Close() }()

	listener := &Listener{
		tcp4Listener: tcp4,
		tcp6Listener: tcp6,
		packetConn:   udp,
	}
	kinds, files, err := externalPolicyListenerFiles(listener)
	if err != nil {
		t.Fatal(err)
	}
	defer closeExternalPolicyFiles(files)
	if got, want := len(files), 3; got != want {
		t.Fatalf("received %d files, want %d", got, want)
	}
	wantKinds := []string{"tcp4", "tcp6", "udp6"}
	for index := range wantKinds {
		if kinds[index] != wantKinds[index] {
			t.Fatalf("listener kind[%d] = %q, want %q", index, kinds[index], wantKinds[index])
		}
	}

	adopted, err := net.FileListener(files[0])
	if err != nil {
		t.Fatalf("adopt duplicated TCP4 listener: %v", err)
	}
	_ = adopted.Close()
	packetConn, err := net.FilePacketConn(files[2])
	if err != nil {
		t.Fatalf("adopt duplicated UDP listener: %v", err)
	}
	_ = packetConn.Close()
}

func TestExternalPolicyProcessDetails(t *testing.T) {
	path, uid, hasUID := externalPolicyProcessDetails(uint32(os.Getpid()))
	if path == "" {
		t.Fatal("process path is empty")
	}
	if !hasUID {
		t.Fatal("user ID was not found")
	}
	if uid != int32(os.Getuid()) {
		t.Fatalf("uid = %d, want %d", uid, os.Getuid())
	}
}

func TestExternalPolicyMACString(t *testing.T) {
	if got := externalPolicyMACString([6]uint8{}); got != "" {
		t.Fatalf("zero MAC = %q, want empty", got)
	}
	if got := externalPolicyMACString([6]uint8{0, 1, 2, 3, 4, 5}); got != "00:01:02:03:04:05" {
		t.Fatalf("MAC = %q", got)
	}
}

func TestConfiguredExternalPolicyUID(t *testing.T) {
	t.Setenv(externalPolicyUIDEnv, "")
	uid, err := configuredExternalPolicyUID()
	if err != nil {
		t.Fatal(err)
	}
	if uid != uint32(os.Geteuid()) {
		t.Fatalf("default uid = %d, want %d", uid, os.Geteuid())
	}

	t.Setenv(externalPolicyUIDEnv, "1234")
	uid, err = configuredExternalPolicyUID()
	if err != nil {
		t.Fatal(err)
	}
	if uid != 1234 {
		t.Fatalf("configured uid = %d, want 1234", uid)
	}

	t.Setenv(externalPolicyUIDEnv, "not-a-uid")
	if _, err = configuredExternalPolicyUID(); err == nil {
		t.Fatal("invalid uid was accepted")
	}
}

func TestExternalPolicyLookupRejectsGenerationMismatch(t *testing.T) {
	request := daeipc.NewMessage(daeipc.TypeLookup)
	request.RequestID = 1
	request.Generation = 10
	response := new(ControlPlane).externalPolicyLookupResponse(request, 11)
	if response.RequestID != request.RequestID {
		t.Fatalf("request id = %d, want %d", response.RequestID, request.RequestID)
	}
	if response.Error == "" {
		t.Fatal("generation mismatch was accepted")
	}
}
