/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/daeuniverse/dae/pkg/ebpfinbound"
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

type testNetListener struct{}

func (testNetListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (testNetListener) Close() error              { return nil }
func (testNetListener) Addr() net.Addr            { return &net.TCPAddr{} }

type testEBPFInboundListenerSet struct {
	tcp4       net.Listener
	tcp6       net.Listener
	udp        *net.UDPConn
	port       uint16
	closeCalls int
}

func (l *testEBPFInboundListenerSet) TCP4() net.Listener { return l.tcp4 }
func (l *testEBPFInboundListenerSet) TCP6() net.Listener { return l.tcp6 }
func (l *testEBPFInboundListenerSet) UDP() *net.UDPConn  { return l.udp }
func (l *testEBPFInboundListenerSet) Port() uint16       { return l.port }
func (l *testEBPFInboundListenerSet) Close() error {
	l.closeCalls++
	return nil
}

type testEBPFInboundRuntime struct {
	listeners   ebpfinbound.ListenerSet
	openPort    uint16
	openCalls   int
	commitCalls int
	committed   ebpfinbound.ListenerSet
	commitErr   error
}

func (r *testEBPFInboundRuntime) OpenListeners(_ context.Context, port uint16) (ebpfinbound.ListenerSet, error) {
	r.openCalls++
	r.openPort = port
	return r.listeners, nil
}

func (r *testEBPFInboundRuntime) CommitListeners(_ context.Context, listeners ebpfinbound.ListenerSet) error {
	r.commitCalls++
	r.committed = listeners
	return r.commitErr
}

func (*testEBPFInboundRuntime) LookupMetadata(context.Context, ebpfinbound.Flow) (ebpfinbound.Metadata, bool, error) {
	return ebpfinbound.Metadata{}, false, nil
}

func (*testEBPFInboundRuntime) OutputMark() uint32 { return 0 }
func (*testEBPFInboundRuntime) Close() error       { return nil }

func newTestEBPFInboundListenerSet() *testEBPFInboundListenerSet {
	return &testEBPFInboundListenerSet{
		tcp4: testNetListener{},
		tcp6: testNetListener{},
		udp:  &net.UDPConn{},
		port: 12345,
	}
}

func TestPrepareEBPFInboundListenersUsesRuntime(t *testing.T) {
	listeners := newTestEBPFInboundListenerSet()
	runtime := &testEBPFInboundRuntime{}

	sockets, err := prepareEBPFInboundListeners(context.Background(), runtime, listeners)
	if err != nil {
		t.Fatalf("prepareEBPFInboundListeners() error = %v", err)
	}
	if runtime.commitCalls != 1 || runtime.committed != listeners {
		t.Fatalf("CommitListeners calls = %d, listener = %T", runtime.commitCalls, runtime.committed)
	}
	if sockets.tcp4 != listeners.tcp4 || sockets.tcp6 != listeners.tcp6 || sockets.udp != listeners.udp {
		t.Fatal("prepared sockets do not match listener set")
	}
}

func TestPrepareEBPFInboundListenersValidatesBeforeCommit(t *testing.T) {
	listeners := newTestEBPFInboundListenerSet()
	listeners.udp = nil
	runtime := &testEBPFInboundRuntime{}

	if _, err := prepareEBPFInboundListeners(context.Background(), runtime, listeners); err == nil {
		t.Fatal("prepareEBPFInboundListeners() error = nil, want missing UDP error")
	}
	if runtime.commitCalls != 0 {
		t.Fatalf("CommitListeners calls = %d, want 0", runtime.commitCalls)
	}
}

func TestPrepareEBPFInboundListenersHonorsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runtime := &testEBPFInboundRuntime{}

	if _, err := prepareEBPFInboundListeners(ctx, runtime, newTestEBPFInboundListenerSet()); !errors.Is(err, context.Canceled) {
		t.Fatalf("prepareEBPFInboundListeners() error = %v, want %v", err, context.Canceled)
	}
	if runtime.commitCalls != 0 {
		t.Fatalf("CommitListeners calls = %d, want 0", runtime.commitCalls)
	}
}

func TestOpenLegacyEBPFInboundListenersUsesRuntime(t *testing.T) {
	listener := &Listener{
		tcp4Listener: testNetListener{},
		tcp6Listener: testNetListener{},
		packetConn:   &net.UDPConn{},
		port:         23456,
	}
	runtime := &testEBPFInboundRuntime{listeners: listener}

	got, err := openLegacyEBPFInboundListeners(context.Background(), runtime, listener.port)
	if err != nil {
		t.Fatalf("openLegacyEBPFInboundListeners() error = %v", err)
	}
	if got != listener {
		t.Fatal("openLegacyEBPFInboundListeners() returned a different listener")
	}
	if runtime.openCalls != 1 || runtime.openPort != listener.port {
		t.Fatalf("OpenListeners calls = %d, port = %d", runtime.openCalls, runtime.openPort)
	}
}

func TestOpenLegacyEBPFInboundListenersClosesForeignSet(t *testing.T) {
	listeners := newTestEBPFInboundListenerSet()
	runtime := &testEBPFInboundRuntime{listeners: listeners}

	if _, err := openLegacyEBPFInboundListeners(context.Background(), runtime, listeners.port); err == nil {
		t.Fatal("openLegacyEBPFInboundListeners() error = nil, want type error")
	}
	if listeners.closeCalls != 1 {
		t.Fatalf("Close calls = %d, want 1", listeners.closeCalls)
	}
}
