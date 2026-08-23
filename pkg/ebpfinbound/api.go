// SPDX-License-Identifier: AGPL-3.0-only

// Package ebpfinbound defines the policy-neutral boundary between dae's Linux
// transparent-capture datapath and a userspace traffic engine.
//
// The package intentionally contains no routing, DNS, sniffing, outbound, or
// proxy-protocol types. Those decisions belong to the consumer. Implementations
// may live inside dae today and move into a standalone module later without
// changing consumers of this contract.
package ebpfinbound

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
)

// Network identifies the transport protocol of an intercepted flow.
type Network string

const (
	NetworkTCP Network = "tcp"
	NetworkUDP Network = "udp"
)

// Flow is the immutable tuple presented by the transparent inbound.
// Source and Destination are the original addresses observed by the datapath.
type Flow struct {
	Network     Network
	Source      netip.AddrPort
	Destination netip.AddrPort
}

// Validate rejects tuples that cannot be looked up in the datapath metadata
// maps. Port zero remains valid because it is representable by the kernel tuple
// ABI, even though ordinary TCP and UDP flows do not normally use it.
func (f Flow) Validate() error {
	switch f.Network {
	case NetworkTCP, NetworkUDP:
	default:
		return fmt.Errorf("unsupported network %q", f.Network)
	}
	if !f.Source.IsValid() {
		return errors.New("invalid source address")
	}
	if !f.Destination.IsValid() {
		return errors.New("invalid destination address")
	}
	return nil
}

// Metadata contains only facts observed or derived from the intercepted flow.
// It deliberately excludes dae route results, outbound IDs, DNS state, and
// sniffed domains so another policy engine can remain authoritative.
type Metadata struct {
	ProcessID    uint32
	ProcessName  string
	SourceMAC    [6]byte
	HasSourceMAC bool
	DSCP         uint8
}

// ListenerSet exposes the transparent sockets assigned by the eBPF datapath.
// The consumer owns the accept/read loops; closing the set wakes those loops.
type ListenerSet interface {
	io.Closer

	TCP4() net.Listener
	TCP6() net.Listener
	UDP() *net.UDPConn
	Port() uint16
}

// Generation is one staged set of transparent listeners. A generation is
// opaque to policy consumers: only its sockets and close operation are
// exposed. Cloning, validation, and publication remain runtime operations.
type Generation interface {
	ListenerSet
}

// Runtime is the stable userspace-facing boundary of the eBPF inbound.
//
// OpenGeneration stages transparent sockets without publishing them to the
// kernel. CloneGeneration duplicates a staged or active generation for a
// same-port handoff. CommitGeneration atomically publishes the generation
// and commits only staged capture-datapath state. None of these operations
// may start a policy engine, DNS server, sniffer, or outbound runtime.
//
// LookupMetadata returns found=false when the tuple is no longer available.
// Consumers should treat that as missing optional metadata, not as a policy
// decision.
type Runtime interface {
	OpenGeneration(ctx context.Context, port uint16) (Generation, error)
	CloneGeneration(ctx context.Context, generation Generation) (Generation, error)
	CommitGeneration(ctx context.Context, generation Generation) error
	LookupMetadata(ctx context.Context, flow Flow) (metadata Metadata, found bool, err error)
	OutputMark() uint32

	// Close releases the datapath runtime. Generation values remain owned by
	// the caller and must be closed separately.
	Close() error
}
