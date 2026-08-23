/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	stderrors "errors"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/ebpfinbound"
	"golang.org/x/sys/unix"
)

var (
	_ ebpfinbound.Runtime     = (*controlPlaneEBPFInbound)(nil)
	_ ebpfinbound.ListenerSet = (*Listener)(nil)
)

// controlPlaneEBPFInbound is a compatibility adapter over dae's existing
// control-plane implementation. Keeping the adapter in one file prevents the
// public eBPF-inbound contract from depending on private BPF structs while the
// datapath implementation is gradually extracted into its own package.
type controlPlaneEBPFInbound struct {
	plane *ControlPlane
}

// TCP4 returns the transparent IPv4 TCP listener.
func (l *Listener) TCP4() net.Listener {
	if l == nil {
		return nil
	}
	return l.tcp4Listener
}

// TCP6 returns the transparent IPv6 TCP listener.
func (l *Listener) TCP6() net.Listener {
	if l == nil {
		return nil
	}
	return l.tcp6Listener
}

// UDP returns the transparent UDP listener.
func (l *Listener) UDP() *net.UDPConn {
	if l == nil {
		return nil
	}
	udpConn, _ := l.packetConn.(*net.UDPConn)
	return udpConn
}

// Port returns the shared transparent-listener port.
func (l *Listener) Port() uint16 {
	if l == nil {
		return 0
	}
	return l.port
}

// EBPFInbound exposes dae's transparent-capture runtime through a
// policy-neutral contract. The returned runtime shares ownership with the
// ControlPlane; closing either closes the same underlying resources.
func (c *ControlPlane) EBPFInbound() ebpfinbound.Runtime {
	return &controlPlaneEBPFInbound{plane: c}
}

func (r *controlPlaneEBPFInbound) OpenListeners(ctx context.Context, port uint16) (ebpfinbound.ListenerSet, error) {
	if r == nil || r.plane == nil {
		return nil, fmt.Errorf("nil control plane")
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	return r.plane.Listen(port)
}

func (r *controlPlaneEBPFInbound) CommitListeners(ctx context.Context, listeners ebpfinbound.ListenerSet) error {
	if r == nil || r.plane == nil {
		return fmt.Errorf("nil control plane")
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	listener, ok := listeners.(*Listener)
	if !ok || listener == nil {
		return fmt.Errorf("unsupported listener set type %T", listeners)
	}
	if listener.TCP4() == nil || listener.TCP6() == nil || listener.UDP() == nil {
		return fmt.Errorf("commit inbound listeners: incomplete listener set")
	}
	if err := r.plane.CommitPreparedDatapath(); err != nil {
		return err
	}
	return r.plane.publishListenerSockets(listener)
}

func (r *controlPlaneEBPFInbound) LookupMetadata(ctx context.Context, flow ebpfinbound.Flow) (ebpfinbound.Metadata, bool, error) {
	if r == nil || r.plane == nil || r.plane.core == nil {
		return ebpfinbound.Metadata{}, false, fmt.Errorf("nil control plane")
	}
	if err := flow.Validate(); err != nil {
		return ebpfinbound.Metadata{}, false, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return ebpfinbound.Metadata{}, false, err
	}

	source := common.ConvergeAddrPort(flow.Source)
	destination := common.ConvergeAddrPort(flow.Destination)

	var (
		result *bpfRoutingResult
		err    error
	)
	switch flow.Network {
	case ebpfinbound.NetworkTCP:
		result, err = retryRetrieveRoutingResult(ctx, func() (*bpfRoutingResult, error) {
			return r.plane.core.RetrieveRoutingResult(source, destination, consts.IPPROTO_TCP)
		}, tcpRoutingLookupRetryAttempts, tcpRoutingLookupRetryDelay)
	case ebpfinbound.NetworkUDP:
		result, err = r.plane.core.RetrieveRoutingResult(source, destination, unix.IPPROTO_UDP)
	default:
		// Flow.Validate already rejects this case. Keep the default so this
		// switch remains safe if validation changes in the future.
		return ebpfinbound.Metadata{}, false, fmt.Errorf("unsupported network %q", flow.Network)
	}
	if err != nil {
		if stderrors.Is(err, ebpf.ErrKeyNotExist) {
			return ebpfinbound.Metadata{}, false, nil
		}
		return ebpfinbound.Metadata{}, false, err
	}
	return metadataFromRoutingResult(result), true, nil
}

func (r *controlPlaneEBPFInbound) OutputMark() uint32 {
	if r == nil || r.plane == nil {
		return 0
	}
	return r.plane.soMarkFromDae
}

func (r *controlPlaneEBPFInbound) Close() error {
	if r == nil || r.plane == nil {
		return nil
	}
	return r.plane.Close()
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}

func metadataFromRoutingResult(result *bpfRoutingResult) ebpfinbound.Metadata {
	if result == nil {
		return ebpfinbound.Metadata{}
	}
	metadata := ebpfinbound.Metadata{
		ProcessID:   result.Pid,
		ProcessName: ProcessName2String(result.Pname[:]),
		SourceMAC:   result.Mac,
		DSCP:        result.Dscp,
	}
	for _, value := range result.Mac {
		if value != 0 {
			metadata.HasSourceMAC = true
			break
		}
	}
	return metadata
}
