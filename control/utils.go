/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
	"encoding/hex"
	stderrors "errors"
	"fmt"
	"net/netip"
	"os"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/ebpfinbound"
	"golang.org/x/sys/unix"
)

func (c *ControlPlane) Route(src, dst netip.AddrPort, domain string, l4proto consts.L4ProtoType, routingResult *bpfRoutingResult) (outboundIndex consts.OutboundIndex, mark uint32, must bool, err error) {
	var ipVersion consts.IpVersionType
	if dst.Addr().Is4() || dst.Addr().Is4In6() {
		ipVersion = consts.IpVersion_4
	} else {
		ipVersion = consts.IpVersion_6
	}
	var mac16 [16]uint8
	copy(mac16[10:], routingResult.Mac[:])
	bSrc := src.Addr().As16()
	bDst := dst.Addr().As16()
	outboundIndex, mark, must, err = c.routingMatcher.Match(
		bSrc,
		bDst,
		src.Port(),
		dst.Port(),
		ipVersion,
		l4proto,
		domain,
		routingResult.Pname,
		routingResult.Dscp,
		mac16,
	)
	return
}

func bpfTuplesKeyFromAddrPorts(src, dst netip.AddrPort, l4proto uint8) bpfTuplesKey {
	src = common.ConvergeAddrPort(src)
	dst = common.ConvergeAddrPort(dst)

	var key bpfTuplesKey
	key.Sip.U6Addr8 = src.Addr().As16()
	key.Dip.U6Addr8 = dst.Addr().As16()
	key.Sport = common.Htons(src.Port())
	key.Dport = common.Htons(dst.Port())
	key.L4proto = l4proto
	return key
}

func (c *controlPlaneCore) RetrieveRoutingResult(src, dst netip.AddrPort, l4proto uint8) (result *bpfRoutingResult, err error) {
	tuples := bpfTuplesKeyFromAddrPorts(src, dst, l4proto)

	if c == nil || c.bpf.Load() == nil {
		return nil, ebpf.ErrKeyNotExist
	}

	routingResult, err := c.retrieveEmbeddedRoutingResult(&tuples, l4proto)
	if err == nil {
		return routingResult, nil
	}
	if !stderrors.Is(err, ebpf.ErrKeyNotExist) {
		return nil, err
	}
	return c.retrieveRoutingHandoffResult(&tuples)
}

func (c *controlPlaneCore) retrieveEmbeddedRoutingResult(tuples *bpfTuplesKey, l4proto uint8) (*bpfRoutingResult, error) {
	bpf := c.bpf.Load()
	var routingResult bpfRoutingResult

	switch l4proto {
	case unix.IPPROTO_TCP:
		if bpf.ConnStateMap == nil {
			return nil, ebpf.ErrKeyNotExist
		}
		var connState bpfConnState
		if err := bpf.ConnStateMap.Lookup(tuples, &connState); err != nil {
			if stderrors.Is(err, ebpf.ErrKeyNotExist) {
				return nil, ebpf.ErrKeyNotExist
			}
			return nil, fmt.Errorf("reading conn_state_map: %w", err)
		}
		if connState.Meta.Data.HasRouting == 0 {
			return nil, ebpf.ErrKeyNotExist
		}
		routingResult = routingResultFromConnState(
			connState.Meta.Data.Mark,
			connState.Meta.Data.Must,
			connState.Meta.Data.Outbound,
			connState.Mac,
			connState.Meta.Data.Dscp,
			connState.Pname,
			connState.Pid,
		)
	case unix.IPPROTO_UDP:
		if bpf.ConnStateMap == nil {
			return nil, ebpf.ErrKeyNotExist
		}
		var connState bpfConnState
		if err := bpf.ConnStateMap.Lookup(tuples, &connState); err != nil {
			if stderrors.Is(err, ebpf.ErrKeyNotExist) {
				return nil, ebpf.ErrKeyNotExist
			}
			return nil, fmt.Errorf("reading conn_state_map: %w", err)
		}
		if connState.Meta.Data.HasRouting == 0 {
			return nil, ebpf.ErrKeyNotExist
		}
		routingResult = routingResultFromConnState(
			connState.Meta.Data.Mark,
			connState.Meta.Data.Must,
			connState.Meta.Data.Outbound,
			connState.Mac,
			connState.Meta.Data.Dscp,
			connState.Pname,
			connState.Pid,
		)
	default:
		return nil, ebpf.ErrKeyNotExist
	}

	return &routingResult, nil
}

func routingResultFromConnState(mark uint32, must uint8, outbound uint8, mac [6]uint8, dscp uint8, pname [16]uint8, pid uint32) bpfRoutingResult {
	var routingResult bpfRoutingResult
	routingResult.Mark = mark
	routingResult.Must = must
	routingResult.Outbound = outbound
	routingResult.Mac = mac
	routingResult.Dscp = dscp
	routingResult.Pname = pname
	routingResult.Pid = pid
	return routingResult
}

func (c *controlPlaneCore) retrieveRoutingHandoffResult(tuples *bpfTuplesKey) (*bpfRoutingResult, error) {
	if c == nil {
		return nil, ebpf.ErrKeyNotExist
	}
	bpf := c.bpf.Load()
	if bpf == nil || bpf.RoutingHandoffMap == nil {
		return nil, ebpf.ErrKeyNotExist
	}

	var entry bpfRoutingHandoffEntry
	if err := bpf.RoutingHandoffMap.Lookup(tuples, &entry); err != nil {
		if stderrors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, ebpf.ErrKeyNotExist
		}
		return nil, fmt.Errorf("reading routing_handoff_map: %w", err)
	}

	now, err := monotonicNowNano()
	if err != nil {
		return nil, fmt.Errorf("reading monotonic clock for routing handoff: %w", err)
	}
	if routingHandoffExpired(now, entry.LastSeenNs) {
		if deleteErr := bpf.RoutingHandoffMap.Delete(tuples); deleteErr != nil &&
			!stderrors.Is(deleteErr, ebpf.ErrKeyNotExist) {
			return nil, fmt.Errorf("deleting expired routing_handoff_map entry: %w", deleteErr)
		}
		return nil, ebpf.ErrKeyNotExist
	}

	routingResult := routingResultFromConnState(
		entry.Result.Mark,
		entry.Result.Must,
		entry.Result.Outbound,
		entry.Result.Mac,
		entry.Result.Dscp,
		entry.Result.Pname,
		entry.Result.Pid,
	)
	return &routingResult, nil
}

func routingHandoffExpired(nowNano, lastSeenNs uint64) bool {
	if lastSeenNs == 0 {
		return true
	}
	timeoutNano := uint64(routingHandoffTimeout.Nanoseconds())
	if nowNano <= lastSeenNs {
		return false
	}
	return nowNano-lastSeenNs > timeoutNano
}

func monotonicNowNano() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, err
	}
	return uint64(ts.Nano()), nil
}

func RetrieveOriginalDest(oob []byte) netip.AddrPort {
	return ebpfinbound.OriginalDestination(oob)
}

func checkIpforward(ifname string, ipversion consts.IpVersionStr) error {
	path := fmt.Sprintf("/proc/sys/net/ipv%v/conf/%v/forwarding", ipversion, ifname)
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if bytes.Equal(bytes.TrimSpace(b), []byte("1")) {
		return nil
	}
	return fmt.Errorf("ipforward on %v is off: %v; see docs of dae for help", ifname, path)
}

func CheckIpforward(ifname string) error {
	if err := checkIpforward(ifname, consts.IpVersionStr_4); err != nil {
		return err
	}
	if err := checkIpforward(ifname, consts.IpVersionStr_6); err != nil {
		return err
	}
	return nil
}

func setForwarding(ifname string, ipversion consts.IpVersionStr, val string) error {
	path := fmt.Sprintf("/proc/sys/net/ipv%v/conf/%v/forwarding", ipversion, ifname)
	return os.WriteFile(path, []byte(val), 0644)
}

func SetIpv4forward(val string) error {
	return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte(val), 0644)
}

func SetForwarding(ifname string, val string) {
	_ = setForwarding(ifname, consts.IpVersionStr_4, val)
	_ = setForwarding(ifname, consts.IpVersionStr_6, val)
}

func checkSendRedirects(ifname string, ipversion consts.IpVersionStr) error {
	path := fmt.Sprintf("/proc/sys/net/ipv%v/conf/%v/send_redirects", ipversion, ifname)
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if bytes.Equal(bytes.TrimSpace(b), []byte("0")) {
		return nil
	}
	return fmt.Errorf("send_directs on %v is on: %v; see docs of dae for help", ifname, path)
}

func CheckSendRedirects(ifname string) error {
	if err := checkSendRedirects(ifname, consts.IpVersionStr_4); err != nil {
		return err
	}
	return nil
}

func setSendRedirects(ifname string, ipversion consts.IpVersionStr, val string) error {
	path := fmt.Sprintf("/proc/sys/net/ipv%v/conf/%v/send_redirects", ipversion, ifname)
	return os.WriteFile(path, []byte(val), 0644)
}

func SetSendRedirects(ifname string, val string) {
	_ = setSendRedirects(ifname, consts.IpVersionStr_4, val)
}

func ProcessName2String(pname []uint8) string {
	return string(bytes.TrimRight(pname, string([]byte{0})))
}

func Mac2String(mac []uint8) string {
	ori := []byte(hex.EncodeToString(mac))
	// Insert ":".
	b := make([]byte, len(ori)/2*3-1)
	for i, j := 0, 0; i < len(ori); i, j = i+2, j+3 {
		copy(b[j:j+2], ori[i:i+2])
		if j+2 < len(b) {
			b[j+2] = ':'
		}
	}
	return string(b)
}
