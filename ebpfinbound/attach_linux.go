//go:build linux && !dae_stub_ebpf

// SPDX-License-Identifier: AGPL-3.0-only

package ebpfinbound

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
	ciliumLink "github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const (
	captureUserTCMajor     = uint16(0xdab1)
	captureInternalTCMajor = uint16(0xdab2)
)

type ownedTCAttachment struct{ record ownedAttachmentRecord }

func (r *captureRuntime) attachDatapath() ([]ownedTCAttachment, []func() error, error) {
	if r.bpf == nil || r.netns == nil {
		return nil, nil, errors.New("capture runtime is closed")
	}
	if err := r.configureKernel(); err != nil {
		return nil, nil, fmt.Errorf("configure capture kernel settings: %w", err)
	}
	var records []ownedTCAttachment
	cleanup := make([]func() error, 0, 24)
	fail := func(err error) ([]ownedTCAttachment, []func() error, error) {
		_ = runCleanupReverse(cleanup)
		return nil, nil, err
	}

	internalRecords, internalCleanup, err := r.attachInternalLinks()
	if err != nil {
		return fail(fmt.Errorf("attach private capture links: %w", err))
	}
	records = append(records, internalRecords...)
	cleanup = append(cleanup, internalCleanup...)

	if len(r.config.WANInterfaces) > 0 {
		cgroupCleanup, attachErr := r.attachProcessMetadata()
		if attachErr != nil {
			if r.config.RequireProcessMetadata {
				return fail(fmt.Errorf("attach required process metadata hooks: %w", attachErr))
			}
			if r.log != nil {
				r.log.Warn("process metadata hooks unavailable; process matching will degrade", "error", attachErr)
			}
		} else {
			r.processMetadataEnabled = true
			cleanup = append(cleanup, cgroupCleanup...)
		}
	}

	for _, interfaceName := range r.config.LANInterfaces {
		attached, attachedCleanup, attachErr := r.attachLANInterface(interfaceName)
		if attachErr != nil {
			return fail(fmt.Errorf("attach LAN interface %s: %w", interfaceName, attachErr))
		}
		records = append(records, attached...)
		cleanup = append(cleanup, attachedCleanup...)
	}
	for _, interfaceName := range r.config.WANInterfaces {
		attached, attachedCleanup, attachErr := r.attachWANInterface(interfaceName)
		if attachErr != nil {
			return fail(fmt.Errorf("attach WAN interface %s: %w", interfaceName, attachErr))
		}
		records = append(records, attached...)
		cleanup = append(cleanup, attachedCleanup...)
	}
	return records, cleanup, nil
}

func (r *captureRuntime) configureKernel() error {
	if !r.config.AutoConfigureKernel || r.netns == nil || r.netns.hostSysctls == nil {
		return nil
	}
	manager := r.netns.hostSysctls
	if err := manager.Set("/proc/sys/net/ipv4/conf/all/rp_filter", "0"); err != nil {
		return err
	}
	if err := manager.Set("/proc/sys/net/ipv4/conf/all/arp_filter", "0"); err != nil {
		return err
	}
	if len(r.config.LANInterfaces) > 0 {
		if err := manager.Set("/proc/sys/net/ipv4/ip_forward", "1"); err != nil {
			return err
		}
		if err := manager.Set("/proc/sys/net/ipv6/conf/all/forwarding", "1"); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	for _, interfaceName := range r.config.LANInterfaces {
		for _, setting := range []struct{ family, key, value string }{
			{"ipv4", "forwarding", "1"},
			{"ipv4", "send_redirects", "0"},
			{"ipv4", "rp_filter", "0"},
			{"ipv6", "forwarding", "1"},
		} {
			path, err := interfaceSysctlPath(setting.family, interfaceName, setting.key)
			if err != nil {
				return err
			}
			if err := manager.Set(path, setting.value); err != nil {
				if setting.family == "ipv6" && errors.Is(err, os.ErrNotExist) {
					continue
				}
				return err
			}
		}
	}
	if len(r.config.LANInterfaces) > 0 {
		for _, interfaceName := range r.config.WANInterfaces {
			path, err := interfaceSysctlPath("ipv6", interfaceName, "accept_ra")
			if err != nil {
				return err
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			if strings.TrimSpace(string(raw)) == "1" {
				if err := manager.Set(path, "2"); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (r *captureRuntime) attachLANInterface(interfaceName string) ([]ownedTCAttachment, []func() error, error) {
	link, err := captureInterface(interfaceName)
	if err != nil {
		return nil, nil, err
	}
	ingressProgram, egressProgram := r.bpf.TproxyLanIngressL3, r.bpf.TproxyLanEgressL3
	ingressName, egressName := "dae_cap_li_l3", "dae_cap_le_l3"
	if linkUsesEthernetHeader(link) {
		ingressProgram, egressProgram = r.bpf.TproxyLanIngressL2, r.bpf.TproxyLanEgressL2
		ingressName, egressName = "dae_cap_li_l2", "dae_cap_le_l2"
	}
	return attachInterfacePair(link, false,
		newTCFilter(link, netlink.HANDLE_MIN_INGRESS, captureUserTCMajor, 0x101, 2, ingressName, ingressProgram),
		newTCFilter(link, netlink.HANDLE_MIN_EGRESS, captureUserTCMajor, 0x102, 1, egressName, egressProgram),
	)
}

func (r *captureRuntime) attachWANInterface(interfaceName string) ([]ownedTCAttachment, []func() error, error) {
	link, err := captureInterface(interfaceName)
	if err != nil {
		return nil, nil, err
	}
	if link.Attrs().Index == 1 || link.Attrs().Name == "lo" {
		return nil, nil, errors.New("cannot attach WAN capture to loopback")
	}
	ingressProgram, egressProgram := r.bpf.TproxyWanIngressL3, r.bpf.TproxyWanEgressL3
	ingressName, egressName := "dae_cap_wi_l3", "dae_cap_we_l3"
	if linkUsesEthernetHeader(link) {
		ingressProgram, egressProgram = r.bpf.TproxyWanIngressL2, r.bpf.TproxyWanEgressL2
		ingressName, egressName = "dae_cap_wi_l2", "dae_cap_we_l2"
	}
	return attachInterfacePair(link, false,
		newTCFilter(link, netlink.HANDLE_MIN_EGRESS, captureUserTCMajor, 0x201, 2, egressName, egressProgram),
		newTCFilter(link, netlink.HANDLE_MIN_INGRESS, captureUserTCMajor, 0x202, 1, ingressName, ingressProgram),
	)
}

func (r *captureRuntime) attachInternalLinks() ([]ownedTCAttachment, []func() error, error) {
	if r.netns.hostLink == nil || r.netns.peerLink == nil {
		return nil, nil, errors.New("private capture links are unavailable")
	}
	var records []ownedTCAttachment
	var cleanup []func() error
	peerFilter := newTCFilter(r.netns.peerLink, netlink.HANDLE_MIN_INGRESS, captureInternalTCMajor, 0x001, 0, "dae_cap_peer", r.bpf.TproxyDae0peerIngress)
	var peerRecord ownedTCAttachment
	var peerCleanup []func() error
	if err := r.netns.With(func() error {
		var attachErr error
		peerRecord, peerCleanup, attachErr = attachSingleFilter(r.netns.peerLink, true, peerFilter)
		return attachErr
	}); err != nil {
		return nil, nil, err
	}
	records = append(records, peerRecord)
	cleanup = append(cleanup, peerCleanup...)

	hostFilter := newTCFilter(r.netns.hostLink, netlink.HANDLE_MIN_INGRESS, captureInternalTCMajor, 0x002, 0, "dae_cap_host", r.bpf.TproxyDae0Ingress)
	hostRecord, hostCleanup, err := attachSingleFilter(r.netns.hostLink, false, hostFilter)
	if err != nil {
		_ = runCleanupReverse(cleanup)
		return nil, nil, err
	}
	records = append(records, hostRecord)
	cleanup = append(cleanup, hostCleanup...)
	return records, cleanup, nil
}

func (r *captureRuntime) attachProcessMetadata() ([]func() error, error) {
	cgroupPath, err := detectCgroupPath()
	if err != nil {
		return nil, err
	}
	programs := []struct {
		program *ebpf.Program
		attach  ebpf.AttachType
	}{
		{r.bpf.TproxyWanCgSockCreate, ebpf.AttachCGroupInetSockCreate},
		{r.bpf.TproxyWanCgSockRelease, ebpf.AttachCgroupInetSockRelease},
		{r.bpf.TproxyWanCgConnect4, ebpf.AttachCGroupInet4Connect},
		{r.bpf.TproxyWanCgConnect6, ebpf.AttachCGroupInet6Connect},
		{r.bpf.TproxyWanCgSendmsg4, ebpf.AttachCGroupUDP4Sendmsg},
		{r.bpf.TproxyWanCgSendmsg6, ebpf.AttachCGroupUDP6Sendmsg},
	}
	cleanup := make([]func() error, 0, len(programs))
	for _, item := range programs {
		if item.program == nil {
			_ = runCleanupReverse(cleanup)
			return nil, errors.New("capture collection is missing a process metadata hook")
		}
		attached, err := ciliumLink.AttachCgroup(ciliumLink.CgroupOptions{Path: cgroupPath, Attach: item.attach, Program: item.program})
		if err != nil {
			_ = runCleanupReverse(cleanup)
			return nil, fmt.Errorf("attach cgroup program: %w", err)
		}
		link := attached
		cleanup = append(cleanup, link.Close)
	}
	return cleanup, nil
}

func captureInterface(name string) (netlink.Link, error) {
	if name == "" || strings.Contains(name, "/") {
		return nil, fmt.Errorf("invalid interface name %q", name)
	}
	return netlink.LinkByName(name)
}

func linkUsesEthernetHeader(link netlink.Link) bool {
	if link == nil || link.Attrs() == nil {
		return false
	}
	switch link.Attrs().EncapType {
	case "none", "ipip", "ppp", "tun":
		return false
	default:
		return true
	}
}

func newTCFilter(link netlink.Link, parent uint32, major, minor, priority uint16, name string, program *ebpf.Program) *netlink.BpfFilter {
	filter := &netlink.BpfFilter{FilterAttrs: netlink.FilterAttrs{LinkIndex: link.Attrs().Index, Parent: parent, Handle: netlink.MakeHandle(major, minor), Protocol: unix.ETH_P_ALL, Priority: priority}, Name: name, DirectAction: true, Fd: -1}
	if program != nil {
		filter.Fd = program.FD()
	}
	return filter
}

func attachInterfacePair(link netlink.Link, inNetNS bool, first, second *netlink.BpfFilter) ([]ownedTCAttachment, []func() error, error) {
	firstRecord, firstCleanup, err := attachSingleFilter(link, inNetNS, first)
	if err != nil {
		return nil, nil, err
	}
	secondRecord, secondCleanup, err := attachSingleFilter(link, inNetNS, second)
	if err != nil {
		_ = runCleanupReverse(firstCleanup)
		return nil, nil, err
	}
	return []ownedTCAttachment{firstRecord, secondRecord}, append(firstCleanup, secondCleanup...), nil
}

func attachSingleFilter(link netlink.Link, inNetNS bool, filter *netlink.BpfFilter) (ownedTCAttachment, []func() error, error) {
	if link == nil || link.Attrs() == nil || filter == nil || filter.Fd < 0 {
		return ownedTCAttachment{}, nil, errors.New("invalid BPF TC filter")
	}
	qdisc, qdiscCreated, err := ensureClsact(link)
	if err != nil {
		return ownedTCAttachment{}, nil, err
	}
	cleanupQdisc := func() error {
		if !qdiscCreated || !interfaceFiltersEmpty(link) {
			return nil
		}
		if err := netlink.QdiscDel(qdisc); err != nil && !isMissingNetlinkError(err) {
			return fmt.Errorf("delete owned clsact qdisc on %s: %w", link.Attrs().Name, err)
		}
		return nil
	}
	if err := assertTCSlotFree(link, filter); err != nil {
		_ = cleanupQdisc()
		return ownedTCAttachment{}, nil, err
	}
	if err := netlink.FilterAdd(filter); err != nil {
		_ = cleanupQdisc()
		return ownedTCAttachment{}, nil, fmt.Errorf("add capture TC filter %s: %w", filter.Name, err)
	}
	actual, err := findTCFilter(link, filter.Attrs().Parent, filter.Attrs().Handle, filter.Attrs().Priority)
	if err != nil {
		_ = netlink.FilterDel(filter)
		_ = cleanupQdisc()
		return ownedTCAttachment{}, nil, err
	}
	bpfActual, ok := actual.(*netlink.BpfFilter)
	if !ok || bpfActual.Name != filter.Name {
		_ = netlink.FilterDel(filter)
		_ = cleanupQdisc()
		return ownedTCAttachment{}, nil, fmt.Errorf("capture TC filter identity mismatch on %s", link.Attrs().Name)
	}
	record := ownedAttachmentRecord{Interface: link.Attrs().Name, InNetNS: inNetNS, Parent: bpfActual.Attrs().Parent, Handle: bpfActual.Attrs().Handle, Priority: bpfActual.Attrs().Priority, Name: bpfActual.Name, ProgramID: bpfActual.Id, QdiscCreated: qdiscCreated}
	return ownedTCAttachment{record: record}, []func() error{func() error { return deleteOwnedFilter(record) }, cleanupQdisc}, nil
}

func ensureClsact(link netlink.Link) (*netlink.GenericQdisc, bool, error) {
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return nil, false, fmt.Errorf("list qdiscs on %s: %w", link.Attrs().Name, err)
	}
	for _, qdisc := range qdiscs {
		if qdisc != nil && qdisc.Type() == "clsact" {
			return &netlink.GenericQdisc{QdiscAttrs: *qdisc.Attrs(), QdiscType: "clsact"}, false, nil
		}
	}
	qdisc := &netlink.GenericQdisc{QdiscAttrs: netlink.QdiscAttrs{LinkIndex: link.Attrs().Index, Handle: netlink.MakeHandle(0xffff, 0), Parent: netlink.HANDLE_CLSACT}, QdiscType: "clsact"}
	if err := netlink.QdiscAdd(qdisc); err != nil {
		return nil, false, fmt.Errorf("add clsact qdisc to %s: %w", link.Attrs().Name, err)
	}
	return qdisc, true, nil
}

func assertTCSlotFree(link netlink.Link, candidate *netlink.BpfFilter) error {
	filters, err := netlink.FilterList(link, candidate.Attrs().Parent)
	if err != nil {
		return err
	}
	for _, existing := range filters {
		if existing == nil || existing.Attrs() == nil {
			continue
		}
		attrs := existing.Attrs()
		if attrs.Handle == candidate.Attrs().Handle || (attrs.Priority == candidate.Attrs().Priority && attrs.Protocol == candidate.Attrs().Protocol) {
			return fmt.Errorf("TC slot collision on %s parent=%#x handle=%#x priority=%d with %s", link.Attrs().Name, attrs.Parent, attrs.Handle, attrs.Priority, existing.Type())
		}
	}
	return nil
}

func findTCFilter(link netlink.Link, parent, handle uint32, priority uint16) (netlink.Filter, error) {
	filters, err := netlink.FilterList(link, parent)
	if err != nil {
		return nil, err
	}
	for _, filter := range filters {
		if filter != nil && filter.Attrs() != nil && filter.Attrs().Handle == handle && filter.Attrs().Priority == priority {
			return filter, nil
		}
	}
	return nil, errors.New("newly attached TC filter was not found")
}

func deleteOwnedFilter(record ownedAttachmentRecord) error {
	remove := func() error {
		link, err := netlink.LinkByName(record.Interface)
		if err != nil {
			if isMissingNetlinkError(err) {
				return nil
			}
			return err
		}
		filter, err := findTCFilter(link, record.Parent, record.Handle, record.Priority)
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				return nil
			}
			return err
		}
		bpfFilter, ok := filter.(*netlink.BpfFilter)
		if !ok || bpfFilter.Name != record.Name || (record.ProgramID != 0 && bpfFilter.Id != record.ProgramID) {
			return fmt.Errorf("refuse to delete TC filter on %s: ownership identity changed", record.Interface)
		}
		if err := netlink.FilterDel(filter); err != nil && !isMissingNetlinkError(err) {
			return fmt.Errorf("delete owned TC filter %s: %w", record.Name, err)
		}
		return nil
	}
	if !record.InNetNS {
		return remove()
	}
	return withNamedNetNS(captureNetNSName, remove)
}

func cleanupStaleAttachments(records []ownedAttachmentRecord) error {
	var errs []error
	for index := len(records) - 1; index >= 0; index-- {
		if err := deleteOwnedFilter(records[index]); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func withNamedNetNS(name string, function func() error) (err error) {
	host, err := netns.Get()
	if err != nil {
		return err
	}
	defer host.Close()
	target, err := netns.GetFromName(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer target.Close()
	if err := netns.Set(target); err != nil {
		return err
	}
	defer func() { err = errors.Join(err, netns.Set(host)) }()
	return function()
}

func interfaceFiltersEmpty(link netlink.Link) bool {
	for _, parent := range []uint32{netlink.HANDLE_MIN_INGRESS, netlink.HANDLE_MIN_EGRESS} {
		filters, err := netlink.FilterList(link, parent)
		if err != nil || len(filters) != 0 {
			return false
		}
	}
	return true
}

func detectCgroupPath() (string, error) {
	file, err := os.Open("/proc/mounts")
	if err != nil {
		return "", err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 3 && fields[2] == "cgroup2" {
			return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\134`, `\`).Replace(fields[1]), nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", errors.New("cgroup v2 mount not found")
}

func attachmentRecords(source []ownedTCAttachment) []ownedAttachmentRecord {
	result := make([]ownedAttachmentRecord, 0, len(source))
	for _, attachment := range source {
		result = append(result, attachment.record)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Interface != result[j].Interface {
			return result[i].Interface < result[j].Interface
		}
		if result[i].Parent != result[j].Parent {
			return result[i].Parent < result[j].Parent
		}
		return result[i].Handle < result[j].Handle
	})
	return result
}
