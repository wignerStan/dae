//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only

package ebpfinbound

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const ownershipRecordVersion = 2

var runtimeStateDirectory = "/run/dae-ebpfinbound"

func runtimeLockPath() string { return filepath.Join(runtimeStateDirectory, "runtime.lock") }
func ownerRecordPath() string { return filepath.Join(runtimeStateDirectory, "owner.json") }
func ownerRecordTemp() string { return filepath.Join(runtimeStateDirectory, ".owner.json.tmp") }

type ownedAttachmentRecord struct {
	Interface    string `json:"interface"`
	InNetNS      bool   `json:"in_netns,omitempty"`
	Parent       uint32 `json:"parent"`
	Handle       uint32 `json:"handle"`
	Priority     uint16 `json:"priority"`
	Name         string `json:"name"`
	ProgramID    int    `json:"program_id"`
	QdiscCreated bool   `json:"qdisc_created,omitempty"`
}

type ownershipRecord struct {
	Version       int                     `json:"version"`
	Token         string                  `json:"token"`
	PID           int                     `json:"pid"`
	BootID        string                  `json:"boot_id"`
	StartedAt     time.Time               `json:"started_at"`
	Released      bool                    `json:"released,omitempty"`
	Namespace     string                  `json:"namespace"`
	HostLink      string                  `json:"host_link"`
	PeerLink      string                  `json:"peer_link"`
	LANInterfaces []string                `json:"lan_interfaces,omitempty"`
	WANInterfaces []string                `json:"wan_interfaces,omitempty"`
	Attachments   []ownedAttachmentRecord `json:"attachments,omitempty"`
	Sysctls       []sysctlMutation        `json:"sysctls,omitempty"`
}

type ownershipLease struct {
	mu       sync.Mutex
	lockFile *os.File
	record   ownershipRecord
	closed   bool
}

func acquireOwnership(report PreflightReport) (*ownershipLease, error) {
	if err := os.MkdirAll(runtimeStateDirectory, 0o700); err != nil {
		return nil, fmt.Errorf("create runtime state directory: %w", err)
	}
	lockFile, err := os.OpenFile(runtimeLockPath(), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open runtime lock: %w", err)
	}
	if err := unix.Flock(int(lockFile.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = lockFile.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, errors.New("another dae eBPF inbound runtime owns the host resources")
		}
		return nil, fmt.Errorf("acquire runtime lock: %w", err)
	}
	fail := func(err error) (*ownershipLease, error) {
		_ = unix.Flock(int(lockFile.Fd()), unix.LOCK_UN)
		_ = lockFile.Close()
		return nil, err
	}
	if raw, err := os.ReadFile(ownerRecordPath()); err == nil && len(strings.TrimSpace(string(raw))) != 0 {
		var record ownershipRecord
		if decodeErr := json.Unmarshal(raw, &record); decodeErr != nil {
			return fail(fmt.Errorf("invalid stale ownership record: %w", decodeErr))
		}
		if validateErr := validateOwnershipRecord(record); validateErr != nil {
			return fail(fmt.Errorf("invalid stale ownership record: %w", validateErr))
		}
		return fail(fmt.Errorf("stale dae eBPF ownership record for pid %d exists; run `dae-ebpf-tool cleanup-stale` after verifying no runtime is active", record.PID))
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fail(fmt.Errorf("read ownership record: %w", err))
	}
	if len(report.ExistingResources) > 0 {
		return fail(fmt.Errorf("refuse to delete unowned capture resources: %s", strings.Join(report.ExistingResources, ", ")))
	}
	token, err := randomToken()
	if err != nil {
		return fail(err)
	}
	bootID, err := readBootID()
	if err != nil {
		return fail(err)
	}
	lease := &ownershipLease{lockFile: lockFile, record: ownershipRecord{
		Version:       ownershipRecordVersion,
		Token:         token,
		PID:           os.Getpid(),
		BootID:        bootID,
		StartedAt:     time.Now().UTC(),
		Namespace:     captureNetNSName,
		HostLink:      captureHostLink,
		PeerLink:      capturePeerLink,
		LANInterfaces: append([]string(nil), report.Config.LANInterfaces...),
		WANInterfaces: append([]string(nil), report.Config.WANInterfaces...),
	}}
	if err := lease.persistLocked(); err != nil {
		return fail(err)
	}
	return lease, nil
}

func (l *ownershipLease) Token() string {
	if l == nil {
		return ""
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.record.Token
}
func (l *ownershipLease) SetAttachments(records []ownedAttachmentRecord) error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return errors.New("ownership lease is closed")
	}
	l.record.Attachments = append([]ownedAttachmentRecord(nil), records...)
	return l.persistLocked()
}
func (l *ownershipLease) UpsertAttachment(record ownedAttachmentRecord) error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return errors.New("ownership lease is closed")
	}
	replaced := false
	for index := range l.record.Attachments {
		current := l.record.Attachments[index]
		if current.Interface == record.Interface && current.InNetNS == record.InNetNS && current.Parent == record.Parent && current.Handle == record.Handle {
			l.record.Attachments[index] = record
			replaced = true
			break
		}
	}
	if !replaced {
		l.record.Attachments = append(l.record.Attachments, record)
	}
	return l.persistLocked()
}
func (l *ownershipLease) SetSysctls(mutations []sysctlMutation) error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return errors.New("ownership lease is closed")
	}
	l.record.Sysctls = append([]sysctlMutation(nil), mutations...)
	return l.persistLocked()
}

func (l *ownershipLease) persistLocked() error {
	if err := validateOwnershipRecord(l.record); err != nil {
		return fmt.Errorf("validate ownership record: %w", err)
	}
	raw, err := json.MarshalIndent(l.record, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	file, err := os.OpenFile(ownerRecordTemp(), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("write ownership record: %w", err)
	}
	if _, err := file.Write(raw); err != nil {
		_ = file.Close()
		return fmt.Errorf("write ownership record: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync ownership record: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close ownership record: %w", err)
	}
	if err := os.Rename(ownerRecordTemp(), ownerRecordPath()); err != nil {
		return fmt.Errorf("publish ownership record: %w", err)
	}
	directory, err := os.Open(runtimeStateDirectory)
	if err != nil {
		return fmt.Errorf("open ownership directory: %w", err)
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return fmt.Errorf("sync ownership directory: %w", err)
	}
	if err := directory.Close(); err != nil {
		return fmt.Errorf("close ownership directory: %w", err)
	}
	return nil
}

func (l *ownershipLease) Close() error {
	return l.release(true)
}

func (l *ownershipLease) Abandon() error {
	return l.release(false)
}

func (l *ownershipLease) release(removeRecord bool) error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	var errs []error
	if !removeRecord {
		l.record.Released = true
		if err := l.persistLocked(); err != nil {
			errs = append(errs, fmt.Errorf("mark ownership record released: %w", err))
		}
	}
	l.closed = true
	lockFile := l.lockFile
	l.lockFile = nil
	token := l.record.Token
	l.mu.Unlock()
	if removeRecord {
		if raw, err := os.ReadFile(ownerRecordPath()); err == nil {
			var current ownershipRecord
			if decodeErr := json.Unmarshal(raw, &current); decodeErr != nil {
				errs = append(errs, fmt.Errorf("decode current ownership record: %w", decodeErr))
			} else if current.Token == token {
				if err := os.Remove(ownerRecordPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
					errs = append(errs, err)
				}
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	if lockFile != nil {
		if err := unix.Flock(int(lockFile.Fd()), unix.LOCK_UN); err != nil {
			errs = append(errs, err)
		}
		if err := lockFile.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func CleanupStale(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.MkdirAll(runtimeStateDirectory, 0o700); err != nil {
		return err
	}
	lockFile, err := os.OpenFile(runtimeLockPath(), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lockFile.Close()
	if err := unix.Flock(int(lockFile.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return errors.New("runtime lock is held; refuse stale cleanup")
	}
	defer unix.Flock(int(lockFile.Fd()), unix.LOCK_UN)
	raw, err := os.ReadFile(ownerRecordPath())
	if errors.Is(err, os.ErrNotExist) {
		if resources := existingCaptureResourcesWithoutRecord(); len(resources) > 0 {
			return fmt.Errorf("unowned resources exist without an ownership record: %s", strings.Join(resources, ", "))
		}
		return nil
	}
	if err != nil {
		return err
	}
	var record ownershipRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return fmt.Errorf("decode ownership record: %w", err)
	}
	if err := validateOwnershipRecord(record); err != nil {
		return fmt.Errorf("refuse invalid ownership record: %w", err)
	}
	bootID, err := readBootID()
	if err != nil {
		return err
	}
	if !record.Released && record.BootID == bootID && pidAlive(record.PID) {
		return fmt.Errorf("recorded runtime pid %d is still active", record.PID)
	}
	var errs []error
	if err := cleanupStaleAttachments(record.Attachments); err != nil {
		errs = append(errs, err)
	}
	if err := restoreRecordedSysctls(record.Sysctls); err != nil {
		errs = append(errs, err)
	}
	if err := cleanupRecordedNetNS(record); err != nil {
		errs = append(errs, err)
	}
	if len(errs) != 0 {
		return errors.Join(errs...)
	}
	return os.Remove(ownerRecordPath())
}

func cleanupRecordedNetNS(record ownershipRecord) error {
	var errs []error
	for _, name := range []string{record.PeerLink, record.HostLink} {
		if name == "" {
			continue
		}
		link, err := netlink.LinkByName(name)
		if err != nil {
			if !isMissingNetlinkError(err) {
				errs = append(errs, err)
			}
			continue
		}
		if link.Attrs() == nil || link.Attrs().Alias != record.Token {
			errs = append(errs, fmt.Errorf("refuse to delete link %s without matching ownership token", name))
			continue
		}
		if err := netlink.LinkDel(link); err != nil && !isMissingNetlinkError(err) {
			errs = append(errs, err)
		}
	}
	if record.Namespace != "" {
		if err := netns.DeleteNamed(record.Namespace); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func validateOwnershipRecord(record ownershipRecord) error {
	if record.Version != ownershipRecordVersion {
		return fmt.Errorf("unsupported version %d", record.Version)
	}
	const tokenPrefix = "dae-ebpfinbound:"
	encodedToken := strings.TrimPrefix(record.Token, tokenPrefix)
	if encodedToken == record.Token || len(encodedToken) != 32 {
		return errors.New("invalid ownership token")
	}
	if _, err := hex.DecodeString(encodedToken); err != nil {
		return fmt.Errorf("invalid ownership token: %w", err)
	}
	if record.PID <= 0 || record.BootID == "" || record.StartedAt.IsZero() {
		return errors.New("incomplete owner identity")
	}
	if record.Namespace != captureNetNSName || record.HostLink != captureHostLink || record.PeerLink != capturePeerLink {
		return errors.New("ownership record names do not match the provider's fixed resources")
	}
	if len(record.LANInterfaces) > 64 || len(record.WANInterfaces) > 64 || len(record.Attachments) > 64 || len(record.Sysctls) > 128 {
		return errors.New("ownership record exceeds resource limits")
	}
	lanInterfaces, err := validateRecordedInterfaces("LAN", record.LANInterfaces)
	if err != nil {
		return err
	}
	wanInterfaces, err := validateRecordedInterfaces("WAN", record.WANInterfaces)
	if err != nil {
		return err
	}
	attachmentSlots := make(map[string]struct{}, len(record.Attachments))
	for _, attachment := range record.Attachments {
		if err := validateOwnedAttachment(attachment, lanInterfaces, wanInterfaces); err != nil {
			return err
		}
		slot := fmt.Sprintf("%t:%s:%d:%d", attachment.InNetNS, attachment.Interface, attachment.Parent, attachment.Handle)
		if _, exists := attachmentSlots[slot]; exists {
			return fmt.Errorf("duplicate attachment slot %s", slot)
		}
		attachmentSlots[slot] = struct{}{}
	}
	for _, mutation := range record.Sysctls {
		if err := validateRecordedSysctl(mutation, lanInterfaces, wanInterfaces); err != nil {
			return err
		}
	}
	return nil
}

func validateRecordedInterfaces(role string, names []string) (map[string]struct{}, error) {
	result := make(map[string]struct{}, len(names))
	if !sort.StringsAreSorted(names) {
		return nil, fmt.Errorf("%s interfaces are not sorted", role)
	}
	for _, name := range names {
		if name == "" || name == "lo" || name == captureHostLink || name == capturePeerLink || len(name) >= unix.IFNAMSIZ || strings.ContainsAny(name, "/\x00\r\n") {
			return nil, fmt.Errorf("invalid %s interface %q", role, name)
		}
		if _, exists := result[name]; exists {
			return nil, fmt.Errorf("duplicate %s interface %q", role, name)
		}
		result[name] = struct{}{}
	}
	return result, nil
}

func validateOwnedAttachment(record ownedAttachmentRecord, lanInterfaces, wanInterfaces map[string]struct{}) error {
	if record.Interface == "" || len(record.Interface) >= unix.IFNAMSIZ || strings.Contains(record.Interface, "/") {
		return fmt.Errorf("invalid attachment interface %q", record.Interface)
	}
	if record.ProgramID <= 0 {
		return fmt.Errorf("invalid program id %d", record.ProgramID)
	}
	type expectedAttachment struct {
		parent uint32
		handle uint32
		role   string
	}
	expectedUser := map[string]expectedAttachment{
		"dae_cap_li_l2": {netlink.HANDLE_MIN_INGRESS, netlink.MakeHandle(captureUserTCMajor, 0x101), "LAN"},
		"dae_cap_li_l3": {netlink.HANDLE_MIN_INGRESS, netlink.MakeHandle(captureUserTCMajor, 0x101), "LAN"},
		"dae_cap_le_l2": {netlink.HANDLE_MIN_EGRESS, netlink.MakeHandle(captureUserTCMajor, 0x102), "LAN"},
		"dae_cap_le_l3": {netlink.HANDLE_MIN_EGRESS, netlink.MakeHandle(captureUserTCMajor, 0x102), "LAN"},
		"dae_cap_we_l2": {netlink.HANDLE_MIN_EGRESS, netlink.MakeHandle(captureUserTCMajor, 0x201), "WAN"},
		"dae_cap_we_l3": {netlink.HANDLE_MIN_EGRESS, netlink.MakeHandle(captureUserTCMajor, 0x201), "WAN"},
		"dae_cap_wi_l2": {netlink.HANDLE_MIN_INGRESS, netlink.MakeHandle(captureUserTCMajor, 0x202), "WAN"},
		"dae_cap_wi_l3": {netlink.HANDLE_MIN_INGRESS, netlink.MakeHandle(captureUserTCMajor, 0x202), "WAN"},
	}
	if expected, exists := expectedUser[record.Name]; exists {
		if record.Interface == captureHostLink || record.Interface == capturePeerLink || record.InNetNS || record.Parent != expected.parent || record.Handle != expected.handle {
			return fmt.Errorf("invalid user attachment %s on %s", record.Name, record.Interface)
		}
		allowed := lanInterfaces
		if expected.role == "WAN" {
			allowed = wanInterfaces
		}
		if _, exists := allowed[record.Interface]; !exists {
			return fmt.Errorf("%s attachment %s uses unrecorded interface %s", expected.role, record.Name, record.Interface)
		}
		return nil
	}
	if record.Name == "dae_cap_host" {
		if record.Interface != captureHostLink || record.InNetNS || record.Parent != netlink.HANDLE_MIN_INGRESS || record.Handle != netlink.MakeHandle(captureInternalTCMajor, 0x002) {
			return errors.New("invalid host capture attachment")
		}
		return nil
	}
	if record.Name == "dae_cap_peer" {
		if record.Interface != capturePeerLink || !record.InNetNS || record.Parent != netlink.HANDLE_MIN_INGRESS || record.Handle != netlink.MakeHandle(captureInternalTCMajor, 0x001) {
			return errors.New("invalid peer capture attachment")
		}
		return nil
	}
	return fmt.Errorf("invalid attachment name %q", record.Name)
}

func validateRecordedSysctl(mutation sysctlMutation, lanInterfaces, wanInterfaces map[string]struct{}) error {
	clean := filepath.Clean(mutation.Path)
	if clean != mutation.Path || strings.ContainsAny(mutation.Original+mutation.Applied, "\x00\r\n") {
		return fmt.Errorf("invalid recorded sysctl %q", mutation.Path)
	}
	for _, value := range []string{mutation.Original, mutation.Applied} {
		if value != "0" && value != "1" && value != "2" {
			return fmt.Errorf("invalid recorded sysctl value %q", value)
		}
	}
	global := map[string]struct{}{
		"/proc/sys/net/ipv4/ip_forward":                  {},
		"/proc/sys/net/ipv4/conf/all/arp_filter":         {},
		"/proc/sys/net/ipv4/conf/all/rp_filter":          {},
		"/proc/sys/net/ipv4/conf/all/src_valid_mark":     {},
		"/proc/sys/net/ipv4/conf/default/src_valid_mark": {},
		"/proc/sys/net/ipv6/conf/all/forwarding":         {},
	}
	if _, exists := global[clean]; exists {
		return nil
	}
	parts := strings.Split(strings.TrimPrefix(clean, "/proc/sys/net/"), "/")
	if len(parts) != 4 || parts[1] != "conf" {
		return fmt.Errorf("invalid recorded sysctl path %q", mutation.Path)
	}
	family, interfaceName, key := parts[0], parts[2], parts[3]
	if interfaceName == captureHostLink {
		allowed := map[string]map[string]struct{}{
			"ipv4": {"accept_local": {}, "arp_filter": {}, "rp_filter": {}},
			"ipv6": {"disable_ipv6": {}, "forwarding": {}},
		}
		if keys, exists := allowed[family]; exists {
			if _, exists := keys[key]; exists {
				return nil
			}
		}
	}
	if _, exists := lanInterfaces[interfaceName]; exists {
		if (family == "ipv4" && (key == "forwarding" || key == "send_redirects" || key == "rp_filter")) || (family == "ipv6" && key == "forwarding") {
			return nil
		}
	}
	if _, exists := wanInterfaces[interfaceName]; exists && family == "ipv6" && key == "accept_ra" {
		return nil
	}
	return fmt.Errorf("sysctl %q is outside recorded provider scope", mutation.Path)
}

func restoreRecordedSysctls(mutations []sysctlMutation) error {
	var errs []error
	for index := len(mutations) - 1; index >= 0; index-- {
		mutation := mutations[index]
		raw, err := os.ReadFile(mutation.Path)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, err)
			}
			continue
		}
		if strings.TrimSpace(string(raw)) != mutation.Applied {
			continue
		}
		if err := os.WriteFile(mutation.Path, []byte(mutation.Original), 0o644); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func existingCaptureResourcesWithoutRecord() []string {
	resources := existingCaptureResources()
	result := resources[:0]
	for _, resource := range resources {
		if resource != ownerRecordPath() {
			result = append(result, resource)
		}
	}
	return result
}
func randomToken() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate ownership token: %w", err)
	}
	return "dae-ebpfinbound:" + hex.EncodeToString(value[:]), nil
}
func readBootID() (string, error) {
	raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", fmt.Errorf("read boot ID: %w", err)
	}
	return strings.TrimSpace(string(raw)), nil
}
func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := unix.Kill(pid, 0)
	return err == nil || errors.Is(err, unix.EPERM)
}
