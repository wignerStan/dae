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
	"strings"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const ownershipRecordVersion = 1
var runtimeStateDirectory = "/run/dae-ebpfinbound"
func runtimeLockPath() string { return filepath.Join(runtimeStateDirectory, "runtime.lock") }
func ownerRecordPath() string { return filepath.Join(runtimeStateDirectory, "owner.json") }
func ownerRecordTemp() string { return filepath.Join(runtimeStateDirectory, ".owner.json.tmp") }

type ownedAttachmentRecord struct {
	Interface string `json:"interface"`
	InNetNS bool `json:"in_netns,omitempty"`
	Parent uint32 `json:"parent"`
	Handle uint32 `json:"handle"`
	Priority uint16 `json:"priority"`
	Name string `json:"name"`
	ProgramID int `json:"program_id"`
	QdiscCreated bool `json:"qdisc_created,omitempty"`
}

type ownershipRecord struct {
	Version int `json:"version"`
	Token string `json:"token"`
	PID int `json:"pid"`
	BootID string `json:"boot_id"`
	StartedAt time.Time `json:"started_at"`
	Namespace string `json:"namespace"`
	HostLink string `json:"host_link"`
	PeerLink string `json:"peer_link"`
	Attachments []ownedAttachmentRecord `json:"attachments,omitempty"`
	Sysctls []sysctlMutation `json:"sysctls,omitempty"`
}

type ownershipLease struct {
	mu sync.Mutex
	lockFile *os.File
	record ownershipRecord
	closed bool
}

func acquireOwnership(report PreflightReport) (*ownershipLease, error) {
	if err := os.MkdirAll(runtimeStateDirectory, 0o700); err != nil { return nil, fmt.Errorf("create runtime state directory: %w", err) }
	lockFile, err := os.OpenFile(runtimeLockPath(), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil { return nil, fmt.Errorf("open runtime lock: %w", err) }
	if err := unix.Flock(int(lockFile.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = lockFile.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) { return nil, errors.New("another dae eBPF inbound runtime owns the host resources") }
		return nil, fmt.Errorf("acquire runtime lock: %w", err)
	}
	fail := func(err error) (*ownershipLease, error) { _ = unix.Flock(int(lockFile.Fd()), unix.LOCK_UN); _ = lockFile.Close(); return nil, err }
	if raw, err := os.ReadFile(ownerRecordPath()); err == nil && len(strings.TrimSpace(string(raw))) != 0 {
		var record ownershipRecord
		if decodeErr := json.Unmarshal(raw, &record); decodeErr != nil { return fail(fmt.Errorf("invalid stale ownership record: %w", decodeErr)) }
		return fail(fmt.Errorf("stale dae eBPF ownership record for pid %d exists; run `dae-ebpf-tool cleanup-stale` after verifying no runtime is active", record.PID))
	} else if err != nil && !errors.Is(err, os.ErrNotExist) { return fail(fmt.Errorf("read ownership record: %w", err)) }
	if len(report.ExistingResources) > 0 { return fail(fmt.Errorf("refuse to delete unowned capture resources: %s", strings.Join(report.ExistingResources, ", "))) }
	token, err := randomToken(); if err != nil { return fail(err) }
	bootID, err := readBootID(); if err != nil { return fail(err) }
	lease := &ownershipLease{lockFile: lockFile, record: ownershipRecord{Version: ownershipRecordVersion, Token: token, PID: os.Getpid(), BootID: bootID, StartedAt: time.Now().UTC(), Namespace: captureNetNSName, HostLink: captureHostLink, PeerLink: capturePeerLink}}
	if err := lease.persistLocked(); err != nil { return fail(err) }
	return lease, nil
}

func (l *ownershipLease) Token() string { if l == nil { return "" }; l.mu.Lock(); defer l.mu.Unlock(); return l.record.Token }
func (l *ownershipLease) SetAttachments(records []ownedAttachmentRecord) error { if l == nil { return nil }; l.mu.Lock(); defer l.mu.Unlock(); if l.closed { return errors.New("ownership lease is closed") }; l.record.Attachments = append([]ownedAttachmentRecord(nil), records...); return l.persistLocked() }
func (l *ownershipLease) SetSysctls(mutations []sysctlMutation) error { if l == nil { return nil }; l.mu.Lock(); defer l.mu.Unlock(); if l.closed { return errors.New("ownership lease is closed") }; l.record.Sysctls = append([]sysctlMutation(nil), mutations...); return l.persistLocked() }

func (l *ownershipLease) persistLocked() error {
	raw, err := json.MarshalIndent(l.record, "", "  "); if err != nil { return err }; raw = append(raw, '\n')
	if err := os.WriteFile(ownerRecordTemp(), raw, 0o600); err != nil { return fmt.Errorf("write ownership record: %w", err) }
	if err := os.Rename(ownerRecordTemp(), ownerRecordPath()); err != nil { return fmt.Errorf("publish ownership record: %w", err) }
	return nil
}

func (l *ownershipLease) Close() error {
	if l == nil { return nil }
	l.mu.Lock(); if l.closed { l.mu.Unlock(); return nil }; l.closed = true; lockFile := l.lockFile; l.lockFile = nil; token := l.record.Token; l.mu.Unlock()
	var errs []error
	if raw, err := os.ReadFile(ownerRecordPath()); err == nil {
		var current ownershipRecord
		if json.Unmarshal(raw, &current) == nil && current.Token == token { if err := os.Remove(ownerRecordPath()); err != nil && !errors.Is(err, os.ErrNotExist) { errs = append(errs, err) } }
	} else if !errors.Is(err, os.ErrNotExist) { errs = append(errs, err) }
	if lockFile != nil { if err := unix.Flock(int(lockFile.Fd()), unix.LOCK_UN); err != nil { errs = append(errs, err) }; if err := lockFile.Close(); err != nil { errs = append(errs, err) } }
	return errors.Join(errs...)
}

func CleanupStale(ctx context.Context) error {
	if ctx == nil { ctx = context.Background() }; if err := ctx.Err(); err != nil { return err }
	if err := os.MkdirAll(runtimeStateDirectory, 0o700); err != nil { return err }
	lockFile, err := os.OpenFile(runtimeLockPath(), os.O_CREATE|os.O_RDWR, 0o600); if err != nil { return err }; defer lockFile.Close()
	if err := unix.Flock(int(lockFile.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil { return errors.New("runtime lock is held; refuse stale cleanup") }
	defer unix.Flock(int(lockFile.Fd()), unix.LOCK_UN)
	raw, err := os.ReadFile(ownerRecordPath())
	if errors.Is(err, os.ErrNotExist) { if resources := existingCaptureResourcesWithoutRecord(); len(resources) > 0 { return fmt.Errorf("unowned resources exist without an ownership record: %s", strings.Join(resources, ", ")) }; return nil }
	if err != nil { return err }
	var record ownershipRecord; if err := json.Unmarshal(raw, &record); err != nil { return fmt.Errorf("decode ownership record: %w", err) }
	bootID, _ := readBootID(); if record.BootID == bootID && pidAlive(record.PID) { return fmt.Errorf("recorded runtime pid %d is still active", record.PID) }
	var errs []error
	if err := cleanupStaleAttachments(record.Attachments); err != nil { errs = append(errs, err) }
	if err := restoreRecordedSysctls(record.Sysctls); err != nil { errs = append(errs, err) }
	if err := cleanupRecordedNetNS(record); err != nil { errs = append(errs, err) }
	if len(errs) != 0 { return errors.Join(errs...) }
	return os.Remove(ownerRecordPath())
}

func cleanupRecordedNetNS(record ownershipRecord) error {
	var errs []error
	for _, name := range []string{record.PeerLink, record.HostLink} {
		if name == "" { continue }
		link, err := netlink.LinkByName(name)
		if err != nil { if !isMissingNetlinkError(err) { errs = append(errs, err) }; continue }
		if link.Attrs() == nil || link.Attrs().Alias != record.Token { errs = append(errs, fmt.Errorf("refuse to delete link %s without matching ownership token", name)); continue }
		if err := netlink.LinkDel(link); err != nil && !isMissingNetlinkError(err) { errs = append(errs, err) }
	}
	if record.Namespace != "" { if err := netns.DeleteNamed(record.Namespace); err != nil && !errors.Is(err, os.ErrNotExist) { errs = append(errs, err) } }
	return errors.Join(errs...)
}

func restoreRecordedSysctls(mutations []sysctlMutation) error {
	var errs []error
	for index := len(mutations)-1; index >= 0; index-- { mutation := mutations[index]; raw, err := os.ReadFile(mutation.Path); if err != nil { if !errors.Is(err, os.ErrNotExist) { errs = append(errs, err) }; continue }; if strings.TrimSpace(string(raw)) != mutation.Applied { continue }; if err := os.WriteFile(mutation.Path, []byte(mutation.Original), 0o644); err != nil && !errors.Is(err, os.ErrNotExist) { errs = append(errs, err) } }
	return errors.Join(errs...)
}

func existingCaptureResourcesWithoutRecord() []string { resources := existingCaptureResources(); result := resources[:0]; for _, resource := range resources { if resource != ownerRecordPath() { result = append(result, resource) } }; return result }
func randomToken() (string, error) { var value [16]byte; if _, err := rand.Read(value[:]); err != nil { return "", fmt.Errorf("generate ownership token: %w", err) }; return "dae-ebpfinbound:"+hex.EncodeToString(value[:]), nil }
func readBootID() (string, error) { raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id"); if err != nil { return "", fmt.Errorf("read boot ID: %w", err) }; return strings.TrimSpace(string(raw)), nil }
func pidAlive(pid int) bool { if pid <= 0 { return false }; err := unix.Kill(pid, 0); return err == nil || errors.Is(err, unix.EPERM) }
