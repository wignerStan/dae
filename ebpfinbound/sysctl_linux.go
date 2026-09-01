//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only

package ebpfinbound

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type sysctlMutation struct {
	Path string `json:"path"`
	Original string `json:"original"`
	Applied string `json:"applied"`
}

type sysctlManager struct {
	mu sync.Mutex
	closed bool
	order []string
	mutations map[string]sysctlMutation
	onChange func([]sysctlMutation) error
	readFile func(string) ([]byte, error)
	writeFile func(string, []byte, os.FileMode) error
}

func newSysctlManager(onChange func([]sysctlMutation) error) *sysctlManager {
	return &sysctlManager{mutations: make(map[string]sysctlMutation), onChange: onChange, readFile: os.ReadFile, writeFile: os.WriteFile}
}

func (m *sysctlManager) Set(path, value string) error {
	if m == nil { return errors.New("nil sysctl manager") }
	clean := filepath.Clean(path)
	if !strings.HasPrefix(clean, "/proc/sys/net/") { return fmt.Errorf("refuse non-network sysctl path %q", path) }
	value = strings.TrimSpace(value)
	m.mu.Lock()
	if m.closed { m.mu.Unlock(); return errors.New("sysctl manager is closed") }
	raw, err := m.readFile(clean)
	if err != nil { m.mu.Unlock(); return fmt.Errorf("read sysctl %s: %w", clean, err) }
	current := strings.TrimSpace(string(raw))
	mutation, exists := m.mutations[clean]
	if !exists { mutation = sysctlMutation{Path: clean, Original: current}; m.order = append(m.order, clean) }
	if current != value {
		if err := m.writeFile(clean, []byte(value), 0o644); err != nil { m.mu.Unlock(); return fmt.Errorf("write sysctl %s=%s: %w", clean, value, err) }
	}
	mutation.Applied = value
	m.mutations[clean] = mutation
	snapshot := m.snapshotLocked()
	callback := m.onChange
	m.mu.Unlock()
	if callback != nil {
		if err := callback(snapshot); err != nil { return fmt.Errorf("record sysctl mutation: %w", err) }
	}
	return nil
}

func (m *sysctlManager) Close() error {
	if m == nil { return nil }
	m.mu.Lock()
	if m.closed { m.mu.Unlock(); return nil }
	m.closed = true
	var errs []error
	for index := len(m.order)-1; index >= 0; index-- {
		mutation := m.mutations[m.order[index]]
		raw, err := m.readFile(mutation.Path)
		if err != nil { if !errors.Is(err, os.ErrNotExist) { errs = append(errs, fmt.Errorf("read sysctl %s before restore: %w", mutation.Path, err)) }; continue }
		if strings.TrimSpace(string(raw)) != mutation.Applied { continue }
		if err := m.writeFile(mutation.Path, []byte(mutation.Original), 0o644); err != nil && !errors.Is(err, os.ErrNotExist) { errs = append(errs, fmt.Errorf("restore sysctl %s: %w", mutation.Path, err)) }
	}
	m.order = nil
	m.mutations = make(map[string]sysctlMutation)
	callback := m.onChange
	m.mu.Unlock()
	if callback != nil { if err := callback(nil); err != nil { errs = append(errs, fmt.Errorf("clear sysctl mutation record: %w", err)) } }
	return errors.Join(errs...)
}

func (m *sysctlManager) snapshotLocked() []sysctlMutation {
	result := make([]sysctlMutation, 0, len(m.order))
	for _, path := range m.order { result = append(result, m.mutations[path]) }
	return result
}

func interfaceSysctlPath(family, interfaceName, key string) (string, error) {
	if interfaceName == "" || strings.Contains(interfaceName, "/") || interfaceName == "." || interfaceName == ".." { return "", fmt.Errorf("invalid interface name %q", interfaceName) }
	if family != "ipv4" && family != "ipv6" { return "", fmt.Errorf("invalid IP family %q", family) }
	return filepath.Join("/proc/sys/net", family, "conf", interfaceName, key), nil
}
