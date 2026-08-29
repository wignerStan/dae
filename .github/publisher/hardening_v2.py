from __future__ import annotations

from pathlib import Path


def extract_function(text: str, signature: str) -> tuple[int, int, str]:
    start = text.index(signature)
    brace = text.index("{", start)
    depth = 0
    i = brace
    quote = ""
    escaped = False
    while i < len(text):
        ch = text[i]
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = ""
        else:
            if ch in ('"', "'", "`"):
                quote = ch
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return start, i + 1, text[start : i + 1]
        i += 1
    raise ValueError(signature)


root = Path(".")

# Gate capture startup on the actual TC attachment state.  The legacy interface
# manager may still schedule callbacks internally, but the reusable runtime is
# not returned to a consumer until every currently resolved interface has both
# ingress and egress BPF filters installed.
(root / "control/ebpf_capture_ready_linux.go").write_text(
    r'''//go:build linux

package control

import (
    "context"
    "errors"
    "fmt"
    "slices"
    "strings"
    "time"

    "github.com/daeuniverse/dae/pkg/ebpfinbound"
    "github.com/vishvananda/netlink"
)

const captureReadyTimeout = 15 * time.Second

var captureInterfaceReady = interfaceHasCaptureFilters

func waitCaptureReady(parent context.Context, preflight ebpfinbound.InterfacePreflight) error {
    ctx, cancel := context.WithTimeout(parent, captureReadyTimeout)
    defer cancel()

    waiting := make(map[string]struct{}, len(preflight.Waiting))
    for _, pattern := range preflight.Waiting {
        waiting[pattern] = struct{}{}
    }
    required := make([]string, 0, len(preflight.LAN)+len(preflight.WAN))
    for _, name := range append(append([]string(nil), preflight.LAN...), preflight.WAN...) {
        if _, lazy := waiting[name]; !lazy {
            required = append(required, name)
        }
    }
    slices.Sort(required)
    required = slices.Compact(required)

    ticker := time.NewTicker(50 * time.Millisecond)
    defer ticker.Stop()
    var last []string
    for {
        last = last[:0]
        for _, name := range required {
            ready, err := captureInterfaceReady(name)
            if err != nil {
                last = append(last, name+": "+err.Error())
                continue
            }
            if !ready {
                last = append(last, name+": TC BPF ingress/egress filters are not ready")
            }
        }
        if len(last) == 0 {
            return nil
        }
        select {
        case <-ctx.Done():
            return fmt.Errorf("capture attachments did not become ready: %s: %w", strings.Join(last, "; "), ctx.Err())
        case <-ticker.C:
        }
    }
}

func interfaceHasCaptureFilters(name string) (bool, error) {
    link, err := netlink.LinkByName(name)
    if err != nil {
        return false, err
    }
    ingress, err := netlink.FilterList(link, netlink.HANDLE_MIN_INGRESS)
    if err != nil {
        return false, fmt.Errorf("list ingress filters: %w", err)
    }
    egress, err := netlink.FilterList(link, netlink.HANDLE_MIN_EGRESS)
    if err != nil {
        return false, fmt.Errorf("list egress filters: %w", err)
    }
    return containsBPF(ingress) && containsBPF(egress), nil
}

func containsBPF(filters []netlink.Filter) bool {
    for _, filter := range filters {
        if filter == nil {
            continue
        }
        switch filter.(type) {
        case *netlink.BpfFilter:
            return true
        }
    }
    return false
}

var _ = errors.Is
'''
)

(root / "control/ebpf_capture_ready_linux_test.go").write_text(
    r'''//go:build linux

package control

import (
    "context"
    "errors"
    "testing"

    "github.com/daeuniverse/dae/pkg/ebpfinbound"
)

func TestWaitCaptureReady(t *testing.T) {
    old := captureInterfaceReady
    t.Cleanup(func() { captureInterfaceReady = old })
    calls := 0
    captureInterfaceReady = func(name string) (bool, error) {
        calls++
        if name == "bad0" {
            return false, errors.New("not attached")
        }
        return true, nil
    }
    if err := waitCaptureReady(context.Background(), ebpfinbound.InterfacePreflight{LAN: []string{"lan0"}, WAN: []string{"wan0"}}); err != nil {
        t.Fatal(err)
    }
    if calls != 2 {
        t.Fatalf("calls = %d", calls)
    }
}

func TestWaitCaptureReadyIgnoresExplicitLazyPattern(t *testing.T) {
    old := captureInterfaceReady
    t.Cleanup(func() { captureInterfaceReady = old })
    captureInterfaceReady = func(name string) (bool, error) {
        t.Fatalf("unexpected readiness lookup for %q", name)
        return false, nil
    }
    if err := waitCaptureReady(context.Background(), ebpfinbound.InterfacePreflight{WAN: []string{"wwan*"}, Waiting: []string{"wwan*"}}); err != nil {
        t.Fatal(err)
    }
}
'''
)

runtime_path = root / "control/ebpf_capture_runtime.go"
runtime = runtime_path.read_text()
if "restoreSysctl bool" not in runtime:
    runtime = runtime.replace("ownership *captureOwnership\n", "ownership *captureOwnership\n\trestoreSysctl bool\n")

return_line = "return &captureRuntime{inner: plane.EBPFInbound(), netns: netns, ownership: ownership}, nil"
if return_line in runtime:
    runtime = runtime.replace(
        return_line,
        '''if err := waitCaptureReady(ctx, preflight); err != nil {
        _ = plane.Close()
        _ = netns.Close()
        ResetDaeNetns(netns)
        _ = ownership.Close()
        if capture.AutoConfigureKernel {
            _ = CloseSysctlManager()
        }
        return nil, err
    }
    return &captureRuntime{
        inner: plane.EBPFInbound(),
        netns: netns,
        ownership: ownership,
        restoreSysctl: capture.AutoConfigureKernel,
    }, nil''',
    )
else:
    raise SystemExit("capture runtime constructor return not found")

close_anchor = "if r.ownership != nil { if err := r.ownership.Close(); err != nil { errs = append(errs, err) } }"
if close_anchor in runtime and "if r.restoreSysctl" not in runtime:
    runtime = runtime.replace(
        close_anchor,
        close_anchor + '''
            if r.restoreSysctl {
                if err := CloseSysctlManager(); err != nil { errs = append(errs, err) }
            }''',
    )
runtime_path.write_text(runtime)

# Turn the process-global sysctl enforcer into an owned, reversible lease.  The
# close path restores only values that still equal the value set by dae, so a
# later administrator change is not overwritten.
sysctl_path = root / "control/sysctl.go"
sysctl = sysctl_path.read_text()
if '"errors"' not in sysctl.split("import (", 1)[1].split(")", 1)[0]:
    sysctl = sysctl.replace("import (\n", 'import (\n\t"errors"\n', 1)
if "originals map[string]string" not in sysctl:
    sysctl = sysctl.replace(
        "expectations map[string]string\n",
        "expectations map[string]string\n\toriginals    map[string]string\n\tclosed       bool\n",
    )
    sysctl = sysctl.replace(
        "expectations: map[string]string{},\n",
        "expectations: map[string]string{},\n\t\toriginals:    map[string]string{},\n",
    )

start, end, _ = extract_function(sysctl, "func (s *SysctlManager) set(")
replacement = r'''func (s *SysctlManager) set(path string, value string, watch bool) error {
    raw, err := os.ReadFile(path)
    if err != nil {
        return err
    }
    original := strings.TrimSpace(string(raw))

    s.mux.Lock()
    if s.closed {
        s.mux.Unlock()
        return errors.New("sysctl manager is closed")
    }
    if _, exists := s.originals[path]; !exists {
        s.originals[path] = original
    }
    if watch {
        s.expectations[path] = value
    }
    s.mux.Unlock()

    if watch {
        if err = s.watcher.Add(path); err != nil {
            return err
        }
    }
    return os.WriteFile(path, []byte(value), 0o644)
}'''
sysctl = sysctl[:start] + replacement + sysctl[end:]

if "func (s *SysctlManager) Close() error" not in sysctl:
    sysctl += r'''

func (s *SysctlManager) Close() error {
    if s == nil {
        return nil
    }
    s.mux.Lock()
    if s.closed {
        s.mux.Unlock()
        return nil
    }
    s.closed = true
    originals := make(map[string]string, len(s.originals))
    expectations := make(map[string]string, len(s.expectations))
    for key, value := range s.originals { originals[key] = value }
    for key, value := range s.expectations { expectations[key] = value }
    s.originals = nil
    s.expectations = nil
    s.mux.Unlock()

    var errs []error
    if err := s.watcher.Close(); err != nil { errs = append(errs, err) }
    for path, original := range originals {
        raw, err := os.ReadFile(path)
        if err != nil { errs = append(errs, err); continue }
        current := strings.TrimSpace(string(raw))
        expected, watched := expectations[path]
        if watched && current != expected {
            continue
        }
        if err = os.WriteFile(path, []byte(original), 0o644); err != nil {
            errs = append(errs, err)
        }
    }
    return errors.Join(errs...)
}

func CloseSysctlManager() error {
    sysctlMu.Lock()
    manager := sysctl
    sysctl = nil
    sysctlMu.Unlock()
    if manager == nil { return nil }
    return manager.Close()
}
'''
sysctl_path.write_text(sysctl)

(root / "control/sysctl_restore_test.go").write_text(
    r'''package control

import (
    "os"
    "path/filepath"
    "testing"
)

func TestSysctlManagerRestoresOwnedValue(t *testing.T) {
    path := filepath.Join(t.TempDir(), "sysctl")
    if err := os.WriteFile(path, []byte("0"), 0o644); err != nil { t.Fatal(err) }
    manager, err := NewSysctlManager(testLogger())
    if err != nil { t.Fatal(err) }
    if err = manager.set(path, "1", true); err != nil { t.Fatal(err) }
    if err = manager.Close(); err != nil { t.Fatal(err) }
    content, err := os.ReadFile(path)
    if err != nil { t.Fatal(err) }
    if string(content) != "0" { t.Fatalf("restored content = %q", content) }
}

func TestSysctlManagerDoesNotOverwriteExternalChange(t *testing.T) {
    path := filepath.Join(t.TempDir(), "sysctl")
    if err := os.WriteFile(path, []byte("0"), 0o644); err != nil { t.Fatal(err) }
    manager, err := NewSysctlManager(testLogger())
    if err != nil { t.Fatal(err) }
    if err = manager.set(path, "1", true); err != nil { t.Fatal(err) }
    if err = os.WriteFile(path, []byte("2"), 0o644); err != nil { t.Fatal(err) }
    if err = manager.Close(); err != nil { t.Fatal(err) }
    content, err := os.ReadFile(path)
    if err != nil { t.Fatal(err) }
    if string(content) != "2" { t.Fatalf("external content = %q", content) }
}
'''
)

# testLogger may not exist in this package; use a small local helper only when
# the repository does not already provide it.
helpers = list((root / "control").glob("*_test.go"))
if not any("func testLogger()" in p.read_text(errors="ignore") for p in helpers):
    test_file = root / "control/sysctl_restore_test.go"
    value = test_file.read_text()
    value = value.replace('"testing"\n)', '"testing"\n\n    "github.com/sirupsen/logrus"\n)')
    value += '\nfunc testLogger() *logrus.Logger { logger := logrus.New(); logger.SetOutput(os.Stderr); return logger }\n'
    test_file.write_text(value)

# Document the hard deployment contract without overstating standalone-module
# extraction, which remains a separate follow-up.
doc = root / "docs/ebpfinbound-hardening.md"
text = doc.read_text() if doc.exists() else "# Embedded eBPF inbound hardening\n"
text += "\nStartup now waits until every currently resolved capture interface has both ingress and egress TC BPF filters. When automatic kernel configuration is enabled, sysctl values are leased and restored on final runtime close unless an administrator changed them afterward.\n"
doc.write_text(text)
