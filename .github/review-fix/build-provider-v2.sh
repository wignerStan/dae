#!/usr/bin/env bash
set -euo pipefail

BASE=5db27a0028d36e7847bd3796497df952337a20e2
FINAL=fix/ebpfinbound-review-v2

rm -rf /tmp/ebpfinbound /tmp/provider-tree
cat .github/review-fix/provider/part-* | base64 -d > /tmp/provider-source.tar.gz
sha256sum /tmp/provider-source.tar.gz
tar -tzf /tmp/provider-source.tar.gz >/dev/null
mkdir -p /tmp/provider-tree
tar -xzf /tmp/provider-source.tar.gz -C /tmp/provider-tree
mv /tmp/provider-tree/ebpfinbound /tmp/ebpfinbound
mkdir -p /tmp/ebpfinbound/bpf
cp control/kern/tproxy.c /tmp/ebpfinbound/bpf/capture.c
cp -a control/kern/headers /tmp/ebpfinbound/bpf/headers
cp LICENSE /tmp/ebpfinbound/LICENSE

python3 - <<'PY'
from pathlib import Path

path = Path('/tmp/ebpfinbound/bpf/capture.c')
text = path.read_text()
text = '''/*
 * Capture-only derivative of dae's transparent proxy datapath.
 *
 * DAE_CAPTURE_ONLY removes userspace routing policy from the kernel decision
 * path. DNS, sniffing, routing and outbounds are owned by the embedding engine.
 */
''' + text

def function_end(source: str, start: int) -> int:
    brace = source.index('{', start)
    depth = 0
    quote = None
    escaped = False
    line_comment = False
    block_comment = False
    i = brace
    while i < len(source):
        ch = source[i]
        nxt = source[i + 1] if i + 1 < len(source) else ''
        if line_comment:
            if ch == '\n':
                line_comment = False
        elif block_comment:
            if ch == '*' and nxt == '/':
                block_comment = False
                i += 1
        elif quote:
            if escaped:
                escaped = False
            elif ch == '\\':
                escaped = True
            elif ch == quote:
                quote = None
        elif ch == '/' and nxt == '/':
            line_comment = True
            i += 1
        elif ch == '/' and nxt == '*':
            block_comment = True
            i += 1
        elif ch in ('"', "'"):
            quote = ch
        elif ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise RuntimeError('function end not found')

route_start = text.index('static __noinline __s64 route(')
route_end = function_end(text, route_start)
route_original = text[route_start:route_end]
route_capture = '''static __always_inline __s64 route(const __u32 *flag, const void *l4hdr,
                                     const __be32 *saddr, const __be32 *daddr,
                                     const __be32 *mac)
{
    return (__s64)OUTBOUND_CONTROL_PLANE_ROUTING;
}'''
text = text[:route_start] + '#ifdef DAE_CAPTURE_ONLY\n' + route_capture + '\n#else\n' + route_original + '\n#endif /* DAE_CAPTURE_ONLY */' + text[route_end:]

wan_marker = 'static __noinline bool\nwan_outbound_is_alive(struct __sk_buff *skb, __u8 outbound, __u8 l4proto,'
wan_start = text.rindex(wan_marker)
wan_end = function_end(text, wan_start)
wan_original = text[wan_start:wan_end]
wan_capture = '''static __noinline bool
wan_outbound_is_alive(struct __sk_buff *skb, __u8 outbound, __u8 l4proto,
                      __be16 dport)
{
    return true;
}'''
text = text[:wan_start] + '#ifdef DAE_CAPTURE_ONLY\n' + wan_capture + '\n#else\n' + wan_original + '\n#endif /* DAE_CAPTURE_ONLY */' + text[wan_end:]
path.write_text(text)
PY

cd /tmp/ebpfinbound
go generate ./...
go mod tidy
find . -name '*.go' -print0 | xargs -0 gofmt -w
go test -race ./...
go vet ./...
go build ./cmd/dae-ebpf-tool

deps=$(go list -deps ./...)
if grep -E 'github.com/(daeuniverse|wignerStan)/dae/(control|config|common|component|cmd|pkg)|github.com/daeuniverse/outbound|github.com/olicesx/quic-go|github.com/quic-go/qpack|github.com/sirupsen/logrus' <<<"$deps"; then
  echo 'forbidden daemon, policy, outbound, QUIC, qpack, or logging dependency leaked into provider' >&2
  exit 1
fi
for asset in go.sum bpf_bpfel.go bpf_bpfeb.go bpf_bpfel.o bpf_bpfeb.o; do
  test -s "$asset"
done

sudo mkdir -p /sys/fs/bpf /run/netns
mountpoint -q /sys/fs/bpf || sudo mount -t bpf bpf /sys/fs/bpf
sudo --preserve-env=PATH env HOME="$HOME" go test -tags=integration -run 'TestPrivileged' -count=1 -v .
! ip link show daecap0
! ip link show daecap1
! ip netns list | grep -q '^dae-ebpfinbound'

cd "$GITHUB_WORKSPACE"
git checkout -B publish "$BASE"
rm -rf ebpfinbound
cp -a /tmp/ebpfinbound ebpfinbound
rm -f ebpfinbound/dae-ebpf-tool
mkdir -p .github/workflows
cat > .github/workflows/ebpfinbound.yml <<'YAML'
name: eBPF inbound provider

on:
  pull_request:
    paths:
      - 'ebpfinbound/**'
      - '.github/workflows/ebpfinbound.yml'
  push:
    branches: [main]
    paths:
      - 'ebpfinbound/**'
      - '.github/workflows/ebpfinbound.yml'

permissions:
  contents: read

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

jobs:
  validate:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v6
      - uses: actions/setup-go@v6
        with:
          go-version: 1.26.7
      - name: Test, race and vet
        working-directory: ebpfinbound
        run: |
          go test -race ./...
          go vet ./...
          go build ./cmd/dae-ebpf-tool
      - name: Verify standalone dependency boundary
        working-directory: ebpfinbound
        run: |
          deps=$(go list -deps ./...)
          ! grep -E 'github.com/(daeuniverse|wignerStan)/dae/(control|config|common|component|cmd|pkg)|github.com/daeuniverse/outbound|github.com/olicesx/quic-go|github.com/quic-go/qpack|github.com/sirupsen/logrus' <<<"$deps"
      - name: Verify committed BPF assets
        working-directory: ebpfinbound
        run: |
          test -s go.sum
          test -s bpf_bpfel.go
          test -s bpf_bpfeb.go
          test -s bpf_bpfel.o
          test -s bpf_bpfeb.o

  privileged:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v6
      - uses: actions/setup-go@v6
        with:
          go-version: 1.26.7
      - name: Install runtime tools
        run: sudo apt-get update && sudo apt-get install -y iproute2
      - name: Run privileged lifecycle tests
        working-directory: ebpfinbound
        run: |
          sudo mkdir -p /sys/fs/bpf /run/netns
          mountpoint -q /sys/fs/bpf || sudo mount -t bpf bpf /sys/fs/bpf
          sudo --preserve-env=PATH env HOME="$HOME" go test -tags=integration -run 'TestPrivileged' -count=1 -v .
          ! ip link show daecap0
          ! ip link show daecap1
          ! ip netns list | grep -q '^dae-ebpfinbound'
YAML

git add -f ebpfinbound .github/workflows/ebpfinbound.yml
git diff --cached --check
git config user.name Jacob
git config user.email 240170694+wignerStan@users.noreply.github.com
git commit -m 'refactor(ebpfinbound): harden one-shot capture runtime'
git push --force origin HEAD:refs/heads/$FINAL
if gh pr view "$FINAL" --repo "$GITHUB_REPOSITORY" >/dev/null 2>&1; then
  gh pr edit "$FINAL" --repo "$GITHUB_REPOSITORY" --base main --title 'refactor(ebpfinbound): harden one-shot capture runtime'
else
  gh pr create --repo "$GITHUB_REPOSITORY" --draft --base main --head "$FINAL" --title 'refactor(ebpfinbound): harden one-shot capture runtime' --body 'Replaces the unsafe cloned-listener generation API with a one-shot stable capture runtime. Adds operation-versus-close gating, ownership-safe netns/TC cleanup, conditional sysctl leases, process identity validation, capture-only BPF pruning, committed generated assets, and privileged lifecycle/traffic tests. This is the provider half of the linked sing-box hardening.'
fi
