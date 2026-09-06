#!/usr/bin/env bash
set -euo pipefail

BASE=5db27a0028d36e7847bd3796497df952337a20e2
FINAL=refactor/ebpfinbound-schema-v9
WORK=/tmp/ebpfinbound

rm -rf "$WORK" /tmp/provider-tree /tmp/control /tmp/provider-hardening.patch
cat .github/review-fix/provider/part-* | base64 -d > /tmp/provider-source.tar.gz
sha256sum /tmp/provider-source.tar.gz
tar -tzf /tmp/provider-source.tar.gz >/dev/null
mkdir -p /tmp/provider-tree
tar -xzf /tmp/provider-source.tar.gz -C /tmp/provider-tree
mv /tmp/provider-tree/ebpfinbound "$WORK"
mkdir -p "$WORK/bpf"
cp control/kern/tproxy.c "$WORK/bpf/capture.c"
cp control/kern/ebpf_sync_defs.h "$WORK/bpf/ebpf_sync_defs.h"
cp -a control/kern/headers "$WORK/bpf/headers"
cp LICENSE "$WORK/LICENSE"

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

cd "$WORK"
go mod tidy
sed -i 's/ -type dae_param//' generate.go
sed -i '/^[[:space:]]*"net"$/d' preflight_linux.go
go generate ./...
go mod tidy
find . -name '*.go' -print0 | xargs -0 gofmt -w
rm -rf bpf/headers dae-ebpf-tool

base64 -d "$GITHUB_WORKSPACE/.github/review-fix/provider-hardening-v3.patch.gz.b64" | gzip -d > /tmp/provider-hardening.patch
patch -p2 --forward --batch < /tmp/provider-hardening.patch
rm -rf bpf/headers dae-ebpf-tool
rm -f /tmp/control
ln -s "$GITHUB_WORKSPACE/control" /tmp/control

go generate ./...
go mod tidy
find . -name '*.go' -print0 | xargs -0 gofmt -w
go test -race ./...
go vet ./...
go test -tags dae_stub_ebpf ./...
stub_files=$(go list -tags dae_stub_ebpf -f '{{join .GoFiles " "}}' .)
if grep -Eq 'bpf_bpf(el|eb)\.go' <<<"$stub_files"; then
  echo 'dae_stub_ebpf unexpectedly includes generated BPF objects' >&2
  exit 1
fi
go build ./cmd/dae-ebpf-tool

deps=$(go list -deps ./...)
if grep -E 'github.com/(daeuniverse|wignerStan)/dae/(control|config|common|component|cmd|pkg)|github.com/daeuniverse/outbound|github.com/(olicesx|quic-go)/quic-go|github.com/quic-go/qpack|github.com/sirupsen/logrus' <<<"$deps"; then
  echo 'forbidden daemon, policy, outbound, QUIC, qpack, or logging dependency leaked into provider' >&2
  exit 1
fi
! grep -R -E 'OpenGeneration|CloneGeneration|CommitGeneration' --include='*.go' .
for asset in go.sum bpf_bpfel.go bpf_bpfeb.go bpf_bpfel.o bpf_bpfeb.o; do
  test -s "$asset"
done

sudo mkdir -p /run/netns
sudo --preserve-env=PATH env HOME="$HOME" go test -tags=integration -run '^TestPrivileged' -count=1 -v .
! ip link show daecap0
! ip link show daecap1
test ! -e /run/netns/dae-ebpfinbound

cd "$GITHUB_WORKSPACE"
git checkout -B publish "$BASE"
rm -rf ebpfinbound
cp -a "$WORK" ebpfinbound
rm -f ebpfinbound/dae-ebpf-tool
mkdir -p .github/workflows
cat > .github/workflows/ebpfinbound.yml <<'YAML'
name: eBPF inbound

on:
  push:
    paths:
      - 'ebpfinbound/**'
      - '.github/workflows/ebpfinbound.yml'
  pull_request:
    paths:
      - 'ebpfinbound/**'
      - '.github/workflows/ebpfinbound.yml'

permissions:
  contents: read

concurrency:
  group: ebpfinbound-${{ github.ref }}
  cancel-in-progress: true

jobs:
  module:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v6
        with:
          submodules: recursive
      - uses: actions/setup-go@v6
        with:
          go-version: '1.26.x'
          cache-dependency-path: ebpfinbound/go.sum
      - name: Install eBPF generation tools
        run: |
          sudo apt-get update
          sudo apt-get install -y clang llvm libbpf-dev iproute2
      - name: Unit, race, vet, and stub boundary
        working-directory: ebpfinbound
        run: |
          set -euxo pipefail
          go test -race ./...
          go vet ./...
          go test -tags dae_stub_ebpf ./...
          stub_files=$(go list -tags dae_stub_ebpf -f '{{join .GoFiles " "}}' .)
          if grep -Eq 'bpf_bpf(el|eb)\.go' <<<"$stub_files"; then
            echo 'dae_stub_ebpf unexpectedly includes generated BPF objects' >&2
            exit 1
          fi
      - name: Dependency and API boundary
        working-directory: ebpfinbound
        run: |
          set -euxo pipefail
          deps=$(go list -deps ./...)
          if grep -E 'github.com/(daeuniverse|wignerStan)/dae/(cmd|common|component|config|control|pkg)|github.com/daeuniverse/outbound|github.com/(olicesx|quic-go)/quic-go|github.com/quic-go/qpack' <<<"$deps"; then
            echo 'daemon, policy, outbound, QUIC, or qpack dependency leaked into ebpfinbound' >&2
            exit 1
          fi
          ! grep -R -E 'OpenGeneration|CloneGeneration|CommitGeneration' --include='*.go' .
          go build ./cmd/dae-ebpf-tool
      - name: Generated BPF freshness
        working-directory: ebpfinbound
        run: |
          set -euxo pipefail
          sha256sum bpf_bpfel.go bpf_bpfel.o bpf_bpfeb.go bpf_bpfeb.o > /tmp/ebpfinbound-bpf.sha256
          go generate ./...
          sha256sum -c /tmp/ebpfinbound-bpf.sha256
          git diff --exit-code -- bpf_bpfel.go bpf_bpfel.o bpf_bpfeb.go bpf_bpfeb.o
      - name: Upload regenerated BPF assets
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: regenerated-bpf-assets
          path: |
            ebpfinbound/bpf_bpfel.go
            ebpfinbound/bpf_bpfel.o
            ebpfinbound/bpf_bpfeb.go
            ebpfinbound/bpf_bpfeb.o
          retention-days: 2

  privileged:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v6
        with:
          submodules: recursive
      - uses: actions/setup-go@v6
        with:
          go-version: '1.26.x'
          cache-dependency-path: ebpfinbound/go.sum
      - name: Install runtime tools
        run: |
          sudo apt-get update
          sudo apt-get install -y iproute2
          sudo mkdir -p /run/netns
      - name: Privileged lifecycle and traffic
        working-directory: ebpfinbound
        run: |
          set -euxo pipefail
          sudo --preserve-env=PATH env HOME="$HOME" go test -tags=integration -run '^TestPrivileged' -count=1 -v .
          ! ip link show daecap0
          test ! -e /run/netns/dae-ebpfinbound
YAML

git add -f ebpfinbound .github/workflows/ebpfinbound.yml
git diff --cached --check
git config user.name Jacob
git config user.email 240170694+wignerStan@users.noreply.github.com
git commit -m 'refactor(ebpfinbound): add standalone capture owner'
git push --force origin HEAD:refs/heads/$FINAL
if gh pr view "$FINAL" --repo "$GITHUB_REPOSITORY" >/dev/null 2>&1; then
  gh pr edit "$FINAL" --repo "$GITHUB_REPOSITORY" --base main --title 'refactor(ebpfinbound): add standalone capture owner'
else
  gh pr create --repo "$GITHUB_REPOSITORY" --draft --base main --head "$FINAL" --title 'refactor(ebpfinbound): add standalone capture owner' --body 'Adds a standalone one-shot transparent eBPF capture module classified under FCIS Schema v9 as one axisless effect_tool(application_support) operation. The provider owns BPF/TC/cgroup/listener/netns/sysctl lifecycle and exposes factual flow metadata only; DNS, sniffing, routing, and outbounds stay with the embedding engine. This change removes listener generations, gates operations against Close, makes namespace switching thread-safe, preserves failed sysctl recovery evidence, fails startup on incomplete IPv6 readiness, commits generated assets, and validates real TCP/UDP interception plus foreign-resource preservation.'
fi
