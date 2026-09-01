#!/usr/bin/env python3
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

module = Path(__file__).resolve().parents[1]
repository = module.parent
source = repository / "control" / "kern"
if not (source / "tproxy.c").is_file():
    raise SystemExit(f"dae BPF source not found at {source / 'tproxy.c'}")
if not (source / "headers").is_dir():
    raise SystemExit("dae BPF headers submodule is missing; run git submodule update --init --recursive")

with tempfile.TemporaryDirectory(prefix="dae-ebpfinbound-generate-") as temporary:
    kern = Path(temporary) / "kern"
    shutil.copytree(source, kern, symlinks=True)
    tproxy = kern / "tproxy.c"
    text = tproxy.read_text()
    signature = """static __noinline __s64 route(const __u32 *flag, const void *l4hdr,
\t\t\t      const __be32 *saddr, const __be32 *daddr,
\t\t\t      const __be32 *mac)
{"""
    replacement = signature + """
#ifdef DAE_CAPTURE_ONLY
\t/* Routing and DNS policy are owned by the embedding userspace engine. */
\treturn (__s64)OUTBOUND_CONTROL_PLANE_ROUTING;
#endif"""
    if signature not in text:
        raise SystemExit("route function marker not found in dae BPF source")
    tproxy.write_text(text.replace(signature, replacement, 1))

    command = [
        "go", "run", "-mod=mod", "github.com/cilium/ebpf/cmd/bpf2go@v0.20.0",
        "-cc", os.environ.get("BPF_CLANG", "clang"),
        "-no-strip",
        "-cflags", "-DMAX_MATCH_SET_LEN=1024 -DDAE_CAPTURE_ONLY=1 -O2 -Wall -Werror",
        "-target", "bpfel,bpfeb",
        "-type", "dae_param",
        "-type", "tuples_key",
        "-type", "conn_state",
        "-type", "routing_handoff_entry",
        "bpf", str(tproxy), "--", f"-I{kern / 'headers'}",
    ]
    environment = os.environ.copy()
    environment["GOPACKAGE"] = "ebpfinbound"
    subprocess.run(command, cwd=module, env=environment, check=True)

for name in ("bpf_bpfel.go", "bpf_bpfeb.go"):
    path = module / name
    lines = path.read_text().splitlines()
    for index, line in enumerate(lines):
        if line.startswith("//go:build "):
            expression = line.removeprefix("//go:build ")
            lines[index] = f"//go:build linux && !dae_stub_ebpf && ({expression})"
            break
    else:
        raise SystemExit(f"generated build constraint missing from {name}")
    path.write_text("\n".join(lines) + "\n")
