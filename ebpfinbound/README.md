# dae eBPF inbound runtime

`github.com/daeuniverse/dae/ebpfinbound` is a Linux-only, policy-neutral transparent traffic capture module distilled from dae.

It owns:

- transparent TCP4, TCP6 and UDP listeners;
- capture-only TC and optional cgroup eBPF programs;
- original source/destination and process/MAC/DSCP metadata;
- one private capture network namespace and veth pair;
- explicit host-resource ownership and deterministic teardown;
- reversible sysctl leases when automatic kernel configuration is enabled.

It deliberately does **not** own DNS, sniffing, routing rules, FakeIP, proxy protocols, outbounds or dialing policy. Those belong to the embedding traffic engine.

## One-shot lifecycle

```go
runtime, err := ebpfinbound.New(ctx, ebpfinbound.Options{
    Capture: ebpfinbound.CaptureConfig{
        WANInterfaces:          []string{"auto"},
        OutputMark:             0x100,
        AutoConfigureKernel:    true,
        RequireProcessMetadata: true,
    },
})
if err != nil {
    return err
}
defer runtime.Close()

listeners := runtime.Listeners()
```

The listener set is stable for the runtime lifetime. It must not be closed, duplicated or republished by the consumer. Configuration reload swaps handlers above this API.

`New` returns only after listener publication and all required traffic attachments are ready. If startup fails, the incomplete BPF collection and every resource created by the call are destroyed.

## Operations

```bash
dae-ebpf-tool doctor --wan auto
dae-ebpf-tool cleanup-stale
```

`doctor` is non-mutating. `cleanup-stale` refuses to run while the ownership lock is held and removes only resources whose ownership metadata matches the recorded runtime.

## Build

Generated little- and big-endian BPF bindings and object files are committed, so downstream users do not need clang. Maintainers regenerate them from dae's current BPF source:

```bash
git submodule update --init --recursive
cd ebpfinbound
go generate ./...
```
