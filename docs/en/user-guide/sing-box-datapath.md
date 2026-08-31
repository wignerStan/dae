# Use dae as the sing-box Linux datapath

dae can run in external policy mode, where it supplies only the Linux TC and
cgroup eBPF datapath while sing-box owns userspace routing, DNS, FakeIP,
sniffing, and all outbounds.

The integration transfers dae's transparent TCP and UDP listener file
descriptors to the sing-box `dae` inbound over a versioned Unix
`SOCK_SEQPACKET` control channel. Application payload does not cross the
control channel.

```text
TC/cgroup eBPF
    -> dae transparent listeners
    -> descriptor handoff
    -> sing-box dae inbound
    -> sing-box sniff / DNS / routing / outbound
```

## Requirements

- Linux; Android is not supported.
- dae and sing-box must run in the same network namespace.
- The sing-box build must include the `dae` inbound.
- The sing-box `output_mark` must equal dae's effective `so_mark_from_dae`.
- Do not enable another sing-box auto-redirect/TUN datapath in the same
  instance. sing-box permits one auto-redirect output mark authority.

## sing-box configuration

Start the sing-box control socket before dae:

```json
{
  "inbounds": [
    {
      "type": "dae",
      "tag": "dae-in",
      "socket_path": "/run/dae/sing-box.sock",
      "socket_mode": 384,
      "producer_uid": 0,
      "output_mark": "0x100"
    }
  ]
}
```

`384` is decimal `0600`. Set `producer_uid` to the effective UID of the dae
process. The default is the effective UID of sing-box.

Configure normal sing-box route actions for sniffing and DNS hijacking. dae
does not run its own DNS listener or userspace route matcher in external
policy mode.

## dae configuration

Keep the normal dae interface and kernel settings. Set a fixed output mark so
both processes agree:

```shell
# excerpt from dae.conf
global {
  wan_interface: auto
  so_mark_from_dae: 0x100
}

routing {
  fallback: direct
}
```

The dae routing section is still parsed for configuration compatibility, but
its per-flow verdicts are not authoritative in external policy mode. Captured
TCP and UDP flows are forced to the transparent listeners and routed by
sing-box.

Set the control socket and expected sing-box UID before starting dae:

```shell
export DAE_EXTERNAL_POLICY_SOCKET=/run/dae/sing-box.sock
export DAE_EXTERNAL_POLICY_UID=0
exec dae run --config /etc/dae/config.dae
```

If `DAE_EXTERNAL_POLICY_UID` is omitted, dae requires the peer to have the same
effective UID as dae. Both peers also authenticate each other with
`SO_PEERCRED`.

## Startup and failure behavior

Start sing-box first. dae retries the control socket for up to 30 seconds.
After sing-box authenticates the dae process and adopts all three listeners,
it acknowledges the generation and dae reports ready.

The mode is fail-closed:

- a listener handoff failure prevents dae from becoming ready;
- a lost control channel retires that dae generation;
- dae never falls back to its own userspace router;
- sing-box outbound and DNS sockets use the shared output mark and are not
  captured again.

During a dae hot reload, the new control-plane generation transfers a new set
of listener descriptors. sing-box replaces only the listeners; established
TCP routes and UDP NAT sessions remain owned by sing-box.

Restarting sing-box is different from a dae reload: the old control channel is
retired and dae deliberately does not reconnect a replacement producer on its
own. Start sing-box first, then reload (or restart) dae so a fresh listener
generation can be handed over. This fail-closed behavior prevents traffic from
silently returning to dae's legacy userspace router.

For a staged recovery reload with no dae-owned subscriptions, dae skips its
public HTTP network-readiness probe. The retired external session is
intentionally unable to carry that probe, so waiting for it would deadlock the
handoff until the reload timeout. Configurations that still use dae
subscriptions retain the readiness probe; set `disable_waiting_network` only
when their bootstrap path is independently guaranteed.

## Contract tests

Run the Linux contract target on an isolated, privileged test VM:

```shell
make sing-box-datapath-test
```

The target runs the Unix `SOCK_SEQPACKET` envelope/descriptor tests, external
policy session tests, and the generated eBPF probes. It requires `CAP_BPF`,
`CAP_NET_ADMIN`, and a matching kernel BTF; it must not be run against a
production datapath. The `dae_stub_ebpf` tag is reserved for compile-only CI
coverage and does not replace this VM test.

## Metadata

For each new TCP connection or UDP association, sing-box requests metadata by
original source/destination tuple. dae returns available eBPF metadata:

- PID, process name, executable path, and UID;
- source MAC address;
- DSCP.

The control protocol is independent of dae's internal BPF map layouts, so map
changes do not require matching sing-box changes.
