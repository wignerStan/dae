# 将 dae 作为 sing-box 的 Linux 数据面

dae 可以运行在外部策略模式：dae 只负责 Linux TC/cgroup eBPF 数据面，
sing-box 负责用户态路由、DNS、FakeIP、流量嗅探和全部出站协议。

该集成通过带版本号的 Unix `SOCK_SEQPACKET` 控制通道，将 dae 创建的透明
TCP/UDP 监听套接字描述符交给 sing-box 的 `dae` 入站。应用数据不会经过控制
通道复制。

```text
TC/cgroup eBPF
    -> dae 透明监听套接字
    -> 描述符交接
    -> sing-box dae 入站
    -> sing-box 嗅探 / DNS / 路由 / 出站
```

## 要求

- 仅支持 Linux，不支持 Android。
- dae 和 sing-box 必须位于同一个网络命名空间。
- sing-box 必须包含 `dae` 入站。
- sing-box 的 `output_mark` 必须等于 dae 实际使用的 `so_mark_from_dae`。
- 同一 sing-box 实例中不要再启用其他 auto-redirect/TUN 数据面。

## sing-box 配置

先让 sing-box 创建控制套接字：

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

`384` 是 `0600` 的十进制表示。`producer_uid` 应设置为 dae 进程的有效
UID；默认值是 sing-box 的有效 UID。

嗅探和 DNS 劫持使用普通的 sing-box 路由动作配置。在外部策略模式下，dae
不会启动自己的 DNS 监听器，也不会执行自己的用户态路由匹配器。

## dae 配置

保留原有接口和内核配置，并固定双方共享的输出 mark：

```shell
# dae.conf 片段
global {
  wan_interface: auto
  so_mark_from_dae: 0x100
}

routing {
  fallback: direct
}
```

为保持配置兼容，dae 仍会解析 routing 段，但其逐流判定在外部策略模式下不再
具有权威性。被 dae 捕获的 TCP/UDP 流量都会进入透明监听套接字，最终由
sing-box 路由。

启动 dae 前设置控制套接字和预期的 sing-box UID：

```shell
export DAE_EXTERNAL_POLICY_SOCKET=/run/dae/sing-box.sock
export DAE_EXTERNAL_POLICY_UID=0
exec dae run --config /etc/dae/config.dae
```

若省略 `DAE_EXTERNAL_POLICY_UID`，dae 会要求对端与自身具有相同的有效 UID。
双方还会通过 `SO_PEERCRED` 相互验证身份。

## 启动与故障行为

应先启动 sing-box。dae 会重试连接控制套接字，最长 30 秒。sing-box 验证
dae 身份并接收三个监听套接字后，会确认该数据面代次，此时 dae 才报告就绪。

该模式采用失败关闭策略：

- 监听器交接失败时 dae 不会进入就绪状态；
- 控制通道断开时，对应的 dae 代次会退出；
- dae 不会静默回退到自己的用户态路由器；
- sing-box 的 DNS 和出站套接字使用共享 mark，不会被再次捕获。

dae 热重载时，新控制面代次会交接一组新的监听器。sing-box 只替换监听器，
已建立的 TCP 路由和 UDP NAT 会话仍由 sing-box 持有。

## 元数据

对于每个新 TCP 连接或 UDP 会话，sing-box 会按原始源/目标五元组查询元数据。
dae 会返回当前可用的 eBPF 元数据：

- PID、进程名、可执行文件路径和 UID；
- 源 MAC 地址；
- DSCP。

控制协议不暴露 dae 的内部 BPF map 布局，因此 dae 内部 map 变化不要求同步
修改 sing-box。
