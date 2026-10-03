# magicTunnel

用 Rust 实现的三层（IP 层）流量代理：客户端用 TUN 虚拟网卡接管本机全部 IPv4 流量，每个 IP 包装进一个 QUIC datagram，经客户端自选的多跳路径逐跳转发，最后由出口节点 NAT 出去。

```mermaid
flowchart LR
  app["本机应用"] --> tunc["客户端 TUN"]
  tunc -->|"QUIC datagram<br/>mTLS + XOR 混淆"| r1["relay1"]
  r1 -->|"独立的 QUIC 会话"| r2["relay2 …"]
  r2 --> exit["出口 mt-server"]
  exit --> tune["出口 TUN"] --> nat["iptables MASQUERADE"] --> net["互联网"]
```

- **传输**：QUIC（quinn），IP 包走不可靠 datagram，无队头阻塞；控制面是一条可靠流（握手、路由表、地址分配）。
- **加密与认证**：TLS 1.3 双向证书（mTLS），每一跳都校验对端证书与名字。
- **混淆**：UDP 层 XOR（每个 UDP 报文带随机 nonce），线上看不到 QUIC 特征。它只是抗 DPI，**不是加密**，机密性由 TLS 保证。
- **多跳**：客户端在配置里写出整条路径（最多 8 跳）；每跳独立的 QUIC + mTLS + XOR 会话，节点只知道相邻两跳。
- **平台**：服务端 Linux；客户端 Linux（已实测），macOS / Windows（已实现、尚未真机验证）。

## 稳定性与性能（阶段 4）

- **断线重连**：隧道断开时客户端保留 TUN 和路由（流量等待，不会绕过隧道泄漏到本地网络），按指数退避（带抖动）重拨整条路径；出口凭会话令牌把**同一个隧道地址**还给客户端，出口的 NAT 状态因此仍然有效，已建立的 TCP 连接通常能挺过断线（e2e 实测：首跳崩溃、出口重启各一次，一条 TCP 长连接零丢失）。
- **保活**：keepalive / idle 超时可配（默认 10s / 30s），首跳握手 10s 超时。
- **多核**：每个方向的数据泵是独立任务；出口 TUN 支持 Linux 多队列（默认每 CPU 一个队列，各自一个读任务）。
- **GSO/GRO**：UDP 侧保留 quinn 的 GSO/GRO；TUN 侧（Linux）启用 virtio-net offload，读入 TSO 超级包后切成 MTU 大小的 datagram，写回前把同一流的分段合并（GRO），每次系统调用搬一个超级包。
- **背压与丢包**：客户端上行在 QUIC 发送缓冲满时等待（拥塞经 TUN 队列反压到本机 socket，而不是丢包）；中继和出口下行不阻塞，缓冲满时丢最旧的包（队头丢弃）。发送缓冲限制在 512 KB，避免缓冲膨胀。包超过当前路径可承载的大小时，客户端、中继、出口都会像路由器一样回 ICMP “需要分片”，使隧道内 TCP 的 PMTU 发现端到端可用。
- **指标与日志**：可选 Prometheus 端点（`/metrics`）、定期流量摘要日志、会话结束时记录收发包数/字节数/时长；日志在非终端或设置 `NO_COLOR` 时不带颜色。

同一台 2 核虚拟机上（所有节点共享 CPU，测的是每字节 CPU 开销），`scripts/e2e/perf.sh` 的批量 TCP 吞吐：

| 路径 | 阶段 3 上行 / 下行 | 阶段 4 上行 / 下行 |
| --- | --- | --- |
| 1 跳 | 1.2–1.7 / 1.8–1.9 Gbit/s | 3.1–3.4 / 3.9–4.2 Gbit/s |
| 2 跳 | 1.2–1.3 / 1.4–1.5 Gbit/s | 2.4–3.1 / 2.5–2.8 Gbit/s |

上行限速 50 Mbit/s（`SHAPE="50mbit 10ms"`）时隧道跑满 44 Mbit/s，负载下 ping 与不走隧道时相同，隧道本身不额外排队。

## 快速开始

需要 Rust（edition 2024，rustc ≥ 1.85）。

```bash
make                                          # = cargo build --release，产物 target/release/{mt-server,mt-client}
make certs                                    # 开发用 CA + relay1/exit1/client1 证书到 ./certs
make config                                   # 交互式生成客户端/出口/中继配置（scripts/gen-config.sh）
```

`make config` 逐项提问并校验（地址格式、地址池、MTU、QUIC 超时等与程序同样的规则），可随机生成 `xor_key` 或从已有配置复制，最后预览并以 0600 权限写出。也可以用 `scripts/gen-config.sh client laptop.toml` 直接指定角色和输出文件。

`make help` 列出全部目标：`test`/`clippy`/`ci`、`e2e*`、`perf`、`install`（`PREFIX`/`DESTDIR`/`CONFDIR` 可改）、`dist`（打包成 `dist/magictunnel-<版本>-<target>.tar.gz`，`TARGET=<triple>` 交叉编译）、`cross-check` 等。

交叉编译 Linux 目标（如在 ARM 机器上出 x86_64 二进制）用 [zig](https://ziglang.org/download/) 当 C 编译器和链接器，Makefile 自动接好（zig 不在 PATH 上时传 `ZIG=/path/to/zig`）：

```bash
rustup target add x86_64-unknown-linux-gnu x86_64-unknown-linux-musl
make TARGET=x86_64-unknown-linux-gnu          # 动态链接，要求 glibc ≥ 2.17（ZIG_GLIBC 可改）
make dist TARGET=x86_64-unknown-linux-musl    # 全静态，任意发行版可用
```

已设置 `CC_<triple>` / `CARGO_TARGET_<TRIPLE>_LINKER` 时以它们为准。同架构的 musl 目标（如 x86_64 主机上 `make TARGET=x86_64-unknown-linux-musl`）没有 zig 也行，直接用系统 `cc`。

1. 出口节点（需要 root 或 `CAP_NET_ADMIN`，PATH 里要有 `iptables`）：`make config` 选“出口”，或以 `config/server.example.toml` 为模板，`sudo mt-server -c exit1.toml`。
2. 可选的中继节点（无需特权）：`make config` 选“中继”，或以 `config/relay.example.toml` 为模板，`mt-server -c relay1.toml`。
3. 客户端（需要 root / 管理员）：`make config` 选“客户端”并按顺序填写路径，或以 `config/client.example.toml` 为模板写好 `[[route]]`，`sudo mt-client -c client1.toml`。
4. 所有节点的 `obfs.xor_key` 必须一致，证书须由同一个 CA 签发，`server_name` 须与对端证书的 SAN 一致。

Ctrl-C / SIGTERM 时客户端会先删路由再删 TUN，把机器恢复原样；被 `kill -9` 后，下次启动会清掉残留路由。

## 文档

- [配置参考](docs/configuration.md)：所有配置项、默认值和取舍。
- [部署指南](docs/deployment.md)：证书、systemd、防火墙与 sysctl、监控告警、滚动升级、排障、安全说明。

## 代码结构

| 路径 | 内容 |
| --- | --- |
| `crates/common` | 配置、握手协议、IPv4/ICMP 辅助、指标、日志、证书加载 |
| `crates/transport` | QUIC 端点、mTLS、XOR 混淆 socket、控制流、datagram 收发与中继 |
| `crates/tunio` | 批量 TUN 读写（Linux offload：TSO 拆分 / GRO 合并） |
| `crates/client` | `mt-client`：会话与重连、TUN、路由接管（Linux/macOS/Windows）、数据泵 |
| `crates/server` | `mt-server`：中继、出口（地址池、会话表、多队列 TUN、iptables NAT） |
| `xtask` | `cargo xtask gen-certs`：开发证书 |
| `deploy/` | systemd 单元、sysctl 示例 |
| `scripts/e2e/` | 基于 netns 的端到端测试与性能测量 |

## 测试

```bash
make test             # 单元测试 + loopback QUIC 测试（make ci 另加 fmt 检查与 clippy -D warnings）
make e2e-single       # 单跳：路由接管、NAT、mTLS/XOR 拒绝、线上无 QUIC 特征（约 20s）
make e2e-multi        # 2/3/8 跳、逐跳隔离、失败原因回传（约 30s）
make e2e-resilience   # 重连、断线期间不泄漏、TCP 长连接存活、指标、PMTU/ICMP（约 35s）
make e2e              # 以上三项
make perf             # release 构建后测吞吐与负载下延迟
```

e2e 脚本在 `unshare -Urn` 建的私有网络命名空间里运行，不需要 root，但需要 `/dev/net/tun`、`iptables`、`python3`、`curl`；`perf.sh` 的 `SHAPE="50mbit 10ms"` 用 `tc netem` 模拟慢速上行。
