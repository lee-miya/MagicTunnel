# 部署指南

## 1. 规划

- **出口**（`[exit]`）：流量最终从这里出公网。需要 root 或 `CAP_NET_ADMIN`、`iptables`，Linux。它同时也能当中继。
- **中继**（无 `[exit]`）：只转发 datagram，不需要任何特权，也不碰本机网络配置。
- **客户端**：在配置里写出整条路径，最多 8 跳。路径上每个节点只认识相邻两跳。

一条路径上的所有节点必须**共用同一个 `obfs.xor_key`**（中继用同一个 socket、同一把 key 拨下一跳），证书必须出自同一个 CA。

每一跳需要放行的只有 `listen` 的 UDP 端口（默认 4433）。

## 2. 安装

```bash
make                  # 以普通用户构建
sudo make install     # 二进制到 /usr/local/bin，示例配置与 certs/ 目录到 /etc/magictunnel，
                      # systemd 单元到 /etc/systemd/system，sysctl 到 /etc/sysctl.d
```

`PREFIX=/usr`、`CONFDIR=...` 会同步改写单元文件里的路径；`DESTDIR=/tmp/pkg` 用于打包暂存。`sudo make uninstall` 删除上述文件但保留 `/etc/magictunnel`（里面有配置和私钥）。要拷到别的机器，用 `make dist`（可加 `TARGET=x86_64-unknown-linux-musl` 交叉编译出全静态二进制，需 zig，见 README）生成带二进制、配置示例、`deploy/`、文档的 tar 包。

## 3. 证书与密钥

开发和小规模部署可以直接用自带工具生成 CA 与节点证书：

```bash
# 服务端名字即证书 DNS SAN（客户端 [[route]].server_name 要写它），可附加 IP SAN
scripts/gen-certs.sh --out certs --server exit1=203.0.113.20 --server relay1 --client laptop --days 365
```

- `certs/ca.key` 是整套信任的根：只用于签发，放在离线机器上，**不要**部署到任何节点。节点只需要 `ca.pem`、自己的 `NAME.pem` 和 `NAME.key`（权限 0600）。
- 再次运行会复用已有 CA，只签缺少的节点证书；`--force` 重签已有节点证书（从不覆盖 CA）。
- 不支持 CRL/OCSP：要撤销某个节点，只能换 CA 并重签其余节点。节点证书有效期宜短，按期轮换；替换文件后重启进程生效，客户端会自动重连。
- XOR key 用足够长的随机串，例如 `openssl rand -base64 32`。它只用于混淆，泄漏后对手能识别出 QUIC 流量，但读不到内容。

## 4. 服务端

### 内核参数

magicTunnel 给 UDP socket 申请 4 MB 收发缓冲，内核按 `net.core.rmem_max` / `wmem_max` 截断（很多发行版默认只有约 200 KB）。高带宽节点建议放开：

```bash
sudo install -m 0644 deploy/sysctl/99-magictunnel.conf /etc/sysctl.d/
sudo sysctl --system
```

`net.ipv4.ip_forward` 不用手动开：出口启动时会打开它，退出时若原来是 0 则恢复。

### 防火墙与 NAT

出口启动时自动插入以下规则（都带注释 `magictunnel:<tun 名>`，退出时删除；被 `kill -9` 后，下次启动会先清掉同名旧规则）：

```text
-t nat    POSTROUTING -s <pool> ! -o <tun> -j MASQUERADE
-t filter FORWARD     -i <tun> ! -o <tun> -j ACCEPT
-t filter FORWARD     -o <tun> -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
```

规则用 `-I` 插在链首，能穿过 Docker 等设置的 `FORWARD DROP` 策略。客户端之间互不可达（出口还会在用户态丢弃发往池内其他地址的包，以及源地址不是该会话地址的包）。若主机防火墙由 firewalld/ufw 管理，确认它们重载时不会把这些规则冲掉，或者把出口进程放在它们之后启动。

### systemd

```bash
sudo install -m 0644 deploy/systemd/mt-server@.service deploy/systemd/mt-relay@.service /etc/systemd/system/
# 出口：/etc/magictunnel/exit1.toml
sudo systemctl enable --now mt-server@exit1
# 纯中继：/etc/magictunnel/relay1.toml，以动态非特权用户运行
sudo systemctl enable --now mt-relay@relay1
journalctl -u mt-server@exit1 -f
```

`mt-server@.service` 以 root 运行但只保留 `CAP_NET_ADMIN` 和 `CAP_NET_RAW`（建 TUN、改 iptables 和 `ip_forward`）。`mt-relay@.service` 不给任何能力。

启动成功的标志：日志里有 `accepting tunnels`，出口还有 `exit TUN up ... queues=N offload=true`。

### 多核与 offload

- `[exit.tun] queues`（默认每 CPU 一个）开启多队列 TUN，下行按流分到各队列并行处理；每个客户端会话的上行本来就是独立任务。
- `offload = true`（默认）时，出口与内核交换 TSO/GRO 超级包。日志里 `offload=false` 说明内核拒绝了，会自动退回逐包模式，功能不受影响。

## 5. 客户端

| 平台 | 运行 | 说明 |
| --- | --- | --- |
| Linux | `sudo mt-client -c client.toml`，或 `deploy/systemd/mt-client.service` | 需要 `ip`（iproute2）。路由带 `proto 233`，崩溃残留可用 `ip -4 route flush proto 233` 清除，下次启动也会自动清。 |
| macOS | `sudo mt-client -c client.toml` | `tun.name` 用 `utun` 或 `utunN`。尚未真机验证。 |
| Windows | 管理员终端运行 `mt-client.exe -c client.toml` | 需要 [wintun.dll](https://www.wintun.net)，放在 exe 同目录。尚未真机验证。 |

客户端只给**首跳**加一条 `/32` 旁路路由，默认流量用 `0.0.0.0/1` + `128.0.0.0/1` 指向 TUN，不修改原默认路由。只接管 IPv4，IPv6 流量不经隧道。

断线时（默认开启重连）客户端保留 TUN 和路由，流量等待隧道恢复而不会走物理网卡；SIGINT/SIGTERM（重连中也一样）会恢复路由并删除 TUN 后退出。

## 6. 监控

在 `[metrics]` 里设 `listen = "127.0.0.1:9100"`，Prometheus 抓 `http://<节点>:9100/metrics`。端点是明文、无认证的，只应暴露在回环或管理网段上（例如通过 SSH 隧道或 node_exporter 所在的内网）。

```yaml
scrape_configs:
  - job_name: magictunnel
    static_configs:
      - targets: ["exit1.internal:9100", "relay1.internal:9100"]
```

| 指标 | 节点 | 含义 |
| --- | --- | --- |
| `magictunnel_client_{packets,bytes}_total{dir}` | 客户端 | 经隧道的上行/下行包与字节 |
| `magictunnel_connected` | 客户端 | 隧道在线为 1 |
| `magictunnel_reconnects_total` | 客户端 | 断线后重建次数 |
| `magictunnel_quic_{rtt_seconds,cwnd_bytes,mtu_bytes,sent_packets,lost_packets,congestion_events}` | 客户端 | 当前到首跳连接的 QUIC 路径统计（重连后从 0 计） |
| `magictunnel_exit_{packets,bytes}_total{dir}` | 出口 | 在出口进出 TUN 的流量 |
| `magictunnel_relay_{packets,bytes}_total{dir}` | 中继 | 中继转发的流量（up 为朝出口方向） |
| `magictunnel_sessions{role}` / `magictunnel_sessions_total{role}` | 服务端 | 当前 / 累计会话，`role` 为 `exit` 或 `relay` |
| `magictunnel_resumed_sessions_total` | 出口 | 重连后拿回原地址的会话 |
| `magictunnel_pool_leased` / `magictunnel_pool_capacity` | 出口 | 地址池占用 |
| `magictunnel_quic_handshake_failures_total` | 服务端 | QUIC 握手失败（证书不对、超时）。XOR key 不一致的包根本不会被识别为握手，不计入 |
| `magictunnel_setup_failures_total` | 服务端 | 握手后建隧道失败（被拒、下一跳不通等） |
| `magictunnel_dropped_packets_total{reason}` | 全部 | 丢包：`too_large` 超过路径 MTU、`filtered` 伪造源地址或访问其他客户端、`no_session` 无对应会话、`not_ipv4`、`tun_write` 内核拒收 |
| `magictunnel_icmp_frag_needed_sent_total` | 全部 | 因包过大回给发送方的 ICMP “需要分片” |

建议告警：客户端 `magictunnel_connected == 0` 持续 1 分钟；`rate(magictunnel_reconnects_total[10m])` 偏高；出口 `magictunnel_pool_leased / magictunnel_pool_capacity > 0.9`；`magictunnel_dropped_packets_total{reason="filtered"}` 增长（有客户端在伪造源地址）；`magictunnel_quic_handshake_failures_total` 突增（证书配置不一致，或知道 XOR key 的人在用错误证书尝试）。

不接 Prometheus 时可以设 `log_interval_secs = 60`，每分钟在日志里记一行 `stats`。

## 7. 日志

- 每个会话的建立与结束各一行：出口 `tunnel up` / `tunnel down`，中继 `relay up` / `relay down`，结束行带 `secs`、`up_packets`、`up_bytes`、`down_packets`、`down_bytes` 和结束原因。节点只记录相邻两跳的地址。
- 客户端：`tunnel up`、`tunnel lost, reconnecting: <原因>`、`reconnect failed ... retry_in_ms=...`、`tunnel restored`。
- 深处的失败会带路径回传给客户端，例如 `tunnel rejected: relay1: relay2: cannot reach exit1 (203.0.113.20:4433): no answer within 4s`。
- 调试用 `RUST_LOG=info,mt_server=debug`（或 `mt_client=debug`）；`trace` 级别会逐包记录丢弃原因，量很大。
- 输出到终端以外（journald、文件）时不带颜色；`NO_COLOR=1` 也会关掉颜色。

## 8. 运维

- **滚动升级 / 重启**：重启中继或出口时，经过它的客户端会断线并自动重连（客户端默认最多等 30 秒退避），出口重启后客户端拿回原地址，已建立的 TCP 连接通常能继续。一次只重启一个节点。
- **改配置**：没有热加载，改完重启进程。
- **调快故障发现**：`[quic] idle_timeout_secs` 调小（例如 10，keepalive 3）能更快发现首跳宕机；需要两端都调小才生效。
- **容量**：地址池 `/24` 可容纳 253 个客户端；会话占用内存很小，瓶颈通常是 CPU（加密 + 拷贝）。用 `scripts/e2e/perf.sh` 可以在单机上估算每字节开销。

## 9. 排障

| 现象 | 可能原因 |
| --- | --- |
| 客户端 `connecting to X: no answer within 10s` | UDP 端口不通、对端没启动，或 `xor_key` 不一致：对端把这些包当噪声丢弃，服务端日志和指标里都看不到任何痕迹。 |
| `invalid peer certificate` / `not valid for name` | CA 不一致，或 `server_name` 不在对端证书 SAN 里。 |
| `tunnel rejected: ...: this node is not an exit` | 路径最后一跳没有 `[exit]` 段。 |
| `tunnel rejected: ...: cannot reach <hop>` | 那一跳的上一跳连不上它（地址、端口、key、证书）。 |
| `tunnel address pool exhausted` | 出口地址池用完，扩大 `exit.pool`。 |
| 能 ping 不能上网 | 出口 `iptables` 规则被别的防火墙冲掉；`iptables-save | grep magictunnel` 应有 3 条。 |
| 大包或 HTTPS 卡住 | 路径 MTU 太小：确认路径能承载 1312 字节的 UDP 报文；若 `tun.mtu` 设得比 1200 大，可以改回 1200。`magictunnel_dropped_packets_total{reason="too_large"}` 会持续增长。 |
| `exit TUN up ... offload=false` | 内核不支持 TUN offload，已自动退回逐包模式。 |

## 10. 安全说明

- 真正的机密性和完整性来自每一跳的 TLS 1.3；XOR 层只是让线上看不出 QUIC 特征。
- 不知道 `xor_key` 的扫描或主动探测得不到任何回复（任意大小的随机 UDP 包都被静默丢弃，端口表现为 `open|filtered`），日志和指标里也没有痕迹。知道 `xor_key` 的人能发起 TLS 握手、看到服务端证书，但没有同一 CA 签发的客户端证书就会被拒（计入 `magictunnel_quic_handshake_failures_total`）。
- 程序没有按来源限速。客户端来源固定时，最好在防火墙上只放行这些地址访问 `listen` 端口；否则可只对新流限速，例如 `iptables -I INPUT -p udp --dport 4433 -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 20/sec --hashlimit-burst 50 --hashlimit-mode srcip --hashlimit-name mt4433 -j DROP`（不要按包数限速，会把隧道吞吐一起限住）。
- 出口只阻止客户端互访，隧道用户仍能访问出口主机本身（经池网关地址）和出口所在的内网（如云元数据 `169.254.169.254`）。不希望这样时自行加规则，例如 `iptables -I INPUT -i <tun> -j DROP` 与 `iptables -I FORWARD -i <tun> -d 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16 -j REJECT`。
- **中继能看到隧道内的明文 IP 包**（每跳都会解密再加密），与出口一样需要可信；需要端到端保密的应用层流量请自行使用 TLS 等加密。
- 重连用的会话令牌经过路径上的中继传递，中继可以看到它。令牌只能用来接管同一个隧道地址，而中继本来就在该会话的路径上。
- metrics 端点无认证，不要暴露到公网。
- 节点私钥与 XOR key 应仅对运行用户可读。

## 11. 已知限制

- 只承载 IPv4。
- 客户端在物理网络切换（换 Wi-Fi、默认网关变化）后，首跳旁路路由仍指向旧网关，重连会一直失败，需要重启客户端。
- 握手时确定的 MTU 不会在会话中途升高（只会因重连而改变）。
- macOS / Windows 客户端尚未真机验证。
