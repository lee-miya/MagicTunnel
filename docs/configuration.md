# 配置参考

配置文件是 TOML，未知字段一律报错（拼错的键不会被静默忽略）。模板见 `config/client.example.toml`、`config/server.example.toml`、`config/relay.example.toml`；也可以用 `make config`（`scripts/gen-config.sh`）交互式生成，它会按下面的取值范围校验每一项。

## 客户端 `mt-client -c client.toml`

### `[log]`

| 键 | 默认 | 说明 |
| --- | --- | --- |
| `level` | `"info"` | tracing 过滤器，如 `"info,mt_client=debug"`。环境变量 `RUST_LOG` 优先。 |

### `[tls]`（必填）

| 键 | 说明 |
| --- | --- |
| `ca` | 验证所有对端用的 CA 证书（PEM）。 |
| `cert` / `key` | 本节点证书链与私钥（PEM）。客户端证书须带 `clientAuth` 用途。 |

### `[obfs]`（必填）

| 键 | 说明 |
| --- | --- |
| `xor_key` | 非空字符串，整条路径上所有节点必须相同。只做 UDP 层混淆，不是加密。 |

### `[tun]`

| 键 | 默认 | 说明 |
| --- | --- | --- |
| `name` | Linux/Windows `"mt0"`，macOS `"utun"` | macOS 只能是 `utun`（内核选空闲单元）或 `utunN`。 |
| `mtu` | `1200` | 上限。实际 MTU = min(本值, 出口回复的路径 MTU, 首跳当前可承载的 datagram)，低于 576 报错。1200 在任何至少能承载 1312 字节 UDP 报文的 IPv4 路径上都放得下；设得更大则取决于握手时各跳 MTU 探测进行到哪里，重连后可能变化。 |
| `offload` | `true` | 仅 Linux：TUN 以 virtio-net 头收发 TSO/GRO 超级包，批量 TCP 的系统调用与内核协议栈开销大幅下降。内核不支持时自动退回普通模式。macOS/Windows 忽略。 |

### `[quic]`

客户端到首跳这条链路的 QUIC 参数（服务端各自有同名段）。

| 键 | 默认 | 说明 |
| --- | --- | --- |
| `keepalive_secs` | `10` | 空闲链路发保活包的间隔，须 ≥ 1 且小于 `idle_timeout_secs`。也用来维持 NAT 映射。 |
| `idle_timeout_secs` | `30` | 链路静默这么久即判定死亡（上限 600）。两端取较小值。越小越快发现首跳宕机、越早重连，但在丢包严重的网络上越容易误判。 |
| `congestion` | `"cubic"` | `"cubic"`、`"bbr"` 或 `"newreno"`。BBR 不把丢包当拥塞信号，在丢包多的长距离链路上通常更快（quinn 将其标为实验性）。 |

### `[reconnect]`

| 键 | 默认 | 说明 |
| --- | --- | --- |
| `enabled` | `true` | 已建立的隧道断开后：保留 TUN 与路由（断线期间流量进 TUN 后丢弃，不会经物理网卡泄漏），立即重拨一次，之后按 1s、2s、4s… 指数退避（±25% 抖动）直到成功。为 `false` 时恢复路由、删除 TUN 并以错误退出（交给 systemd 之类重启）。 |
| `max_delay_secs` | `30` | 退避上限（≥ 1）。 |

重连时客户端把上次的隧道地址和出口发的会话令牌一起带上：地址空闲就直接给回；仍被旧连接占着（出口还没发现旧连接已死）时，令牌匹配即接管并关闭旧连接。地址不变，出口的 NAT/conntrack 状态就仍然有效，已建立的 TCP 连接能继续。若出口给了新地址（例如地址被别人占用），客户端会就地换地址（先加新地址再删旧地址，路由不中断），已有连接会断。

**首次**连接失败不会重试，直接报错退出，这类失败通常是配置问题。

### `[metrics]`

| 键 | 默认 | 说明 |
| --- | --- | --- |
| `listen` | 不启用 | 例如 `"127.0.0.1:9100"`，提供 `GET /metrics`（Prometheus 文本格式）。明文 HTTP、无认证，只应监听回环或内网地址。启动时端口被占用会报错。 |
| `log_interval_secs` | `0`（关闭） | 每隔 N 秒以 info 级别记一行 `stats`：上下行速率、RTT、丢包、重连次数。 |

### `[[route]]`（至少 1 个，至多 8 个）

| 键 | 说明 |
| --- | --- |
| `addr` | 该跳的 `IP:端口`。只有第一跳的地址会被加旁路路由。 |
| `server_name` | 必须是该跳证书里的 SAN。 |

第一项是首跳，最后一项是出口；中间都是中继。

## 服务端 `mt-server -c server.toml`

| 键 | 说明 |
| --- | --- |
| `listen` | 监听的 UDP 地址，如 `"0.0.0.0:4433"`。中继也用这个 socket 拨下一跳。 |
| `[log]` `[tls]` `[obfs]` | 同客户端。服务端证书须带 `serverAuth`，作为中继拨下一跳时还要 `clientAuth`（`xtask gen-certs` 两者都签）。 |
| `[quic]` | 同客户端，作用于本节点接受和拨出的所有链路。 |
| `[metrics]` | 同客户端；`stats` 日志内容为会话数、出口/中继上下行速率、丢包。 |

### `[exit]`（可选）

有这一段的节点既是出口也能中继，需要 root 或 `CAP_NET_ADMIN`，PATH 上要有 `iptables`；没有这一段就是纯中继，不碰 TUN/NAT，不需要特权。

| 键 | 说明 |
| --- | --- |
| `pool` | 隧道地址池，至少 `/30`。第一个主机地址给出口 TUN 自己，其余按 next-fit 轮转分给客户端（刚释放的地址不立即复用）。不要和出口机器上已有的网段重叠。 |

### `[exit.tun]`

| 键 | 默认 | 说明 |
| --- | --- | --- |
| `name` | `"mt0"` | 出口 TUN 名，也是 iptables 规则注释 `magictunnel:<name>` 的一部分。 |
| `mtu` | `1200` | 出口 TUN MTU；回复给客户端的路径 MTU 不超过它。 |
| `offload` | `true` | 同客户端 `tun.offload`。 |
| `queues` | `0`（每 CPU 一个） | 多队列 TUN：内核按流把包分到各队列，每个队列一个读任务，下行可用满多核。1 即单队列。上限 64。 |

## 协议兼容

握手消息新增的字段（`Hello.resume`、`HelloReply::Ok.token`）都是可选的，旧版本节点会忽略它们：混跑新旧版本不会出错，只是经过旧节点的路径拿不回原地址。
