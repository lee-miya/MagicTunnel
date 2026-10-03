#!/usr/bin/env bash
# Interactive generator for mt-server / mt-client config files.
#
#   scripts/gen-config.sh                     asks for everything, starting with the role
#   scripts/gen-config.sh client laptop.toml  role (client|exit|relay) and output file up front
#
# Enter accepts the default shown in [brackets]. Answers are read line by line from stdin, so
# the script can also be fed from a file. The result is written with mode 0600 because it
# holds the shared obfs.xor_key. Every value is checked against the same rules mt-server and
# mt-client apply (see crates/common/src/config.rs). Runs on bash 3.2 (macOS) and later.
set -euo pipefail

if [[ -t 2 && -z "${NO_COLOR:-}" ]]; then
  B=$'\e[1m' DIM=$'\e[2m' YEL=$'\e[33m' RED=$'\e[31m' GRN=$'\e[32m' RST=$'\e[0m'
else
  B='' DIM='' YEL='' RED='' GRN='' RST=''
fi

say() { printf '%s\n' "$*" >&2; }
note() { say "${DIM}$*${RST}"; }
warn() { say "${YEL}注意：$*${RST}"; }
die() { say "${RED}错误：$*${RST}"; exit 1; }
section() { say ""; say "${B}== $*${RST}"; }

usage() {
  sed -n '2,10s/^# \{0,1\}//p' "$0"
  exit "${1:-0}"
}

trim() {
  local s=$1
  s=${s#"${s%%[![:space:]]*}"}
  s=${s%"${s##*[![:space:]]}"}
  printf '%s' "$s"
}

# ---- prompts -------------------------------------------------------------------------------

# Locals of the prompt helpers are __-prefixed: they assign the caller's variable by name, and a
# same-named local would shadow it.

# ask VAR PROMPT DEFAULT [VALIDATOR [HINT]]: repeats until VALIDATOR accepts the answer.
ask() {
  local __var=$1 __prompt=$2 __default=$3 __check=${4:-} __hint=${5:-} __reply
  while :; do
    if [[ -n $__default ]]; then
      printf '%s [%s]: ' "$__prompt" "$__default" >&2
    else
      printf '%s: ' "$__prompt" >&2
    fi
    IFS= read -r __reply || die "输入意外结束"
    __reply=$(trim "$__reply")
    __reply=${__reply:-$__default}
    if [[ -z $__check ]] || "$__check" "$__reply"; then
      printf -v "$__var" '%s' "$__reply"
      return
    fi
    say "${RED}  无效：${__hint:-请重新输入}${RST}"
  done
}

# ask_yn VAR PROMPT y|n: sets VAR to true or false.
ask_yn() {
  local __var=$1 __prompt=$2 __default=$3 __reply __hint=y/N
  [[ $__default == y ]] && __hint=Y/n
  while :; do
    printf '%s [%s]: ' "$__prompt" "$__hint" >&2
    IFS= read -r __reply || die "输入意外结束"
    __reply=$(trim "$__reply")
    case ${__reply:-$__default} in
      [yY] | [yY][eE][sS]) printf -v "$__var" true; return ;;
      [nN] | [nN][oO]) printf -v "$__var" false; return ;;
    esac
    say "${RED}  请输入 y 或 n${RST}"
  done
}

RANGE_LO=0 RANGE_HI=0
in_range() { is_uint "$1" && ((10#$1 >= RANGE_LO && 10#$1 <= RANGE_HI)); }

# ask_num VAR PROMPT DEFAULT LO HI
ask_num() {
  RANGE_LO=$4 RANGE_HI=$5
  ask "$1" "$2" "$3" in_range "$4–$5 之间的整数"
  printf -v "$1" '%d' "$((10#${!1}))"
}

CHOICES=0
is_choice() { is_uint "$1" && ((10#$1 >= 1 && 10#$1 <= CHOICES)); }

# choose VAR PROMPT DEFAULT_INDEX "value|label"...: numbered menu, sets VAR to the value.
choose() {
  local __var=$1 __prompt=$2 __default=$3 __i __opt __pick
  shift 3
  say "$__prompt"
  for ((__i = 1; __i <= $#; __i++)); do
    __opt=${!__i}
    say "  $__i) ${__opt#*|}"
  done
  CHOICES=$#
  ask __pick "选择" "$__default" is_choice "输入 1–$# 的序号"
  __opt=${!__pick}
  printf -v "$__var" '%s' "${__opt%%|*}"
}

# ---- validators ----------------------------------------------------------------------------

is_uint() { [[ $1 =~ ^[0-9]{1,9}$ ]]; }
is_port() { is_uint "$1" && ((10#$1 >= 1 && 10#$1 <= 65535)); }
is_nonempty() { [[ -n $1 ]]; }

is_ipv4() {
  [[ $1 =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  local i
  for i in 1 2 3 4; do ((10#${BASH_REMATCH[i]} <= 255)) || return 1; done
}

# IP:port as Rust's SocketAddr parses it: an IPv4 address or a bracketed IPv6 one, no names.
is_sockaddr() {
  local host=${1%:*} port=${1##*:}
  [[ $1 == *:* ]] && is_port "$port" || return 1
  is_ipv4 "$host" || [[ $host =~ ^\[[0-9A-Fa-f:.]+\]$ && $host == *:* ]]
}
is_opt_sockaddr() { [[ -z $1 ]] || is_sockaddr "$1"; }
is_hop_addr() { is_ipv4 "$1" || is_sockaddr "$1"; }

# Up to 3 unicast IPv4 addresses separated by spaces or commas, or nothing.
is_dns_list() {
  local ip n=0
  # shellcheck disable=SC2086
  for ip in ${1//,/ }; do
    is_ipv4 "$ip" || return 1
    [[ $ip != 0.0.0.0 && $ip != 255.255.255.255 ]] || return 1
    ((10#${ip%%.*} < 224 || 10#${ip%%.*} > 239)) || return 1
    n=$((n + 1))
  done
  ((n <= 3))
}

is_pool() {
  [[ $1 =~ ^([0-9.]+)/([0-9]{1,2})$ ]] || return 1
  local addr=${BASH_REMATCH[1]} plen=${BASH_REMATCH[2]}
  is_ipv4 "$addr" && ((10#$plen <= 30))
}

# A DNS name or IP from the peer's certificate SANs.
is_server_name() { [[ $1 =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]]; }
is_node_name() { [[ $1 =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$ ]]; }
is_linux_ifname() { [[ $1 =~ ^[A-Za-z0-9_.-]{1,15}$ ]]; }
is_macos_utun() { [[ $1 =~ ^utun[0-9]*$ ]]; }
is_win_ifname() { [[ -n $1 && $1 != *[\\/:\"]* ]]; }
is_printable() { [[ -n $1 && $1 != *[[:cntrl:]]* ]]; }

# ---- helpers -------------------------------------------------------------------------------

toml_str() {
  local s=$1
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  printf '"%s"' "$s"
}

# Prints the obfs.xor_key value of a magicTunnel config, or fails.
read_xor_key() {
  local file=$1 line value
  [[ -f $file && -r $file ]] || return 1
  line=$(grep -m1 -E '^[[:space:]]*xor_key[[:space:]]*=' "$file") || return 1
  value=$(trim "${line#*=}")
  case $value in
    \"*\")
      value=${value:1:${#value}-2}
      value=${value//\\\\/$'\x01'}
      value=${value//\\\"/\"}
      value=${value//$'\x01'/\\}
      ;;
    \'*\') value=${value:1:${#value}-2} ;;
    *) return 1 ;;
  esac
  [[ -n $value ]] && printf '%s' "$value"
}

random_key() {
  head -c 32 /dev/urandom | base64 | tr -d '\n='
}

ip2int() {
  local IFS=.
  # shellcheck disable=SC2086
  set -- $1
  echo $(((10#$1 << 24) | (10#$2 << 16) | (10#$3 << 8) | 10#$4))
}
int2ip() { echo "$(($1 >> 24 & 255)).$(($1 >> 16 & 255)).$(($1 >> 8 & 255)).$(($1 & 255))"; }
prefix_mask() { (($1 == 0)) && echo 0 || echo $(((0xffffffff << (32 - $1)) & 0xffffffff)); }

# Warns when the pool overlaps an address configured on this machine.
check_pool_overlap() {
  command -v ip >/dev/null 2>&1 || return 0
  local net=$1 plen=$2 cidr addr alen m
  while read -r cidr; do
    addr=${cidr%/*} alen=${cidr#*/}
    m=$(prefix_mask $((plen < alen ? plen : alen)))
    if ((($(ip2int "$addr") & m) == (net & m))); then
      warn "本机已有地址 $cidr 与地址池重叠；如果本机就是出口，请换一个网段"
    fi
  done < <(ip -4 -o addr show 2>/dev/null | awk '{print $4}')
}

host_platform() {
  case $(uname -s 2>/dev/null) in
    Darwin) echo macos ;;
    MINGW* | MSYS* | CYGWIN*) echo windows ;;
    *) echo linux ;;
  esac
}

platform_index() {
  case $1 in
    linux) echo 1 ;;
    macos) echo 2 ;;
    windows) echo 3 ;;
  esac
}

# ---- arguments -----------------------------------------------------------------------------

ROLE=${1:-}
OUT=${2:-}
case $ROLE in
  -h | --help) usage ;;
  '' | client | exit | relay) ;;
  *) say "未知角色：$ROLE"; usage 2 ;;
esac
(($# <= 2)) || usage 2

say "${B}magicTunnel 配置生成${RST}"
note "回车接受 [方括号] 里的默认值。各项含义见 docs/configuration.md。"

section "角色"
if [[ -z $ROLE ]]; then
  choose ROLE "这个配置给哪种节点用？" 1 \
    "client|客户端 mt-client：用 TUN 接管本机流量，经路径送到出口" \
    "exit|出口 mt-server：流量从这里 NAT 出公网（需 root，也能当中继）" \
    "relay|中继 mt-server：只转发，不需要特权"
fi

case $ROLE in
  client) default_name=client1 ;;
  exit) default_name=exit1 ;;
  relay) default_name=relay1 ;;
esac
ask NAME "节点名（证书文件名 NAME.pem / NAME.key）" "$default_name" is_node_name \
  "字母、数字、. _ -，以字母或数字开头"

PLATFORM=linux
if [[ $ROLE == client ]]; then
  choose PLATFORM "客户端运行在哪个平台？" "$(platform_index "$(host_platform)")" \
    "linux|Linux" "macos|macOS" "windows|Windows"
fi

ask OUT "输出文件" "${OUT:-$NAME.toml}" is_nonempty

# ---- tls -----------------------------------------------------------------------------------

section "证书"
SEP=/
if [[ $PLATFORM == windows ]]; then
  SEP='\' default_dir='C:\ProgramData\magicTunnel\certs'
elif [[ -f certs/ca.pem ]]; then
  default_dir=certs
else
  default_dir=/etc/magictunnel/certs
fi
note "相对路径以运行 mt-server / mt-client 时的工作目录为准（systemd 下是 /），部署时用绝对路径。"
ask CERT_DIR "证书目录（含 ca.pem、$NAME.pem、$NAME.key）" "$default_dir" is_printable
CA="$CERT_DIR${SEP}ca.pem"
CERT="$CERT_DIR${SEP}$NAME.pem"
KEY="$CERT_DIR${SEP}$NAME.key"
MISSING=()
if [[ $PLATFORM != windows || $(host_platform) == windows ]]; then
  for f in "$CA" "$CERT" "$KEY"; do [[ -f $f ]] || MISSING+=("$f"); done
  ((${#MISSING[@]} == 0)) || warn "这些文件现在还不存在（可以之后再放）：${MISSING[*]}"
fi

# ---- obfs ----------------------------------------------------------------------------------

section "混淆密钥 obfs.xor_key"
note "整条路径上所有节点必须相同；泄漏后对手能认出流量是 QUIC，但读不到内容。"
default_src=1
[[ $ROLE == client ]] && default_src=3
choose KEY_SRC "密钥来源" "$default_src" \
  "new|随机生成新的（部署的第一个节点）" \
  "type|手动输入已有的" \
  "file|从已有的 magicTunnel 配置文件复制"
case $KEY_SRC in
  new)
    XOR_KEY=$(random_key)
    say "已生成：${GRN}$XOR_KEY${RST}"
    ;;
  type)
    ask XOR_KEY "xor_key" "" is_printable "不能为空，也不能含控制字符"
    ((${#XOR_KEY} >= 16)) || warn "密钥较短，建议用 32 字节以上的随机串"
    ;;
  file)
    while :; do
      ask KEY_FILE "配置文件路径" "" is_nonempty
      if XOR_KEY=$(read_xor_key "$KEY_FILE"); then
        say "已读取 $KEY_FILE 中的 xor_key（${#XOR_KEY} 个字符）"
        break
      fi
      say "${RED}  在 $KEY_FILE 里没有找到 xor_key${RST}"
    done
    ;;
esac

# ---- role specific -------------------------------------------------------------------------

if [[ $ROLE != client ]]; then
  section "监听"
  ask LISTEN "UDP 监听地址（IP:端口，0.0.0.0 为所有地址）" "0.0.0.0:4433" is_sockaddr \
    "形如 0.0.0.0:4433 或 [::]:4433"
fi

if [[ $ROLE == exit ]]; then
  section "出口"
  ask POOL "隧道地址池（第一个地址给出口自己，其余分给客户端）" "10.88.0.0/24" is_pool \
    "IPv4 网段，前缀不超过 /30，例如 10.88.0.0/24"
  plen=$((10#${POOL#*/}))
  net=$(($(ip2int "${POOL%/*}") & $(prefix_mask "$plen")))
  POOL="$(int2ip "$net")/$plen"
  say "地址池 $POOL，可容纳 $(((1 << (32 - plen)) - 3)) 个客户端"
  check_pool_overlap "$net" "$plen"
  ask TUN_NAME "出口 TUN 名" "mt0" is_linux_ifname "最多 15 个字符：字母、数字、. _ -"
  ask_num TUN_MTU "出口 TUN MTU" 1200 576 9000
  ask_num TUN_QUEUES "TUN 队列数（0 = 每 CPU 一个）" 0 0 64
fi

if [[ $ROLE == client ]]; then
  section "TUN"
  case $PLATFORM in
    macos)
      ask TUN_NAME "TUN 名（utun = 由内核挑空闲单元）" "utun" is_macos_utun "只能是 utun 或 utunN"
      ;;
    windows)
      ask TUN_NAME "TUN（Wintun 适配器）名" "mt0" is_win_ifname "不能为空或含 \\ / : \""
      ;;
    *)
      ask TUN_NAME "TUN 名" "mt0" is_linux_ifname "最多 15 个字符：字母、数字、. _ -"
      ;;
  esac
  note "MTU 是上限，客户端会降到整条路径能承载的值；1200 在任何能过 1312 字节 UDP 的路径上都放得下。"
  ask_num TUN_MTU "TUN MTU" 1200 576 9000

  section "路径"
  note "按顺序填写：第一跳是客户端直接连接的节点，最后一跳是出口，中间都是中继。"
  ask_num HOPS "一共几跳（1 = 直连出口，最多 8）" 1 1 8
  HOP_ADDR=() HOP_NAME=()
  for ((i = 1; i <= HOPS; i++)); do
    if ((i == HOPS)); then
      label=出口
    elif ((i == 1)); then
      label="首跳中继"
    else
      label=中继
    fi
    ask addr "第 $i 跳（$label）地址 IP:端口" "" is_hop_addr \
      "形如 203.0.113.20:4433，只能是 IP 不能是域名；省略端口则为 4433"
    is_ipv4 "$addr" && addr="$addr:4433"
    ask name "第 $i 跳 server_name（须在该节点证书的 SAN 里）" "" is_server_name \
      "证书里的 DNS 名或 IP，例如 exit1"
    HOP_ADDR+=("$addr")
    HOP_NAME+=("$name")
  done

  section "DNS"
  note "连上后系统改用这些 DNS 服务器（查询经隧道从出口发出），退出时恢复原设置；留空 = 不改系统 DNS。"
  ask DNS_SERVERS "DNS 服务器（IPv4，空格或逗号分隔，最多 3 个，例如 1.1.1.1 8.8.8.8）" "" is_dns_list \
    "最多 3 个单播 IPv4 地址，用空格或逗号分隔，或留空"
fi

# ---- advanced ------------------------------------------------------------------------------

LOG_LEVEL=info KEEPALIVE=10 IDLE=30 CONGESTION=cubic OFFLOAD=true
RECONNECT=true MAX_DELAY=30 METRICS_LISTEN='' LOG_INTERVAL=0

section "高级选项"
ask_yn ADVANCED "调整日志、QUIC、重连、指标等高级选项？（否则用默认值）" n
if [[ $ADVANCED == true ]]; then
  ask LOG_LEVEL "日志级别（tracing 过滤器，如 info 或 info,mt_server=debug）" info is_printable
  ask_num KEEPALIVE "QUIC 保活间隔（秒）" 10 1 599
  ask_num IDLE "QUIC 空闲超时（秒，须大于保活间隔；两端取较小值）" \
    $((KEEPALIVE < 30 ? 30 : KEEPALIVE + 1)) $((KEEPALIVE + 1)) 600
  choose CONGESTION "拥塞控制算法" 1 \
    "cubic|cubic（默认）" \
    "bbr|bbr（丢包多的长距离链路上通常更快，quinn 标为实验性）" \
    "newreno|newreno"
  if [[ $PLATFORM == linux && $ROLE != relay ]]; then
    ask_yn OFFLOAD "启用 TUN offload（TSO/GRO 超级包，内核不支持会自动退回）？" y
  fi
  if [[ $ROLE == client ]]; then
    ask_yn RECONNECT "断线后保留 TUN 与路由并自动重连？" y
    if [[ $RECONNECT == true ]]; then
      ask_num MAX_DELAY "重连退避上限（秒）" 30 1 3600
    fi
  fi
  ask METRICS_LISTEN "Prometheus 指标监听地址（留空不启用，建议 127.0.0.1:9100）" "" \
    is_opt_sockaddr "形如 127.0.0.1:9100，或留空"
  if [[ $METRICS_LISTEN == 0.0.0.0:* || $METRICS_LISTEN == \[::\]:* ]]; then
    warn "指标端点无认证，不要暴露到公网"
  fi
  ask_num LOG_INTERVAL "每隔多少秒在日志里记一行 stats（0 = 关闭）" 0 0 86400
fi

# ---- render --------------------------------------------------------------------------------

render() {
  local i ip list=''
  echo "# magicTunnel $ROLE config for $NAME, generated by scripts/gen-config.sh."
  echo "# All options: docs/configuration.md"
  [[ $ROLE == client ]] || printf 'listen = %s\n' "$(toml_str "$LISTEN")"
  echo
  echo "[log]"
  printf 'level = %s\n' "$(toml_str "$LOG_LEVEL")"
  echo
  echo "[tls]"
  printf 'ca = %s\n' "$(toml_str "$CA")"
  printf 'cert = %s\n' "$(toml_str "$CERT")"
  printf 'key = %s\n' "$(toml_str "$KEY")"
  echo
  echo "[obfs]"
  echo "# Must be identical on every node of a path."
  printf 'xor_key = %s\n' "$(toml_str "$XOR_KEY")"
  if [[ $ROLE == client ]]; then
    echo
    echo "[tun]"
    printf 'name = %s\n' "$(toml_str "$TUN_NAME")"
    echo "# Upper bound; the client lowers it to what the whole path carries."
    echo "mtu = $TUN_MTU"
    [[ $PLATFORM == linux ]] && echo "offload = $OFFLOAD"
  fi
  echo
  echo "[quic]"
  echo "keepalive_secs = $KEEPALIVE"
  echo "idle_timeout_secs = $IDLE"
  printf 'congestion = %s\n' "$(toml_str "$CONGESTION")"
  if [[ $ROLE == client ]]; then
    echo
    echo "[reconnect]"
    echo "enabled = $RECONNECT"
    echo "max_delay_secs = $MAX_DELAY"
  fi
  echo
  echo "[metrics]"
  [[ -n $METRICS_LISTEN ]] && printf 'listen = %s\n' "$(toml_str "$METRICS_LISTEN")"
  echo "log_interval_secs = $LOG_INTERVAL"
  if [[ $ROLE == exit ]]; then
    echo
    echo "[exit]"
    printf 'pool = %s\n' "$(toml_str "$POOL")"
    echo
    echo "[exit.tun]"
    printf 'name = %s\n' "$(toml_str "$TUN_NAME")"
    echo "mtu = $TUN_MTU"
    echo "offload = $OFFLOAD"
    echo "# 0 = one queue per CPU."
    echo "queues = $TUN_QUEUES"
  fi
  if [[ $ROLE == client ]]; then
    echo
    echo "[dns]"
    if [[ -n $DNS_SERVERS ]]; then
      echo "# Used while the tunnel is up; the previous DNS settings return when it stops."
      # shellcheck disable=SC2086
      for ip in ${DNS_SERVERS//,/ }; do list="$list${list:+, }\"$ip\""; done
      echo "servers = [$list]"
    else
      echo "# Unset: system DNS is left alone. Example: servers = [\"1.1.1.1\", \"8.8.8.8\"]"
    fi
    echo
    echo "# Full path, first hop first; the last hop is the exit."
    for ((i = 0; i < ${#HOP_ADDR[@]}; i++)); do
      echo "[[route]]"
      printf 'addr = %s\n' "$(toml_str "${HOP_ADDR[i]}")"
      printf 'server_name = %s\n' "$(toml_str "${HOP_NAME[i]}")"
      ((i + 1 == ${#HOP_ADDR[@]})) || echo
    done
  fi
}

CONFIG=$(render)

section "预览 $OUT"
say "$CONFIG"
say ""
if [[ -e $OUT ]]; then
  ask_yn OK "$OUT 已存在，覆盖？" n
else
  ask_yn OK "写入 $OUT？" y
fi
[[ $OK == true ]] || die "已取消，没有写入任何文件"

dir=$(dirname "$OUT")
mkdir -p "$dir"
tmp=$(mktemp "$dir/.gen-config.XXXXXX")
trap 'rm -f "$tmp"' EXIT
printf '%s\n' "$CONFIG" >"$tmp"
chmod 0600 "$tmp"
mv -f "$tmp" "$OUT"
trap - EXIT
say "${GRN}已写入 $OUT（权限 0600）${RST}"

# ---- next steps ----------------------------------------------------------------------------

section "下一步"
if ((${#MISSING[@]} > 0)); then
  if [[ $ROLE == client ]]; then
    say "- 签发证书：make certs CERT_ARGS=\"--client $NAME\"，再把 ca.pem、$NAME.pem、$NAME.key 放到 $CERT_DIR"
  else
    say "- 签发证书：make certs CERT_ARGS=\"--server $NAME=<本节点公网 IP>\"，再把 ca.pem、$NAME.pem、$NAME.key 放到 $CERT_DIR"
  fi
  say "  （ca.key 留在签发机器上，不要部署到节点）"
fi
case $ROLE in
  exit)
    say "- 运行：sudo mt-server -c $OUT"
    say "  或 systemd：sudo install -m 0600 $OUT /etc/magictunnel/$NAME.toml && sudo systemctl enable --now mt-server@$NAME"
    ;;
  relay)
    say "- 运行：mt-server -c $OUT（不需要 root）"
    say "  或 systemd：放到 /etc/magictunnel/$NAME.toml 后 sudo systemctl enable --now mt-relay@$NAME"
    say "  mt-relay@ 以动态用户运行，配置和私钥须对它可读（见 deploy/systemd/mt-relay@.service）"
    ;;
  client)
    case $PLATFORM in
      linux)
        say "- 运行：sudo mt-client -c $OUT"
        say "  或 systemd：sudo install -m 0600 $OUT /etc/magictunnel/client.toml && sudo systemctl enable --now mt-client"
        ;;
      macos) say "- 运行：sudo mt-client -c $OUT" ;;
      windows) say "- 运行：在管理员终端执行 mt-client.exe -c $OUT（wintun.dll 放在 exe 同目录）" ;;
    esac
    say "- 路径上每个节点的 server_name 须在其证书 SAN 里，所有节点的证书出自同一个 CA"
    ;;
esac
if [[ $KEY_SRC == new ]]; then
  say "- 给其他节点生成配置时，密钥来源选「从已有的 magicTunnel 配置文件复制」并指向 $OUT，"
  say "  或手动输入同一个 xor_key"
fi
