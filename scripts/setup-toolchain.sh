#!/bin/sh
# Install what `make` needs to build magicTunnel on this host (Linux or macOS): system packages
# (C compiler, GNU make, curl, ...), rustup with the toolchain pinned in rust-toolchain.toml,
# rustup targets, zig for cross-architecture Linux targets, and optionally the e2e test tools.
# Re-runnable: whatever is already present is left alone. POSIX sh, so it runs before bash is
# installed (Alpine) and on macOS's /bin/sh.
#
#   scripts/setup-toolchain.sh [--check] [--target TRIPLE]... [--e2e] [--yes]
set -eu

ZIG_VERSION=0.14.1
ROOT=$(cd "$(dirname "$0")/.." && pwd)
CARGO_BIN=${CARGO_HOME:-$HOME/.cargo}/bin
# Must match ZIG_HOME in the Makefile, which picks up $ZIG_HOME/zig/zig.
ZIG_HOME=${ZIG_HOME:-${XDG_DATA_HOME:-$HOME/.local/share}/magictunnel}
ZIG=$ZIG_HOME/zig/zig

usage() {
  cat <<EOF
usage: scripts/setup-toolchain.sh [options]   (also: make setup / make doctor)

  --check           only report what is missing; install nothing (exit 1 if anything is)
  --target TRIPLE   also install the rustup target, plus zig when TRIPLE is a Linux target of
                    another CPU (or the host is macOS); repeatable
  --e2e             also install the end-to-end test tools (Linux)
  -y, --yes         install system packages without asking
  -h, --help        this help

System packages go through apt-get/dnf/yum/pacman/apk (sudo unless root) or Homebrew;
rustup goes to ${CARGO_HOME:-~/.cargo}, zig $ZIG_VERSION to $ZIG_HOME/zig.
Nothing is added to shell profiles: the Makefile finds both locations by itself.
EOF
}

step() { printf '\n== %s\n' "$*"; }
ok() { printf '  [ok]      %s\n' "$*"; }
note() { printf '  [note]    %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
# Something setup installs: reported in --check mode, then installed (or the script dies).
miss() {
  if [ "$CHECK" = 1 ]; then printf '  [missing] %s\n' "$*"; else printf '  [install] %s\n' "$*"; fi
  MISSING=$((MISSING + 1))
}
# Something setup cannot fix (kernel settings): always fails the run.
broken() { printf '  [missing] %s\n' "$*"; MISSING=$((MISSING + 1)); BROKEN=$((BROKEN + 1)); }

CHECK=0 E2E=0 YES=0 TARGETS="" MISSING=0 BROKEN=0 PATH_ORIG=$PATH
while [ $# -gt 0 ]; do
  case $1 in
    --check) CHECK=1 ;;
    --e2e) E2E=1 ;;
    -y | --yes) YES=1 ;;
    --target) [ $# -ge 2 ] || die "--target needs a triple"; TARGETS="$TARGETS $2"; shift ;;
    --target=*) TARGETS="$TARGETS ${1#--target=}" ;;
    -h | --help) usage; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
  shift
done

# ---- host ------------------------------------------------------------------------------------

case $(uname -s) in
  Linux) OS=linux ;;
  Darwin) OS=macos ;;
  *) die "unsupported OS $(uname -s): Linux and macOS only" ;;
esac
ARCH=$(uname -m)
case $ARCH in arm64) ARCH=aarch64 ;; amd64) ARCH=x86_64 ;; esac

PKG=""
if [ "$OS" = macos ]; then
  command -v brew >/dev/null 2>&1 && PKG=brew
else
  for p in apt-get dnf yum pacman apk; do
    if command -v "$p" >/dev/null 2>&1; then PKG=$p; break; fi
  done
fi

SUDO=""
if [ "$PKG" != brew ] && [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null 2>&1 && SUDO=sudo
fi

# Same rule as CROSS_CC in the Makefile: Linux targets the host's cc cannot produce.
needs_zig() {
  case $1 in *-linux-*) ;; *) return 1 ;; esac
  [ "$OS" != linux ] || [ "${1%%-*}" != "$ARCH" ]
}
NEED_ZIG=0
for t in $TARGETS; do
  if needs_zig "$t"; then NEED_ZIG=1; fi
done

# iptables & co. live in /usr/sbin, which is often not on a normal user's PATH.
have() { command -v "$1" >/dev/null 2>&1 || [ -x "/usr/sbin/$1" ] || [ -x "/sbin/$1" ]; }

# Prints the first GNU make >= 3.82 (.SHELLFLAGS) on PATH.
gnu_make() {
  for m in make gmake; do
    v=$("$m" --version 2>/dev/null | sed -n '1s/^GNU Make \([0-9]*\)\.\([0-9]*\).*/\1 \2/p')
    [ -n "$v" ] || continue
    # shellcheck disable=SC2086 # "major minor"
    set -- $v
    if [ "$1" -gt 3 ] || { [ "$1" -eq 3 ] && [ "$2" -ge 82 ]; }; then
      echo "$m"
      return 0
    fi
  done
  return 1
}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1
}

# Package name(s) providing a tool, for $PKG.
pkg_for() {
  case $PKG:$1 in
    apt-get:cc) echo build-essential ;;
    apt-get:curl) echo curl ca-certificates ;;
    apt-get:xz) echo xz-utils ;;
    apt-get:ping) echo iputils-ping ;;
    dnf:cc | yum:cc | pacman:cc) echo gcc ;;
    dnf:ip | yum:ip) echo iproute ;;
    pacman:python3) echo python ;;
    apk:cc) echo build-base ;;
    brew:make) echo make ;;
    *:ip) echo iproute2 ;;
    *:ping) echo iputils ;;
    *:nsenter | *:unshare) echo util-linux ;;
    *) echo "$1" ;;
  esac
}

confirm() {
  [ "$YES" = 1 ] && return 0
  [ -t 0 ] || die "not a terminal: re-run with --yes, or run the command above yourself"
  printf '  Run it? [Y/n] '
  read -r answer
  case $answer in "" | [Yy]*) return 0 ;; *) return 1 ;; esac
}

install_packages() {
  case $PKG in
    apt-get) set -- $SUDO apt-get install -y --no-install-recommends "$@" ;;
    dnf | yum) set -- $SUDO "$PKG" install -y "$@" ;;
    pacman) set -- $SUDO pacman -S --needed --noconfirm "$@" ;;
    apk) set -- $SUDO apk add --no-cache "$@" ;;
    brew) set -- brew install "$@" ;;
    *) die "no supported package manager found; install these yourself: $*" ;;
  esac
  printf '  %s\n' "$*"
  [ "$CHECK" = 1 ] && return 0
  confirm || die "cancelled"
  if [ -z "$SUDO" ] && [ "$PKG" != brew ] && [ "$(id -u)" -ne 0 ]; then
    die "need root (or sudo) to install system packages"
  fi
  if [ "$PKG" = apt-get ]; then $SUDO apt-get update; fi
  "$@"
}

printf 'magicTunnel toolchain setup: %s/%s, package manager: %s%s\n' "$OS" "$ARCH" "${PKG:-none}" \
  "$([ "$CHECK" = 1 ] && echo ', check only')"

# ---- system packages -------------------------------------------------------------------------

step "System packages"
WANT=""   # tools to install, as pkg_for names
if [ "$OS" = macos ]; then
  if xcode-select -p >/dev/null 2>&1; then
    ok "Xcode Command Line Tools ($(xcode-select -p))"
  else
    miss "Xcode Command Line Tools (C compiler, linker, git)"
    if [ "$CHECK" = 0 ]; then
      xcode-select --install || true
      die "finish the Command Line Tools installer, then re-run this script"
    fi
  fi
fi

check_tool() { # tool [description]
  if have "$1"; then ok "${2:-$1}"; else miss "${2:-$1}"; WANT="$WANT $1"; fi
}
if [ "$OS" = linux ]; then
  check_tool cc "cc (C compiler for ring, and the linker)"
  check_tool bash "bash (Makefile recipes)"
  check_tool curl
  check_tool tar
  if [ "$NEED_ZIG" = 1 ] && ! [ -x "$ZIG" ]; then check_tool xz "xz (unpacks zig)"; fi
fi
if GMAKE=$(gnu_make); then
  ok "GNU make >= 3.82 ($GMAKE)"
else
  GMAKE="make"
  [ "$OS" = macos ] && GMAKE="gmake"   # Homebrew's GNU make; Apple's make is 3.81
  miss "GNU make >= 3.82"
  WANT="$WANT make"
fi
if [ "$E2E" = 1 ]; then
  if [ "$OS" = linux ]; then
    for t in ip iptables python3 ping nsenter unshare timeout; do check_tool "$t"; done
  else
    note "--e2e: the end-to-end suites need Linux network namespaces; skipped on macOS"
  fi
fi

if [ -n "$WANT" ] && [ -z "$PKG" ]; then
  [ "$CHECK" = 1 ] || die "no supported package manager found; install these yourself:$WANT"
  note "no supported package manager found; install these yourself:$WANT"
elif [ -n "$WANT" ]; then
  pkgs=""
  for t in $WANT; do
    for p in $(pkg_for "$t"); do
      case " $pkgs " in *" $p "*) ;; *) pkgs="$pkgs $p" ;; esac
    done
  done
  # shellcheck disable=SC2086 # one argument per package
  install_packages $pkgs
  if [ "$CHECK" = 0 ]; then
    for t in $WANT; do
      case $t in
        make) GMAKE=$(gnu_make) || die "GNU make >= 3.82 still not found" ;;
        *) have "$t" || die "$t still not found after installing packages" ;;
      esac
    done
  fi
fi

# ---- Rust ------------------------------------------------------------------------------------

step "Rust"
PATH=$CARGO_BIN:$PATH
export PATH
CHANNEL=$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml")
[ -n "$CHANNEL" ] || die "no channel in $ROOT/rust-toolchain.toml"

if command -v rustup >/dev/null 2>&1; then
  ok "rustup ($(rustup --version 2>/dev/null | head -n1))"
else
  miss "rustup"
  if [ "$CHECK" = 0 ]; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --no-modify-path --profile minimal --default-toolchain none
  fi
fi

if command -v rustup >/dev/null 2>&1; then
  if rustup toolchain list 2>/dev/null | cut -d' ' -f1 | grep -q "^$CHANNEL-"; then
    ok "toolchain $CHANNEL (rust-toolchain.toml)"
  else
    miss "toolchain $CHANNEL (rust-toolchain.toml)"
    [ "$CHECK" = 1 ] || rustup toolchain install "$CHANNEL" --profile minimal
  fi
  # A fresh rustup has no default; give cargo/rustc outside this checkout one too.
  if ! rustup default >/dev/null 2>&1; then
    if [ "$CHECK" = 1 ]; then
      note "no default toolchain; setup would make $CHANNEL the default"
    else
      rustup default "$CHANNEL"
    fi
  fi

  installed() { rustup "$1" list --installed --toolchain "$CHANNEL" 2>/dev/null; }
  for c in clippy rustfmt; do
    if installed component | grep -q "^$c"; then
      ok "component $c"
    else
      miss "component $c"
      [ "$CHECK" = 1 ] || rustup component add --toolchain "$CHANNEL" "$c"
    fi
  done
  for t in $TARGETS; do
    if installed target | grep -qx "$t"; then
      ok "target $t"
    else
      miss "target $t"
      [ "$CHECK" = 1 ] || rustup target add --toolchain "$CHANNEL" "$t"
    fi
    case $t in
      *-linux-*) ;;
      *) note "$t: \`make cross-check\` only (ring needs CC_$(echo "$t" | tr - _) for it)" ;;
    esac
  done
else
  miss "toolchain $CHANNEL, components, targets (need rustup first)"
fi

# ---- zig -------------------------------------------------------------------------------------

if [ "$NEED_ZIG" = 1 ]; then
  step "zig $ZIG_VERSION (C compiler + linker for cross-architecture Linux targets)"
  if [ -x "$ZIG" ] && [ "$("$ZIG" version 2>/dev/null)" = "$ZIG_VERSION" ]; then
    ok "zig $ZIG_VERSION ($ZIG)"
  else
    miss "zig $ZIG_VERSION at $ZIG"
    case $ARCH-$OS in
      x86_64-linux) sum=24aeeec8af16c381934a6cd7d95c807a8cb2cf7df9fa40d359aa884195c4716c ;;
      aarch64-linux) sum=f7a654acc967864f7a050ddacfaa778c7504a0eca8d2b678839c21eea47c992b ;;
      x86_64-macos) sum=b0f8bdfb9035783db58dd6c19d7dea89892acc3814421853e5752fe4573e5f43 ;;
      aarch64-macos) sum=39f3dc5e79c22088ce878edc821dedb4ca5a1cd9f5ef915e9b3cc3053e8faefa ;;
      *) die "no zig $ZIG_VERSION build for $ARCH-$OS; install zig yourself and pass ZIG=/path/to/zig" ;;
    esac
    if [ "$CHECK" = 0 ]; then
      name=zig-$ARCH-$OS-$ZIG_VERSION
      tmp=$ZIG_HOME/.download.$$
      trap 'rm -rf "$tmp"' EXIT
      mkdir -p "$tmp"
      url=https://ziglang.org/download/$ZIG_VERSION/$name.tar.xz
      note "downloading $url"
      curl --proto '=https' --tlsv1.2 -fsSL -o "$tmp/$name.tar.xz" "$url"
      got=$(sha256 "$tmp/$name.tar.xz")
      [ "$got" = "$sum" ] || die "zig tarball sha256 mismatch: got $got, want $sum"
      tar -xJf "$tmp/$name.tar.xz" -C "$tmp"
      rm -rf "$ZIG_HOME/zig"
      mv "$tmp/$name" "$ZIG_HOME/zig"
      ok "installed zig $("$ZIG" version) to $ZIG"
    fi
  fi
fi

# ---- e2e kernel features ---------------------------------------------------------------------

if [ "$E2E" = 1 ] && [ "$OS" = linux ]; then
  step "Kernel features for the e2e suites (not changed by this script)"
  if [ -c /dev/net/tun ]; then ok "/dev/net/tun"; else broken "/dev/net/tun (modprobe tun)"; fi
  if have unshare && unshare -Urn true 2>/dev/null; then
    ok "unprivileged user + network namespaces"
  else
    broken "unprivileged user namespaces (unshare -Urn)"
    note "Debian: sysctl kernel.unprivileged_userns_clone=1; Ubuntu 24.04+:" \
      "sysctl kernel.apparmor_restrict_unprivileged_userns=0; also check user.max_user_namespaces"
  fi
fi

# ---- summary ---------------------------------------------------------------------------------

step "Summary"
if [ "$CHECK" = 1 ] && [ "$MISSING" -gt 0 ]; then
  echo "  $MISSING item(s) missing; run scripts/setup-toolchain.sh (or make setup) with the same options."
  exit 1
fi
if [ "$BROKEN" -gt 0 ]; then
  echo "  $BROKEN item(s) need manual attention; see [missing] above."
  exit 1
fi
echo "  Ready. Build with:"
echo "    $GMAKE"
for t in $TARGETS; do
  case $t in *-linux-*) echo "    $GMAKE TARGET=$t" ;; esac
done
if ! printf '%s' ":$PATH_ORIG:" | grep -q ":$CARGO_BIN:"; then
  echo "  To run cargo/rustc by hand, add rustup to PATH: export PATH=\"$CARGO_BIN:\$PATH\""
fi
