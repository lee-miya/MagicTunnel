# magicTunnel build, test, install and packaging entry points. `make help` lists the targets.
#
#   make                                     release build of mt-server + mt-client
#   make PROFILE=dev                         debug build
#   make setup [TARGET=...]                  install the toolchain (scripts/setup-toolchain.sh)
#   make TARGET=x86_64-unknown-linux-gnu     cross build (links with zig; ZIG=/path/to/zig)
#   make dist TARGET=x86_64-unknown-linux-musl
#   sudo make install PREFIX=/usr            or DESTDIR=/tmp/pkg for staging
#
# Every variable below can be overridden on the command line or from the environment.

SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := build
MAKEFLAGS += --no-print-directory

# rustup installs into ~/.cargo/bin, which is often not on PATH (and $(shell) in make < 4.4
# ignores exported variables, so the tools are located explicitly).
CARGO_BIN := $(or $(CARGO_HOME),$(HOME)/.cargo)/bin
export PATH := $(CARGO_BIN):$(PATH)
CARGO ?= $(firstword $(wildcard $(CARGO_BIN)/cargo) cargo)
RUSTC ?= $(firstword $(wildcard $(CARGO_BIN)/rustc) rustc)

# ---- build ---------------------------------------------------------------------------------

PROFILE    ?= release
TARGET     ?=
TARGET_DIR ?= $(or $(CARGO_TARGET_DIR),target)

PROFILE_DIR := $(if $(filter dev test,$(PROFILE)),debug,$(PROFILE))
OUT_DIR     := $(TARGET_DIR)/$(if $(TARGET),$(TARGET)/)$(PROFILE_DIR)
CARGO_FLAGS := --profile $(PROFILE) $(if $(TARGET),--target $(TARGET))

HOST    := $(shell $(RUSTC) -vV 2>/dev/null | sed -n 's/^host: //p')
TRIPLE  := $(or $(TARGET),$(HOST))
VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)
EXE     := $(if $(findstring windows,$(TRIPLE)),.exe)
# mt-server is Linux-only; other platforms get just the client.
BINS    ?= $(if $(findstring linux,$(TRIPLE)),mt-server mt-client,mt-client)

# Cross builds to another Linux triple use `zig cc` (scripts/zig/) as ring's C compiler and as
# the linker, unless CC_<triple> / CARGO_TARGET_<TRIPLE>_LINKER are already set.
# gnu targets link against ZIG_GLIBC's symbol versions, so the binary runs on that glibc or newer.
# Without zig, a same-CPU target on a Linux host (e.g. musl on a gnu host) builds with the system
# cc (and rustc's bundled musl startup files and libc); CROSS_CC marks targets that cannot.
# ZIG defaults to the one `make setup` installs, then to zig on PATH.
ZIG_HOME  ?= $(or $(XDG_DATA_HOME),$(HOME)/.local/share)/magictunnel
ZIG       ?= $(firstword $(wildcard $(ZIG_HOME)/zig/zig) $(shell command -v zig 2>/dev/null))
ZIG_GLIBC ?= 2.17
CROSS_LINUX := $(if $(and $(TARGET),$(findstring -linux-,$(TARGET))),$(filter-out $(HOST),$(TARGET)))
SAME_CPU    := $(and $(findstring -linux-,$(HOST)),$(filter $(firstword $(subst -, ,$(HOST))),$(firstword $(subst -, ,$(TARGET)))))
CROSS_CC    := $(if $(CROSS_LINUX),$(if $(SAME_CPU),,yes))
TARGET_ENV  := $(subst -,_,$(TARGET))
TARGET_ENV_UPPER := $(shell echo '$(TARGET_ENV)' | tr a-z A-Z)
ifneq ($(and $(CROSS_LINUX),$(ZIG)),)
ZIG_ABI := $(lastword $(subst -, ,$(TARGET)))
export MT_ZIG := $(abspath $(ZIG))
export MT_ZIG_TARGET := $(firstword $(subst -, ,$(TARGET)))-linux-$(ZIG_ABI)$(if $(filter gnu%,$(ZIG_ABI)),.$(ZIG_GLIBC))
export CC_$(TARGET_ENV) ?= $(CURDIR)/scripts/zig/cc
export AR_$(TARGET_ENV) ?= $(CURDIR)/scripts/zig/ar
export CARGO_TARGET_$(TARGET_ENV_UPPER)_LINKER ?= $(CURDIR)/scripts/zig/cc
else ifneq ($(and $(CROSS_LINUX),$(SAME_CPU)),)
# cc-rs would insist on <arch>-linux-musl-gcc / musl-gcc; ring's C code builds fine with the host cc.
export CC_$(TARGET_ENV) ?= cc
export AR_$(TARGET_ENV) ?= ar
endif

# ---- install -------------------------------------------------------------------------------

PREFIX     ?= /usr/local
BINDIR     ?= $(PREFIX)/bin
SYSCONFDIR ?= /etc
CONFDIR    ?= $(SYSCONFDIR)/magictunnel
UNITDIR    ?= $(SYSCONFDIR)/systemd/system
SYSCTLDIR  ?= $(SYSCONFDIR)/sysctl.d
DESTDIR    ?=

# ---- dist / tests --------------------------------------------------------------------------

DIST_DIR  ?= dist
DIST_NAME := magictunnel-$(VERSION)-$(TRIPLE)
SHA256SUM := $(if $(shell command -v sha256sum 2>/dev/null),sha256sum,shasum -a 256)

# Extra options for scripts/setup-toolchain.sh, e.g. SETUP_ARGS="--e2e --yes".
SETUP_ARGS ?=

# Extra arguments for scripts/gen-certs.sh, e.g. CERT_ARGS="--server exit1=203.0.113.20".
CERT_ARGS ?=
# Targets for `make cross-check`; each needs a C compiler for ring (CC_<triple>, AR_<triple>).
CROSS_TARGETS ?= x86_64-pc-windows-gnu aarch64-apple-darwin

.PHONY: help setup doctor build all debug release check clippy fmt fmt-check test ci \
        e2e e2e-single e2e-multi e2e-resilience perf certs config cross-check \
        install uninstall dist clean

help: ## Show this help
	@echo "magicTunnel $(VERSION)  (target: $(TRIPLE), profile: $(PROFILE), out: $(OUT_DIR))"
	@echo
	@grep -hE '^[a-zA-Z0-9_-]+:.*## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*## "} {printf "  %-15s %s\n", $$1, $$2}'
	@echo
	@echo "Variables: PROFILE TARGET TARGET_DIR BINS ZIG ZIG_HOME ZIG_GLIBC SETUP_ARGS PREFIX DESTDIR CONFDIR"
	@echo "           CERT_ARGS CROSS_TARGETS"

setup: ## Install the build toolchain for this host; TARGET=<triple>, SETUP_ARGS="--e2e --yes"
	scripts/setup-toolchain.sh $(addprefix --target ,$(TARGET)) $(SETUP_ARGS)

doctor: ## Report what `make setup` would install (same options), change nothing
	scripts/setup-toolchain.sh --check $(addprefix --target ,$(TARGET)) $(SETUP_ARGS)

build: ## (default) Build mt-server/mt-client; PROFILE=dev for debug, TARGET=<triple> to cross
	@if [[ -n "$(TARGET)" ]] && command -v rustup >/dev/null \
	    && ! rustup target list --installed | grep -qx '$(TARGET)'; then \
	  echo "Rust target $(TARGET) is not installed: make setup TARGET=$(TARGET)" >&2; exit 1; \
	fi
	@if [[ -n "$(CROSS_CC)" && -z "$(ZIG)" && -z "$${CARGO_TARGET_$(TARGET_ENV_UPPER)_LINKER:-}" ]]; then \
	  echo "Cross-compiling to $(TARGET) needs zig: make setup TARGET=$(TARGET) (or pass ZIG=/path/to/zig)," >&2; \
	  echo "or set CC_$(TARGET_ENV) and CARGO_TARGET_$(TARGET_ENV_UPPER)_LINKER." >&2; exit 1; \
	fi
	$(CARGO) build $(CARGO_FLAGS) $(addprefix --bin ,$(BINS))
	@for b in $(BINS); do echo "  -> $(OUT_DIR)/$$b$(EXE)"; done

all: build

release: ## Release build of every workspace binary
	$(CARGO) build --release --workspace --bins

debug: ## Debug build of every workspace binary (what the e2e scripts run)
	$(CARGO) build --workspace --bins

check: ## cargo check the whole workspace
	$(CARGO) check --workspace --all-targets

clippy: ## Lint the workspace, warnings are errors
	$(CARGO) clippy --workspace --all-targets -- -D warnings

fmt: ## Format all code
	$(CARGO) fmt --all

fmt-check: ## Fail if code is not formatted
	$(CARGO) fmt --all -- --check

test: ## Unit tests + loopback QUIC tests
	$(CARGO) test --workspace

ci: fmt-check clippy test ## fmt-check + clippy + test

cross-check: ## clippy the client for CROSS_TARGETS (macOS/Windows; type-check only)
	@for t in $(CROSS_TARGETS); do \
	  echo "== $$t"; \
	  $(CARGO) clippy -p magictunnel-client -p magictunnel-tunio --all-targets --target $$t -- -D warnings; \
	done

# The e2e scripts need /dev/net/tun and unprivileged user namespaces; no root.
e2e-single: debug ## End-to-end: single hop (~20s)
	scripts/e2e/single-hop.sh $(TARGET_DIR)/debug

e2e-multi: debug ## End-to-end: 2/3/8 hops, per-hop isolation (~30s)
	scripts/e2e/multi-hop.sh $(TARGET_DIR)/debug

e2e-resilience: debug ## End-to-end: reconnect, metrics, PMTU (~35s)
	scripts/e2e/resilience.sh $(TARGET_DIR)/debug

e2e: debug ## All end-to-end suites
	scripts/e2e/single-hop.sh $(TARGET_DIR)/debug
	scripts/e2e/multi-hop.sh $(TARGET_DIR)/debug
	scripts/e2e/resilience.sh $(TARGET_DIR)/debug

perf: release ## Throughput / latency measurement (DURATION, SHAPE, ... see perf.sh)
	scripts/e2e/perf.sh $(TARGET_DIR)/release

certs: ## Dev CA + node certificates into ./certs (CERT_ARGS=... for custom nodes)
	scripts/gen-certs.sh $(CERT_ARGS)

config: ## Interactively write a client/exit/relay config file
	@scripts/gen-config.sh

install: ## Install binaries, example configs, systemd units, sysctl file (Linux; build first)
	@[[ "$(TRIPLE)" == *linux* ]] || { echo "install is Linux-only (target $(TRIPLE))" >&2; exit 1; }
	@for b in $(BINS); do \
	  [[ -x "$(OUT_DIR)/$$b" ]] || { echo "missing $(OUT_DIR)/$$b; run 'make' first (not as root)" >&2; exit 1; }; \
	done
	install -d -m 0755 "$(DESTDIR)$(BINDIR)"
	install -m 0755 $(addprefix $(OUT_DIR)/,$(BINS)) "$(DESTDIR)$(BINDIR)/"
	install -d -m 0750 "$(DESTDIR)$(CONFDIR)" "$(DESTDIR)$(CONFDIR)/certs"
	install -m 0640 config/*.example.toml "$(DESTDIR)$(CONFDIR)/"
	install -d -m 0755 "$(DESTDIR)$(UNITDIR)" "$(DESTDIR)$(SYSCTLDIR)"
	@for u in deploy/systemd/*.service; do \
	  sed -e 's|/usr/local/bin/|$(BINDIR)/|g' -e 's|/etc/magictunnel/|$(CONFDIR)/|g' "$$u" \
	    > "$(DESTDIR)$(UNITDIR)/$${u##*/}"; \
	  chmod 0644 "$(DESTDIR)$(UNITDIR)/$${u##*/}"; \
	  echo "  unit -> $(DESTDIR)$(UNITDIR)/$${u##*/}"; \
	done
	install -m 0644 deploy/sysctl/99-magictunnel.conf "$(DESTDIR)$(SYSCTLDIR)/"
	@echo
	@echo "Next: copy a config to $(CONFDIR)/<name>.toml and certs to $(CONFDIR)/certs/, then"
	@echo "  systemctl daemon-reload && sysctl --system"
	@echo "  systemctl enable --now mt-server@<name> | mt-relay@<name> | mt-client"

uninstall: ## Remove what install put in place (keeps CONFDIR: configs and keys)
	rm -f "$(DESTDIR)$(BINDIR)/mt-server" "$(DESTDIR)$(BINDIR)/mt-client"
	@for u in deploy/systemd/*.service; do rm -fv "$(DESTDIR)$(UNITDIR)/$${u##*/}"; done
	rm -f "$(DESTDIR)$(SYSCTLDIR)/99-magictunnel.conf"
	@echo "Kept $(DESTDIR)$(CONFDIR); remove it by hand if no longer needed."

dist: build ## Tarball of binaries + configs + deploy files + docs into dist/
	rm -rf "$(DIST_DIR)/$(DIST_NAME)"
	install -d "$(DIST_DIR)/$(DIST_NAME)/bin"
	install -m 0755 $(addprefix $(OUT_DIR)/,$(addsuffix $(EXE),$(BINS))) "$(DIST_DIR)/$(DIST_NAME)/bin/"
	cp -r config deploy docs README.md "$(DIST_DIR)/$(DIST_NAME)/"
	tar -C "$(DIST_DIR)" -czf "$(DIST_DIR)/$(DIST_NAME).tar.gz" "$(DIST_NAME)"
	cd "$(DIST_DIR)" && $(SHA256SUM) "$(DIST_NAME).tar.gz" > "$(DIST_NAME).tar.gz.sha256"
	rm -rf "$(DIST_DIR)/$(DIST_NAME)"
	@echo "  -> $(DIST_DIR)/$(DIST_NAME).tar.gz"

clean: ## Remove build output and dist/
	$(CARGO) clean
	rm -rf "$(DIST_DIR)"
