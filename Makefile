# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Jason Ricca

# CambiOS Makefile - Build kernel and Limine bootable ISO
#
# Usage:
#   make all     - Build kernel + ISO
#   make run     - Build + run in QEMU (BIOS)
#   make run-uefi - Build + run in QEMU (UEFI)
#   make clean   - Remove build artifacts
#   make test    - Run unit tests
#
# Signing modes:
#   make run                        # YubiKey signing (default, requires CAMBIO_SIGN_PIN)
#   make run SIGN_MODE=seed         # Seed-based signing (CI/testing)
#   CAMBIO_SIGN_PIN=123456 make run # YubiKey with PIN via env var

# Force bash for all recipes. GNU make defaults SHELL to /bin/sh, which on Linux
# is dash — and dash's printf does NOT support `\xHH` hex escapes. Every
# user-crate rule builds CARGO_ENCODED_RUSTFLAGS via `printf '%s\x1f%s' ...` to
# join rustflags with the 0x1F separator byte; under dash that emits the literal
# text "\x1f", cargo then passes the whole rustflags blob as one unsplit linker
# arg, and the linker-script path mangles ("cannot find linker script
# link.ld\x1f..."). macOS /bin/sh is bash, so this was invisible until the Linux
# boot-smoke CI runner hit it.
SHELL := /bin/bash

KERNEL := target/x86_64-unknown-none/release/cambios_microkernel
ISO := cambios.iso
LIMINE_DIR := $(HOME)/.cache/cambios/limine
LIMINE_BRANCH := v8.x-binary
LIMINE_REPO := https://github.com/limine-bootloader/limine.git

# =============================================================================
# Build lists
#
# Every per-architecture rule, image recipe and gate below is generated from
# these lists. Nothing else in this file spells out the set of architectures,
# of user crates, or of proof crates. `make print-<VAR>` prints any variable
# (the lints read the lists that way).
# =============================================================================

# The architectures are the backend directories under src/arch/.
ARCHES := $(sort $(patsubst src/arch/%/mod.rs,%,$(wildcard src/arch/*/mod.rs)))

# Per architecture: Rust target triple, make-target suffix, the user crates'
# linker script, and the `--target` argument user crates are built with.
# x86_64 user crates pass no `--target`; the repository's .cargo/config.toml
# default applies.
TRIPLE_x86_64  := x86_64-unknown-none
TRIPLE_aarch64 := aarch64-unknown-none
TRIPLE_riscv64 := riscv64gc-unknown-none-elf
SUFFIX_x86_64  :=
SUFFIX_aarch64 := -aarch64
SUFFIX_riscv64 := -riscv64
USER_LINK_x86_64  := link.ld
USER_LINK_aarch64 := link-aarch64.ld
USER_LINK_riscv64 := link-riscv64.ld
USER_TARGET_ARG_x86_64  :=
USER_TARGET_ARG_aarch64 := --target $(TRIPLE_aarch64)
USER_TARGET_ARG_riscv64 := --target $(TRIPLE_riscv64)

# A backend directory with no entries above stops the build here, instead of
# generating rules with an empty triple.
$(foreach a,$(ARCHES),$(if $(TRIPLE_$(a)),,$(error src/arch/$(a)/ exists but this Makefile has no TRIPLE_$(a): add the per-architecture entries above)))

# User crates staged into each architecture's boot image, in the order the
# image recipe copies them (for riscv64 that is the initrd's module order).
# `init` is staged by its own lines in each recipe and is not listed.
STAGE_x86_64 := policy-service key-store-service fs-service virtio-blk nvme \
	usb-host ccid virtio-net udp-stack shell compositor scanout-virtio-gpu \
	scanout-limine virtio-input terminal-window ping sprouty tree worm \
	hello-window faultme audit-tail fde-mount
STAGE_aarch64 := policy-service key-store-service fs-service virtio-blk \
	fde-mount usb-host ccid virtio-net udp-stack scanout-virtio-gpu \
	virtio-input compositor terminal-window tree hello-window faultme worm \
	ping sprouty shell audit-tail
STAGE_riscv64 := policy-service key-store-service fs-service virtio-blk \
	fde-mount usb-host ccid virtio-net udp-stack audit-tail shell faultme

# User crates that build for the architecture but are not in its image.
#
# i219-net (x86_64, aarch64): the Intel I219-LM driver. No manifest.toml
# entry names it, so no image carries it.
# Revisit when: a manifest.toml entry names i219-net.
#
# scanout-limine (aarch64): omitted on purpose; limine-aarch64.conf gives
# the reason and its own trigger.
#
# The riscv64 display stack and the apps that need it: they build, but the
# riscv64 initrd ships no display stack.
# Revisit when: compositor + scanout-virtio-gpu + virtio-input ship in the
# riscv64 initrd.
UNSTAGED_x86_64  := i219-net
UNSTAGED_aarch64 := i219-net scanout-limine
UNSTAGED_riscv64 := scanout-virtio-gpu virtio-input compositor hello-window \
	tree worm ping sprouty terminal-window

# Every user crate with a build rule for the architecture.
$(foreach a,$(ARCHES),$(eval CRATES_$(a) := init $$(STAGE_$(a)) $$(UNSTAGED_$(a))))

# Image profiles: the values a manifest.toml `profile` tag may take.
# `default` is the QEMU image (`make iso`); `PROFILE=` picks one of the
# bare-metal ones for img-usb.
PROFILES := default headless framebuffer-fallback

# The proof crates are the *-proofs directories under verification/.
PROOF_CRATES := $(sort $(patsubst verification/%/Cargo.toml,%,$(wildcard verification/*-proofs/Cargo.toml)))

# A newline, for recipes that expand a list into one command per line.
define NL


endef

# `make print-ARCHES`, `make print-CRATES_aarch64`, ...
print-%:
	@echo '$($*)'

# Hand-assembled test binary (x86_64). The Rust user crates are listed in
# "Build lists" below.
USER_ELF := user/hello.elf
USER_SRC := user/hello.S
USER_LD  := user/user.ld

# Host-tool build target + headless QEMU display (CI overrides). HOST_TARGET:
# the host-side tools (sign-elf, mkinitrd, ...) are native binaries, not
# bare-metal; each overrides the parent .cargo/config.toml bare-metal default.
# Defaults to the macOS dev host; CI on Linux overrides with
# `HOST_TARGET=x86_64-unknown-linux-gnu`. Consumed by the host-tool output-path
# vars and their build rules below. QEMU_DISPLAY: empty by default (interactive
# `run-quiet` keeps its window); headless CI sets `QEMU_DISPLAY=-display none`.
HOST_TARGET ?= aarch64-apple-darwin
QEMU_DISPLAY ?=

# RISC-V initrd artifacts
INITRD_RISCV64 := initrd-riscv64.img
MKINITRD_DIR := tools/mkinitrd
MKINITRD := $(MKINITRD_DIR)/target/$(HOST_TARGET)/release/mkinitrd

# Hand-assembled test binary (AArch64)
USER_ELF_AARCH64 := user/hello-aarch64.elf
USER_SRC_AARCH64 := user/hello-aarch64.S
USER_LD_AARCH64  := user/user-aarch64.ld

# ELF signing tool
SIGN_ELF_DIR := tools/sign-elf
SIGN_ELF := $(SIGN_ELF_DIR)/target/$(HOST_TARGET)/release/sign-elf

# Boot-manifest builder (ADR-018 step 2; input = manifest.toml, the
# ADR-037 Phase-2 endpoint-registry artifact)
BUILD_MANIFEST_DIR := tools/build-manifest
BUILD_MANIFEST := $(BUILD_MANIFEST_DIR)/target/$(HOST_TARGET)/release/build-manifest

# Dev-PIV keypair generator (host-side). Derives Ed25519+X25519 keys from a
# persistent per-developer seed; writes dev_bootstrap_pubkey.bin (consumed by
# the kernel under --features dev-piv) and user/key-store-service/
# dev_piv_secret.bin (consumed by SwPivBackend under --features dev-piv).
GEN_DEV_PIV_DIR := tools/gen-dev-piv-keys
GEN_DEV_PIV := $(GEN_DEV_PIV_DIR)/target/aarch64-apple-darwin/release/gen-dev-piv-keys
DEV_BOOTSTRAP_PUBKEY := dev_bootstrap_pubkey.bin
DEV_PIV_SECRET := user/key-store-service/dev_piv_secret.bin

# Format-volume host tool (stream A A-v.e). Writes a fresh signed
# ADR-032 § 4 volume header to a raw disk image file using the
# DPIV bundle gen-dev-piv-keys produced. Sibling to sign-elf.
FORMAT_VOLUME_DIR := tools/format-volume
FORMAT_VOLUME := $(FORMAT_VOLUME_DIR)/target/aarch64-apple-darwin/release/format-volume

# Signing mode: "yubikey" (default) or "seed" (for CI/testing without hardware key)
SIGN_MODE ?= seed

# Bootstrap seed hex — only used when SIGN_MODE=seed (for dev/CI builds)
BOOTSTRAP_SEED_HEX := 4172634f532d426f6f7473747261702d4964656e746974792d50686173653021

# Resolve sign-elf flags based on signing mode
ifeq ($(SIGN_MODE),seed)
  SIGN_FLAGS := --seed $(BOOTSTRAP_SEED_HEX)
else ifeq ($(SIGN_MODE),dev-piv)
  # Sign ELFs with the dev-PIV slot-9C Ed25519 seed (matches the
  # bootstrap pubkey baked into a kernel built with `--features
  # dev-piv`). Requires `make gen-dev-piv-keys` to have produced
  # dev_slot_9c_seed.bin. NOTE: this is the *derived* slot-9C
  # seed (blake3(.dev-seed.bin || "cambios-dev-piv:slot-9c-
  # ed25519")), not .dev-seed.bin itself — the bootstrap pubkey
  # under `--features dev-piv` is the slot-9C public key, so
  # sign-elf needs the slot-9C secret to produce signatures the
  # kernel accepts.
  DEV_PIV_SEED_HEX := $(shell xxd -p -c 32 dev_slot_9c_seed.bin)
  SIGN_FLAGS := --seed $(DEV_PIV_SEED_HEX)
else
  SIGN_FLAGS :=
endif

.PHONY: manifest-profile all kernel iso run run-gui run-uefi test clean symbols img-x86 run-img-x86 img-usb run-img-usb usb verify-usb disk-img kernel-aarch64 img-aarch64 run-aarch64 run-aarch64-gui kernel-riscv64 img-riscv64 run-riscv64 check-all check-stable check-x86 check-clippy check-clippy-x86 check-adrs new-adr check-doc-refs update-doc-refs-baseline audit-taxonomy check-audit-taxonomy check-index-isolation check-deferrals update-deferrals-baseline check-fail-open update-fail-open-baseline claude-preflight sync-site sync-site-check user-elf user-elf-aarch64 sign-tool manifest manifest-headless manifest-aarch64 manifest-riscv64 mkinitrd gen-dev-piv-keys format-volume bake-font export-pubkey kernel-dev-piv key-store-service-dev-piv iso-dev-piv run-quiet-dev-piv

all: iso

# Optional cargo features for the x86_64 kernel build, e.g.
# `KERNEL_FEATURES=fbcon-hold` (diagnostic: keep the framebuffer text
# console mirrored after the scanout driver maps the display — the only
# way to read the boot log on a machine with no serial port). Flows
# through iso / img-x86 / img-usb / usb.
KERNEL_FEATURES ?=

kernel:
	cargo build --target x86_64-unknown-none --release $(if $(KERNEL_FEATURES),--features "$(KERNEL_FEATURES)",)

# Kernel built with `--features dev-piv` — replaces the committed
# bootstrap pubkey with the per-developer dev one from
# tools/gen-dev-piv-keys/.dev-seed.bin. Used end-to-end by
# `run-dev-piv` for the stream A FDE unlock smoke test.
kernel-dev-piv:
	cargo build --target x86_64-unknown-none --release --features dev-piv

# Key-store-service built with `--features dev-piv` — loads
# SwPivBackend with the slot-9C/9D keys from
# user/key-store-service/dev_piv_secret.bin so the kernel's PIV
# IPC clients can talk to a virtual YubiKey without real hardware.
key-store-service-dev-piv:
	@echo "=== Building Key Store service (--features dev-piv) ==="
	cd user/key-store-service && CARGO_ENCODED_RUSTFLAGS=$$(printf '%s\x1f%s\x1f%s\x1f%s' \
		'-Clink-arg=--script=link.ld' '-Clink-arg=-z' '-Clink-arg=noexecstack' \
		'-Crelocation-model=static') cargo build --release --features dev-piv
	@echo "=== Key Store service ready (dev-piv) ==="

user-elf:
	@echo "=== Building user-space ELF ==="
	clang -target x86_64-unknown-none -nostdlib -ffreestanding -c $(USER_SRC) -o user/hello.o
	ld.lld -T $(USER_LD) -nostdlib --no-dynamic-linker -static user/hello.o -o $(USER_ELF)
	@echo "=== $(USER_ELF) ready ==="

user-elf-aarch64:
	@echo "=== Building user-space ELF (AArch64) ==="
	clang -target aarch64-unknown-none -nostdlib -ffreestanding -c $(USER_SRC_AARCH64) -o user/hello-aarch64.o
	ld.lld -T $(USER_LD_AARCH64) -nostdlib --no-dynamic-linker -static user/hello-aarch64.o -o $(USER_ELF_AARCH64)
	@echo "=== $(USER_ELF_AARCH64) ready ==="

# -----------------------------------------------------------------------------
# User crates: one rule per (crate, architecture), generated from the lists.
#
# The recipe is the same for every crate. CARGO_ENCODED_RUSTFLAGS replaces the
# rustflags the repository's .cargo/config.toml sets for the kernel (kernel
# linker script, kernel code model) with the crate's own linker script.
#
# Targets are named <crate><suffix>: fs-service, fs-service-aarch64,
# fs-service-riscv64. Each rule also defines ELF_<crate>_<arch>, the path of
# the binary it produces.
#
# nvme serves the same block seam as virtio-blk; the bare-metal manifest
# profiles (headless / framebuffer-fallback) spawn it.
# -----------------------------------------------------------------------------

# Cargo features for one (crate, architecture). The headless image rebuilds
# the x86_64 shell with `headless-input` (the shell owns the input endpoint;
# see manifest.toml's second `shell` entry). Empty for the ISO and the GUI
# profiles.
SHELL_FEATURES ?=
FEATURES_shell_x86_64 = $(if $(SHELL_FEATURES),--features $(SHELL_FEATURES),)

# $(1) = crate directory under user/, $(2) = architecture
define USER_CRATE_RULE
ELF_$(1)_$(2) := user/$(1)/target/$$(TRIPLE_$(2))/release/cambios-$(1)
.PHONY: $(1)$$(SUFFIX_$(2))
$(1)$$(SUFFIX_$(2)):
	@echo "=== Building $(1) ($(2)) ==="
	cd user/$(1) && CARGO_ENCODED_RUSTFLAGS=$$$$(printf '%s\x1f%s\x1f%s\x1f%s' \
		'-Clink-arg=--script=$$(USER_LINK_$(2))' '-Clink-arg=-z' '-Clink-arg=noexecstack' \
		'-Crelocation-model=static') cargo build $$(strip $$(USER_TARGET_ARG_$(2)) --release $$(FEATURES_$(1)_$(2)))
	@echo "=== $(1) ($(2)) ready ==="
endef
$(foreach a,$(ARCHES),$(foreach c,$(CRATES_$(a)),$(eval $(call USER_CRATE_RULE,$(c),$(a)))))

sign-tool:
	@echo "=== Building ELF signing tool ==="
	cd $(SIGN_ELF_DIR) && cargo build --release --target $(HOST_TARGET)
	@echo "=== sign-elf ready ==="

# Boot manifest (ADR-018 migration step 2). Emits manifest.bin from
# manifest.toml (the ADR-037 Phase-2 endpoint-registry artifact) via
# tools/build-manifest, then signs it with the same ARCSIG path +
# SIGN_MODE resolution as the boot-module ELFs. Not yet consumed by
# the ISO — boot wiring lands at ADR-018 migration step 7.
manifest: sign-tool
	@echo "=== Building build-manifest tool ==="
	cd $(BUILD_MANIFEST_DIR) && cargo build --release --target $(HOST_TARGET)
	@echo "=== Emitting + signing manifest.bin (x86_64) ==="
	$(BUILD_MANIFEST) manifest.toml -o manifest.bin --arch x86_64
	$(SIGN_ELF) $(SIGN_FLAGS) manifest.bin
	@echo "=== manifest.bin ready (signed) ==="

# Serial-console-only manifest for bare-metal first boot (see img-x86).
# Bare-metal image profile (manifest.toml `profile` tags). `headless`
# = no display stack, serial/framebuffer-console shell only;
# `framebuffer-fallback` = scanout-limine on the GOP framebuffer +
# compositor + terminal-window (keyboard via usb-host HID).
PROFILE ?= headless
MANIFEST_PROFILE_BIN := manifest-$(PROFILE).bin

manifest-profile: sign-tool
	@echo "=== Building build-manifest tool ==="
	cd $(BUILD_MANIFEST_DIR) && cargo build --release --target $(HOST_TARGET)
	@echo "=== Emitting + signing $(MANIFEST_PROFILE_BIN) (x86_64, --profile $(PROFILE)) ==="
	$(BUILD_MANIFEST) manifest.toml -o $(MANIFEST_PROFILE_BIN) --arch x86_64 --profile $(PROFILE)
	$(SIGN_ELF) $(SIGN_FLAGS) $(MANIFEST_PROFILE_BIN)
	@echo "=== $(MANIFEST_PROFILE_BIN) ready (signed) ==="

manifest-headless:
	$(MAKE) manifest-profile PROFILE=headless

manifest-aarch64: sign-tool
	@echo "=== Building build-manifest tool ==="
	cd $(BUILD_MANIFEST_DIR) && cargo build --release --target $(HOST_TARGET)
	@echo "=== Emitting + signing manifest-aarch64.bin ==="
	$(BUILD_MANIFEST) manifest.toml -o manifest-aarch64.bin --arch aarch64
	$(SIGN_ELF) $(SIGN_FLAGS) manifest-aarch64.bin
	@echo "=== manifest-aarch64.bin ready (signed) ==="

manifest-riscv64: sign-tool
	@echo "=== Building build-manifest tool ==="
	cd $(BUILD_MANIFEST_DIR) && cargo build --release --target $(HOST_TARGET)
	@echo "=== Emitting + signing manifest-riscv64.bin ==="
	$(BUILD_MANIFEST) manifest.toml -o manifest-riscv64.bin --arch riscv64
	$(SIGN_ELF) $(SIGN_FLAGS) manifest-riscv64.bin
	@echo "=== manifest-riscv64.bin ready (signed) ==="

mkinitrd:
	@echo "=== Building mkinitrd host tool ==="
	cd $(MKINITRD_DIR) && cargo build --release --target $(HOST_TARGET)
	@echo "=== mkinitrd ready ==="

# Builds the gen-dev-piv-keys tool (idempotent; rebuilds only on source
# change) and runs it. Idempotent at the file-output level: same seed →
# byte-identical dev_bootstrap_pubkey.bin and dev_piv_secret.bin.
# Required before any build with `--features dev-piv` enabled.
gen-dev-piv-keys:
	@echo "=== Building dev-PIV keypair generator ==="
	cd $(GEN_DEV_PIV_DIR) && cargo build --release
	@echo "=== Generating dev-PIV keypair files ==="
	$(GEN_DEV_PIV)
	@echo "=== dev-PIV keypair files ready ==="

# Builds the format-volume host tool. Doesn't run it — invoke
# directly with a disk image path (e.g.,
# `$(FORMAT_VOLUME) disk.img`). Requires gen-dev-piv-keys to have
# run at least once (consumes user/key-store-service/dev_piv_secret.bin).
format-volume:
	@echo "=== Building format-volume host tool ==="
	cd $(FORMAT_VOLUME_DIR) && cargo build --release
	@echo "=== format-volume ready: $(FORMAT_VOLUME) ==="

# Re-bake the JetBrains Mono Regular TTF in assets/fonts/ into the
# antialiased glyph table consumed by user/libgui at compile time. Run
# only when the font, target cell size, or pixel height changes — the
# generated file is checked in. Bake parameters live here as the source
# of truth (the tool's CLI lets you override at the command line).
JBM_PX_HEIGHT := 24
JBM_CELL := 16x32
bake-font:
	@echo "=== Building bake-font host tool ==="
	cd tools/bake-font && cargo build --release
	@echo "=== Re-baking JetBrains Mono into user/libgui/src/font_jbmono_data.rs ==="
	./tools/bake-font/target/aarch64-apple-darwin/release/bake-font \
	    assets/fonts/JetBrainsMono-Regular.ttf \
	    user/libgui/src/font_jbmono_data.rs \
	    --px $(JBM_PX_HEIGHT) --cell $(JBM_CELL) --const-prefix JBM
	@echo "=== bake-font ready ==="

# Export the bootstrap public key from the signing source.
# Run this once after setting up your YubiKey to generate bootstrap_pubkey.bin.
# Usage: make export-pubkey                   (from YubiKey)
#        make export-pubkey SIGN_MODE=seed    (from seed, for dev)
export-pubkey: sign-tool
	$(SIGN_ELF) $(SIGN_FLAGS) --export-pubkey bootstrap_pubkey.bin

# Auto-clone Limine if $(LIMINE_DIR) was cleaned or partially nibbled.
# rm -rf before clone defends against the macOS /tmp daily-cleanup case
# that prompted the move out of /tmp: per-file atime cleanup can leave
# the dir present but missing key files (e.g., BOOTX64.EFI gone while
# BOOTAA64.EFI survives), and `git clone` refuses a non-empty target.
$(LIMINE_DIR)/BOOTX64.EFI $(LIMINE_DIR)/BOOTAA64.EFI:
	@echo "=== Cloning Limine $(LIMINE_BRANCH) ==="
	rm -rf $(LIMINE_DIR)
	mkdir -p $(dir $(LIMINE_DIR))
	git clone $(LIMINE_REPO) --branch=$(LIMINE_BRANCH) --depth=1 $(LIMINE_DIR)

# Upstream's `limine-binary` branch ships the pre-built EFI stages but
# NOT the compiled macOS host tool `limine` (the `xxx bios-install $(ISO)`
# call at the bottom of `iso:`). The clone includes the single-file
# `limine.c` source; compile it in-place. Depends on BOOTX64.EFI to
# guarantee the clone has run.
$(LIMINE_DIR)/limine: $(LIMINE_DIR)/BOOTX64.EFI
	@echo "=== Building Limine host tool ==="
	$(MAKE) -C $(LIMINE_DIR)

limine: $(LIMINE_DIR)/BOOTX64.EFI $(LIMINE_DIR)/limine

# `iso-dev-piv` produces the same ISO as `iso`, but with the kernel
# and key-store-service binaries built under `--features dev-piv`
# (stream A FDE end-to-end). Approach: build the dev-piv variants
# first, then re-invoke `iso` with `--assume-old` so make doesn't
# clobber them with the default (non-dev-piv) cargo build.
iso-dev-piv: kernel-dev-piv key-store-service-dev-piv gen-dev-piv-keys format-volume fde-mount sign-tool
	@echo "=== Re-assembling ISO with --features dev-piv binaries ==="
	$(MAKE) --assume-old=kernel --assume-old=key-store-service SIGN_MODE=dev-piv iso

iso: kernel $(STAGE_x86_64) init manifest sign-tool limine
	@echo "=== Building ISO (signing mode: $(SIGN_MODE)) ==="
	rm -rf iso_root
	mkdir -p iso_root/boot
	mkdir -p iso_root/boot/limine
	mkdir -p iso_root/EFI/BOOT
	# Copy kernel binary
	cp $(KERNEL) iso_root/boot/cambios_microkernel
	# Copy + sign boot modules (the set must cover limine.conf's
	# module_path lines; order is not load-bearing since ADR-018 step 9).
	# Both scanout drivers are staged; the manifest profile picks one.
	# `default` (QEMU, -device virtio-gpu-pci) spawns scanout-virtio-gpu;
	# `framebuffer-fallback` (bare metal over the GOP framebuffer,
	# `make img-usb PROFILE=framebuffer-fallback`) spawns scanout-limine.
	# A staged module the manifest does not declare is loaded but
	# unspawnable, so carrying both costs nothing but bytes.
	$(foreach c,$(STAGE_x86_64),cp $(ELF_$(c)_x86_64) iso_root/boot/$(c).elf$(NL))
	# ADR-018: init + the signed manifest blob (full reservation set —
	# the step-8 cutover shape). manifest.bin arrives already signed by
	# the `manifest` prerequisite — do NOT re-sign it here (sign-elf
	# appends a trailer; a second pass would stack trailers and break
	# verification).
	cp $(ELF_init_x86_64) iso_root/boot/init.elf
	cp manifest.bin iso_root/boot/manifest.bin
	$(SIGN_ELF) $(SIGN_FLAGS) iso_root/boot/init.elf
	$(foreach c,$(STAGE_x86_64),$(SIGN_ELF) $(SIGN_FLAGS) iso_root/boot/$(c).elf$(NL))
	# Copy Limine config (root + standard location)
	cp limine.conf iso_root/limine.conf
	cp limine.conf iso_root/boot/limine/limine.conf
	# Copy Limine BIOS files
	cp $(LIMINE_DIR)/limine-bios.sys iso_root/boot/limine/
	cp $(LIMINE_DIR)/limine-bios-cd.bin iso_root/boot/limine/
	# Copy Limine UEFI files
	cp $(LIMINE_DIR)/BOOTX64.EFI iso_root/EFI/BOOT/
	cp $(LIMINE_DIR)/BOOTIA32.EFI iso_root/EFI/BOOT/
	# Create ISO
	xorriso -as mkisofs \
		-b boot/limine/limine-bios-cd.bin \
		-no-emul-boot -boot-load-size 4 -boot-info-table \
		--efi-boot EFI/BOOT/BOOTX64.EFI \
		-efi-boot-part --efi-boot-image --protective-msdos-label \
		iso_root -o $(ISO) 2>&1
	# Install Limine BIOS stages
	$(LIMINE_DIR)/limine bios-install $(ISO)
	# iso_root is kept: img-x86 mirrors it into the FAT/USB image. It is
	# rebuilt from scratch at the top of this recipe and removed by clean.
	@echo "=== $(ISO) ready ==="

# Persistent backing file for the virtio-blk device. 64 MiB is enough for
# the Phase 4a.i DiskObjectStore with 4096-slot capacity (~32 MiB used) plus
# room to grow. The image file persists across `make run` invocations, which
# is the whole point — reboot-cycle testing needs the bytes to survive.
DISK_IMG := cambios-disk.img

# Which QEMU bus carries the disk: `virtio` (virtio-blk-pci, served by the
# virtio-blk driver in the `default` manifest profile) or `nvme` (an NVMe
# controller, served by the nvme driver in the bare-metal profiles —
# `make run-img-usb DISK_BUS=nvme PROFILE=headless` is the QEMU rehearsal
# for the Dell 3630's drive).
DISK_BUS ?= virtio
ifeq ($(DISK_BUS),nvme)
DISK_DEVICE_ARGS := -drive file=$(DISK_IMG),if=none,format=raw,id=cambios-disk0 -device nvme,serial=cambios0,drive=cambios-disk0
else
DISK_DEVICE_ARGS := -drive file=$(DISK_IMG),if=none,format=raw,id=cambios-disk0 -device virtio-blk-pci,drive=cambios-disk0
endif
DISK_SIZE_MB := 64

disk-img:
	@if [ ! -f $(DISK_IMG) ]; then \
		echo "=== Creating $(DISK_IMG) ($(DISK_SIZE_MB) MiB) ==="; \
		qemu-img create -f raw $(DISK_IMG) $(DISK_SIZE_MB)M; \
	else \
		echo "=== $(DISK_IMG) already exists; leaving it alone ==="; \
	fi

# `-vga virtio` replaces QEMU's default cirrus VGA with virtio-vga.
# virtio-vga is a virtio-gpu device (vendor 0x1AF4, device 0x1050,
# probed identically to virtio-gpu-pci) plus a VGA compatibility
# mode Limine uses for its boot framebuffer. With default `-vga std`
# + a *separate* `-device virtio-gpu-pci`, the Cocoa window shows
# the primary cirrus adapter — nobody writes to it in Scanout-4.b
# and the window is black. Unifying the adapter means what our
# driver programs (SET_SCANOUT / TRANSFER / FLUSH) is what Cocoa
# displays.
run: iso disk-img
	qemu-system-x86_64 \
		-cdrom $(ISO) \
		-serial mon:stdio \
		-smp 2 \
		-m 4G \
		-netdev user,id=net0 \
		-device virtio-net-pci,netdev=net0 \
		-drive file=$(DISK_IMG),if=none,format=raw,id=cambios-disk0 \
		-device virtio-blk-pci,drive=cambios-disk0 \
		-device qemu-xhci,id=xhci0 \
		-device usb-ccid,bus=xhci0.0 \
		-vga virtio \
		-no-reboot

# Filtered `run`: streams kernel output through tools/qemu-run-quiet.py,
# suppressing memory-map / Limine noise and exiting with a status code
# that reflects outcome (0 = success sentinel seen, 1 = panic/exception,
# 2 = hang). Default success sentinel is `cambios> ` (full boot to shell);
# override for pre-shell testing:  make run-quiet SUCCESS="virtio-net ready"
# Keep this QEMU command in sync with `run:` above.
# Liveness assertions for run-quiet: the shell banner alone proved too
# little for months (the policy upcall never answered and every boot
# still "passed"). Every `--require REGEX` must match a serial line
# before the run counts as success; the runner keeps reading after the
# banner until they all do, or the timeout. Default: the wave settled
# with nothing failed. CI adds the enforcement counters via
# EXTRA_REQUIRES (see .github/workflows/boot-smoke.yml).
RUN_QUIET_REQUIRES ?= --require 'boot wave settled: [0-9]+ ready, 0 spawn-failed, 0 dep-failed'
EXTRA_REQUIRES ?=

run-quiet: iso disk-img
	python3 tools/qemu-run-quiet.py \
		$(if $(TIMEOUT),--timeout $(TIMEOUT),) \
		$(if $(SUCCESS),--success "$(SUCCESS)",) \
		$(RUN_QUIET_REQUIRES) $(EXTRA_REQUIRES) \
		-- qemu-system-x86_64 \
			-cdrom $(ISO) \
			-serial mon:stdio \
			-smp 2 \
			-m 4G \
			-netdev user,id=net0 \
			-device virtio-net-pci,netdev=net0 \
			$(DISK_DEVICE_ARGS) \
			-device qemu-xhci,id=xhci0 \
			-device usb-ccid,bus=xhci0.0 \
			-vga virtio \
			$(QEMU_DISPLAY) \
			-no-reboot

# Quiet run under `--features dev-piv` — the stream A FDE end-to-end
# smoke test. Formats the disk image with a fresh signed volume
# header (idempotent under a constant master via --master-key-hex
# would be possible, but the default random master is what matches
# production semantics). Boots; fde-mount unwraps the master key
# via SwPivBackend; SYS_INSTALL_MASTER_KEY installs
# EncryptedBlockDevice<VirtioBlkDevice> as OBJECT_STORE; substrate
# now lives on XTS-AES-256. Success sentinel default
# `cambios> ` indicates the boot reached the shell.
run-quiet-dev-piv: iso-dev-piv disk-img
	@echo "=== Zeroing substrate superblock (LBA 4) for fresh-wrap detection ==="
	@# format-volume randomizes the master key each invocation, so any
	@# substrate state at LBA 4+ from a prior boot decrypts to garbage
	@# under the new master — kernel's open_strict refuses (correct
	@# wrong-master behavior, see A-v.d.4 design). Smoke test wants the
	@# fresh-wrap → format() path each run, so we zero just LBA 4 (the
	@# substrate's SUPERBLOCK_LBA after the FDE_SUBSTRATE_LBA_OFFSET = 4
	@# shift) to force the kernel's `is_fresh_wrap` check to fire.
	@# Leaves LBA 5+ untouched; persistence semantics are unchanged when
	@# the master is held stable (e.g., via --master-key-hex).
	dd if=/dev/zero of=$(DISK_IMG) bs=4096 count=1 seek=4 conv=notrunc status=none
	@echo "=== Formatting cambios-disk.img with fresh signed FDE header ==="
	$(FORMAT_VOLUME) $(DISK_IMG)
	python3 tools/qemu-run-quiet.py \
		$(if $(TIMEOUT),--timeout $(TIMEOUT),) \
		$(if $(SUCCESS),--success "$(SUCCESS)",) \
		-- qemu-system-x86_64 \
			-cdrom $(ISO) \
			-serial mon:stdio \
			-smp 2 \
			-m 4G \
			-netdev user,id=net0 \
			-device virtio-net-pci,netdev=net0 \
			-drive file=$(DISK_IMG),if=none,format=raw,id=cambios-disk0 \
			-device virtio-blk-pci,drive=cambios-disk0 \
			-device qemu-xhci,id=xhci0 \
			-device usb-ccid,bus=xhci0.0 \
			-vga virtio \
			-no-reboot

# Same as `run`, plus a graphical QEMU window (macOS Cocoa backend) so
# compositor / scanout output is visible. Use for Scanout-3+ visual
# verification; `run` stays headless (serial-only) for CI / text-mode
# workflows. For Linux change `cocoa` to `gtk`; for remote sessions
# swap to `-vnc :0` and connect via Screen Sharing.
run-gui: iso disk-img
	qemu-system-x86_64 \
		-cdrom $(ISO) \
		-serial mon:stdio \
		-smp 2 \
		-m 4G \
		-netdev user,id=net0 \
		-device virtio-net-pci,netdev=net0 \
		-drive file=$(DISK_IMG),if=none,format=raw,id=cambios-disk0 \
		-device virtio-blk-pci,drive=cambios-disk0 \
		-device virtio-keyboard-pci \
		-device virtio-mouse-pci \
		-device qemu-xhci,id=xhci0 \
		-device usb-ccid,bus=xhci0.0 \
		-vga virtio \
		-no-reboot \
		-display cocoa

run-uefi: iso
	@cp $(EFI_VARS_X86) /tmp/cambios-efivars.fd
	qemu-system-x86_64 \
		-cdrom $(ISO) \
		-drive if=pflash,format=raw,readonly=on,file=$(EFI_FW_X86) \
		-drive if=pflash,format=raw,file=/tmp/cambios-efivars.fd \
		-serial mon:stdio \
		-m 4G \
		-no-reboot

# x86_64 FAT32 UEFI image — for USB boot on bare-metal x86_64 hardware.
# Usage: make img-x86 && sudo dd if=cambios-x86.img of=/dev/diskN bs=1M
IMG_X86 := cambios-x86.img

img-x86: iso manifest-profile
	@echo "=== Building x86_64 FAT boot image from iso_root (signing mode: $(SIGN_MODE)) ==="
	# The FAT image is the ISO's staging tree verbatim (kernel, every
	# signed module, init, Limine UEFI/BIOS files, limine.conf), so the
	# USB stick and the ISO can never drift apart — with ONE swap: the
	# manifest is the `$(PROFILE)` profile (default `headless`). Bare metal has no virtio-gpu,
	# and with the default manifest the compositor's scanout handshake
	# never completes and init's wave stalls before the shell. The GUI
	# modules are staged regardless (undeclared modules are registered
	# but unspawnable); `PROFILE=framebuffer-fallback` swaps in the
	# manifest that spawns scanout-limine + compositor + terminal-window.
	rm -f $(IMG_X86)
	dd if=/dev/zero of=$(IMG_X86) bs=1M count=64
	mformat -i $(IMG_X86) -F ::
	mcopy -s -i $(IMG_X86) iso_root/EFI iso_root/boot iso_root/limine.conf ::/
	mcopy -o -i $(IMG_X86) $(MANIFEST_PROFILE_BIN) ::/boot/manifest.bin
	# Second swap, headless only: the shell built as the input consumer
	# (`headless-input`), signed, replacing the ISO's plain shell in the
	# image. iso_root keeps the plain one so the ISO never carries it.
	if [ "$(PROFILE)" = "headless" ]; then \
		$(MAKE) shell SHELL_FEATURES=headless-input && \
		cp $(ELF_shell_x86_64) /tmp/shell-headless-signed.elf && \
		$(SIGN_ELF) $(SIGN_FLAGS) /tmp/shell-headless-signed.elf && \
		mcopy -o -i $(IMG_X86) /tmp/shell-headless-signed.elf ::/boot/shell.elf; \
	fi
	@echo "=== $(IMG_X86) ready ($(PROFILE) manifest) ==="
	@echo "To write to USB: make usb DEVICE=/dev/diskN  (or: sudo dd if=$(IMG_X86) of=/dev/diskN bs=1M)"

# UEFI firmware paths (resolved via Homebrew Cellar for QEMU 10.x)
# QEMU 10.x requires pflash loading (not -bios) per firmware/*.json descriptors.
EFI_FW_X86 := $(shell find /opt/homebrew/Cellar/qemu -name 'edk2-x86_64-code.fd' 2>/dev/null | head -1)
EFI_VARS_X86 := $(shell find /opt/homebrew/Cellar/qemu -name 'edk2-i386-vars.fd' 2>/dev/null | head -1)

# Test x86_64 FAT image in QEMU UEFI (validates the image before writing to USB)
run-img-x86: img-x86
	@cp $(EFI_VARS_X86) /tmp/cambios-efivars.fd
	qemu-system-x86_64 \
		-drive file=$(IMG_X86),format=raw \
		-drive if=pflash,format=raw,readonly=on,file=$(EFI_FW_X86) \
		-drive if=pflash,format=raw,file=/tmp/cambios-efivars.fd \
		-serial mon:stdio \
		-smp 2 \
		-m 4G \
		-netdev user,id=net0 \
		-device virtio-net-pci,netdev=net0 \
		-no-reboot

# ============================================================================
# USB boot image (GPT-partitioned, UEFI-bootable)
# ============================================================================
#
# Builds a GPT-partitioned disk image with a single EFI System Partition
# (ESP) containing all kernel + signed user-space modules. Suitable for
# `dd`-ing to a USB stick and booting on bare-metal UEFI systems.
#
# Layout:
#   LBA 0:        Protective MBR (created by sgdisk)
#   LBA 1:        Primary GPT header
#   LBA 2..33:    Primary GPT partition table
#   LBA 2048:     ESP partition start (FAT32, type C12A7328-...)
#   LBA -33..-1:  Backup GPT (header + table)
#
# Requires sgdisk (gptfdisk). Install via: brew install gptfdisk
#
# Usage:
#   make img-usb               # Build the image
#   make run-img-usb           # Test in QEMU UEFI
#   make usb DEVICE=/dev/diskN # Write to USB (with confirmation)
#   make verify-usb DEVICE=/dev/diskN # Read back and compare

IMG_USB := cambios-usb.img
IMG_USB_SIZE_MB := 96
ESP_SIZE_MB := 64

img-usb: img-x86
	@command -v sgdisk >/dev/null 2>&1 || { \
		echo "ERROR: sgdisk not found. Install with: brew install gptfdisk"; \
		exit 1; \
	}
	@echo "=== Building GPT-partitioned USB image ==="
	rm -f $(IMG_USB)
	# Create blank disk image
	dd if=/dev/zero of=$(IMG_USB) bs=1M count=$(IMG_USB_SIZE_MB) status=none
	# Create GPT with a single ESP partition starting at LBA 2048 (1 MiB).
	# Partition type C12A7328-F81F-11D2-BA4B-00A0C93EC93B = EFI System Partition.
	sgdisk --clear \
		--new=1:2048:+$(ESP_SIZE_MB)M \
		--typecode=1:EF00 \
		--change-name=1:"CambiOS ESP" \
		$(IMG_USB) >/dev/null
	# Embed the FAT32 ESP image at LBA 2048 (offset = 2048 * 512 = 1 MiB).
	dd if=$(IMG_X86) of=$(IMG_USB) bs=1M seek=1 conv=notrunc status=none
	@echo "=== $(IMG_USB) ready ($(IMG_USB_SIZE_MB) MiB, GPT + FAT32 ESP) ==="
	@echo "Test in QEMU:    make run-img-usb"
	@echo "Write to USB:    make usb DEVICE=/dev/diskN"

# Test the GPT image in QEMU UEFI (validates before writing to USB)
run-img-usb: img-usb disk-img
	@cp $(EFI_VARS_X86) /tmp/cambios-efivars.fd
	qemu-system-x86_64 \
		-drive file=$(IMG_USB),format=raw \
		-drive if=pflash,format=raw,readonly=on,file=$(EFI_FW_X86) \
		-drive if=pflash,format=raw,file=/tmp/cambios-efivars.fd \
		-serial mon:stdio \
		-smp 2 \
		-m 4G \
		-netdev user,id=net0 \
		-device virtio-net-pci,netdev=net0 \
		$(DISK_DEVICE_ARGS) \
		-no-reboot

# Write the GPT image to a USB stick (with safety prompt).
# Usage: make usb DEVICE=/dev/diskN
usb: img-usb
	@if [ -z "$(DEVICE)" ]; then \
		echo "ERROR: specify the target device:"; \
		echo "  make usb DEVICE=/dev/diskN"; \
		echo ""; \
		echo "Available external disks:"; \
		diskutil list external 2>/dev/null || diskutil list; \
		exit 1; \
	fi
	@if [ ! -b "$(DEVICE)" ] && [ ! -c "$(DEVICE)" ]; then \
		echo "ERROR: $(DEVICE) is not a block/character device"; \
		exit 1; \
	fi
	@echo ""
	@echo "============================================================"
	@echo "  WARNING: This will OVERWRITE all data on $(DEVICE)"
	@echo "============================================================"
	@diskutil info $(DEVICE) 2>/dev/null | grep -E "(Device.*Identifier|Media Name|Disk Size|Protocol)" || true
	@echo ""
	@printf "Type 'yes' to continue: "
	@read confirm && [ "$$confirm" = "yes" ] || { echo "Aborted."; exit 1; }
	@echo "Unmounting $(DEVICE)..."
	@diskutil unmountDisk $(DEVICE) 2>/dev/null || true
	@echo "Writing $(IMG_USB) to $(DEVICE) (this may take a minute)..."
	sudo dd if=$(IMG_USB) of=$(DEVICE) bs=1M
	sync
	# The image's GPT backup header sits at the $(IMG_USB_SIZE_MB) MiB mark.
	# A real stick is larger, so after dd the backup header is not in the
	# device's last sector — a layout some firmware (Dell UEFI, observed
	# 2026-10-22 on a Precision 3630) treats as a corrupt GPT and silently
	# refuses to list as a boot device. QEMU's edk2 tolerated it because
	# the virtual disk was exactly image-sized. Relocate the backup
	# header + table to the end of the actual device (`sgdisk -e`) and
	# re-verify the table before ejecting.
	@echo "Relocating the GPT backup header to the end of $(DEVICE)..."
	sudo sgdisk -e $(DEVICE)
	sync
	sudo sgdisk -v $(DEVICE)
	@echo "Ejecting $(DEVICE)..."
	@diskutil eject $(DEVICE) 2>/dev/null || true
	@echo ""
	@echo "✓ USB ready. Boot the target machine from this device."

# Verify a USB stick by reading it back and comparing to the source image.
# Usage: make verify-usb DEVICE=/dev/diskN
verify-usb:
	@if [ -z "$(DEVICE)" ]; then \
		echo "ERROR: specify the device: make verify-usb DEVICE=/dev/diskN"; \
		exit 1; \
	fi
	@if [ ! -f $(IMG_USB) ]; then \
		echo "ERROR: $(IMG_USB) not found. Run 'make img-usb' first."; \
		exit 1; \
	fi
	@echo "Reading the ESP ($(ESP_SIZE_MB) MiB at +1 MiB) from $(DEVICE)..."
	@diskutil unmountDisk $(DEVICE) 2>/dev/null || true
	# ESP payload only (1 MiB .. 1 + ESP_SIZE_MB MiB): `make usb` relocates
	# the GPT backup header to the end of the device, which rewrites the
	# primary header's backup pointer + CRC in sector 1, so a whole-image
	# compare would always fail on a correctly written stick. The partition
	# table itself is checked by `sgdisk -v` below.
	# Only the read of the raw device needs root; the readback file is
	# written by an unprivileged dd on the far side of the pipe so the
	# user owns it and the cleanup below can remove it.
	sudo dd if=$(DEVICE) bs=1M skip=1 count=$(ESP_SIZE_MB) status=none \
		| dd of=/tmp/cambios-usb-readback.img bs=1M status=none
	dd if=$(IMG_USB) of=/tmp/cambios-usb-expected.img bs=1M skip=1 count=$(ESP_SIZE_MB) status=none
	sudo sgdisk -v $(DEVICE)
	@echo "Comparing to $(IMG_USB)..."
	@if cmp -s /tmp/cambios-usb-readback.img /tmp/cambios-usb-expected.img; then \
		echo "✓ USB ESP matches source image (verified $(ESP_SIZE_MB) MiB)"; \
		rm -f /tmp/cambios-usb-readback.img /tmp/cambios-usb-expected.img; \
	else \
		echo "✗ MISMATCH: USB does not match $(IMG_USB)"; \
		echo "  Readback saved to /tmp/cambios-usb-readback.img for inspection"; \
		exit 1; \
	fi

test:
	RUST_MIN_STACK=8388608 cargo test --lib --target x86_64-apple-darwin

# =============================================================================
# make verify — run Kani formal-verification proofs.
#
# Proofs live in `verification/<crate>/` and reuse kernel source via
# `#[path]` includes (no copy, no fork). Kani uses its own bundled
# nightly toolchain, so this works regardless of `rust-toolchain.toml`.
#
# Run after any change to a proven module. A proof failure means the property
# no longer holds — investigate before committing.
#
# `verify` is an alias for `verify-all`, which is the single canonical list of
# proof crates (defined below alongside the per-crate `verify-<crate>` targets).
# Keeping one list prevents the drift that previously left `dtb-proofs` out of
# the aggregate and a stale 4-crate enumeration here.
# =============================================================================
.PHONY: verify
verify: verify-all

# =============================================================================
# make stats — derive canonical counts from source code.
#
# CLAUDE.md and STATUS.md must not hardcode these numbers; they drift
# silently and become load-bearing lies. Run this target when a count
# actually matters. Intentionally cheap (no full build required for
# syscall/LOC counts; test count uses `--list` which only needs compiled
# test binaries).
# =============================================================================
.PHONY: stats
# Host triple used to enumerate --lib tests in `make stats`. Defaults to the
# maintainer's macOS host; override in CI / on Linux
# (STATS_TEST_TARGET=x86_64-unknown-linux-gnu). The --lib tests are pure logic,
# so the count is host-independent — the target only overrides the .cargo
# bare-metal default so a host binary can be built.
STATS_TEST_TARGET ?= x86_64-apple-darwin

stats:
	@echo "=== CambiOS stats (derived from source) ==="
	@printf "Syscalls:        "
	@sed -n '/^pub enum SyscallNumber/,/^}/p' cambios-abi/src/lib.rs | grep -Ec '^[[:space:]]+[A-Z][A-Za-z]+ = [0-9]+,'
	@printf "Kernel .rs:      "
	@find src -name '*.rs' | wc -l | tr -d ' '
	@printf "Userspace .rs:   "
	@find user -name '*.rs' -not -path '*/target/*' | wc -l | tr -d ' '
	@printf "Kani harnesses:  "
	@grep -rh --include='*.rs' --exclude-dir=target '#\[kani::proof\]' verification 2>/dev/null | grep -vc '^[[:space:]]*//' || true
	@printf "Tests (lib):     "
	@RUST_MIN_STACK=8388608 cargo test --lib --target $(STATS_TEST_TARGET) -- --list 2>/dev/null | awk '/^[0-9]+ tests?,/ {print $$1; found=1; exit} END {if (!found) print "(build first: make test)"}'

# Generate machine-readable symbol index for AI-assisted development.
# Output: .symbols (gitignored). Read by Claude Code at session start
# to avoid repeated grep calls for symbol locations and line numbers.
symbols:
	python3 tools/gen-symbols.py

# Verify ADR cross-references and regenerate docs/adr/INDEX.md.
# Exit nonzero if any ADR references a missing or superseded ADR, or
# if two ADRs share a number. Run after any ADR edit or addition.
check-adrs:
	python3 tools/check-adrs.py

# Allocate the next ADR number and scaffold its file. The next number is derived
# from the actual docs/adr/*.md files (max + 1) so it is never eyeballed; the
# duplicate-number guard in check-adrs.py is the backstop. Usage:
#   make new-adr TITLE="Native App Framework"
new-adr:
	@test -n "$(TITLE)" || { echo 'usage: make new-adr TITLE="Title of the decision"'; exit 1; }
	python3 tools/new-adr.py "$(TITLE)"

# Verify source line-refs in docs resolve to live code (anti-drift / anti-hallucination).
# Catches the HD-01 class: an ASSUMPTIONS.md row citing a source line that has moved
# or a symbol that no longer sits there. Don't-grow-the-baseline gate; baseline in
# tools/check-doc-refs-baseline.txt, refresh with `make update-doc-refs-baseline`.
check-doc-refs:
	python3 tools/check-doc-refs.py

update-doc-refs-baseline:
	python3 tools/check-doc-refs.py --update-baseline

# Regenerate docs/generated/audit-taxonomy.md from the canonical audit event
# taxonomy in cambios-abi (the `audit_taxonomy!` macro). The doc is rendered
# from the `TAXONOMY` const slice — never hand-edited. ADR-007 carries the
# categories and rationale; this generated file carries the enumeration.
audit-taxonomy:
	@mkdir -p docs/generated
	( cd tools/gen-audit-taxonomy && cargo run --release -q ) > $(CURDIR)/docs/generated/audit-taxonomy.md
	@echo "=== regenerated docs/generated/audit-taxonomy.md ==="

# Verify docs/generated/audit-taxonomy.md is in sync with cambios-abi.
# Regenerates to a temp file and diffs against the committed copy; fails if
# stale. Same generate-and-verify shape as check-adrs -> INDEX.md. Run after
# any audit-taxonomy change (and in the commit gate).
check-audit-taxonomy:
	@tmp=$$(mktemp); \
	( cd tools/gen-audit-taxonomy && cargo run --release -q ) > $$tmp 2>/dev/null; \
	if diff -u docs/generated/audit-taxonomy.md $$tmp >/dev/null; then \
		rm -f $$tmp; echo "=== audit-taxonomy.md in sync ==="; \
	else \
		echo "ERROR: docs/generated/audit-taxonomy.md is stale — run 'make audit-taxonomy'"; \
		diff -u docs/generated/audit-taxonomy.md $$tmp || true; rm -f $$tmp; exit 1; \
	fi

# Mirror kernel ADRs to the cambios-site repo. Reads tools/sync-to-site.toml
# for the slug map (kernel ADR stem -> site URL slug) and cross-doc reference
# maps. Idempotent: re-running on a synced state writes nothing. Override
# the site path with CAMBIOS_SITE_DIR or the script's --site-dir flag; the
# default in the toml assumes a sibling layout.
sync-site:
	python3 tools/sync-to-site.py

# Dry-run companion to `sync-site`: prints the would-update / would-create
# plan and writes nothing. Useful as a pre-commit sanity check, and as the
# smoke test after editing tools/sync-to-site.toml.
sync-site-check:
	python3 tools/sync-to-site.py --check

# Enforce STATUS.md commit-isolation (see tools/check-index-isolation.py).
# Rejects commits that bundle a structural STATUS.md change (> 20 lines
# changed) with any *.rs source file. Small Post-Change Review Step 8 row
# updates are unaffected. Wired into .githooks/pre-commit; also runnable
# manually via `make check-index-isolation`. Rationale: 2026-04-21 Tree v0
# incident — parallel sessions both touched STATUS.md and one bundled the
# other's restructure into a feature commit, requiring soft-reset + split.
check-index-isolation:
	@python3 tools/check-index-isolation.py

# Enforce that paths deleted from git stay deleted on disk (see
# tools/check-banned-paths.py and tools/banned-paths.txt). A `git rm
# --cached`, conflict-resolved merge, or cross-clone cherry-pick can
# leave a file in the working tree after the deletion commit lands;
# this lint catches the divergence at the commit boundary. Wired into
# .githooks/pre-commit; also runnable as `make check-banned-paths`.
# Rationale: 2026-04-21 third-strike recurrence — user/hello-riscv64.S
# and user/user-riscv64.ld survived afc4b11's deletion on disk and sat
# untracked for two days before a rebase surfaced them.
check-banned-paths:
	@python3 tools/check-banned-paths.py

# Surface every new (crate, version) pair pulled into Cargo.lock by this
# commit (or, when run between commits, since HEAD). Advisory — does not
# block. The point is visibility: build.rs and proc macros run with full
# host privileges before any signature is checked, so a poisoned
# transitive dep is the highest-yield supply-chain attack on a Rust
# project. T-1 in docs/threat-model.md. Wired into .githooks/pre-commit;
# also runnable as `make check-lockfile`.
check-lockfile:
	@python3 tools/check-lockfile-additions.py

# STATUS.md freshness gate — warn (advisory only) when the file's
# `last_synced_to_code:` is more than 7 days behind today. Fires on
# pre-commit so per-landing increments stay cheaper than the catch-up
# sync that recovers from prolonged drift. Tightens to a hard block
# (exit 1) once the warn cycle proves it does not change behavior;
# see tools/check-status-freshness.py for the trigger and rationale.
check-status-freshness:
	@python3 tools/check-status-freshness.py

# Pre-edit audit for a file. Run before the first Edit on any file per
# session — especially under parallel-thread development. Surfaces
# uncommitted changes (HEAD commit, status, full diff) so the caller
# can distinguish "mine" (proceed) from "parallel session" (stop, ask
# the user to commit first). File-scoped `git add <file>` doesn't
# protect against within-file multi-authorship; this gate catches it
# at edit time. See CLAUDE.md § Stop-and-Ask Gate "Pre-edit audit"
# bullet and tools/claude-preflight.py.
# Usage: make claude-preflight FILE=<path>
claude-preflight:
	@test -n "$(FILE)" || { echo "usage: make claude-preflight FILE=<path>" >&2; exit 1; }
	@python3 tools/claude-preflight.py "$(FILE)"

# Install the tracked pre-commit hook by pointing core.hooksPath at
# .githooks/. Run once per clone. Future hook changes propagate via
# `git pull` — no re-install needed. See .githooks/pre-commit.
install-hooks:
	@git config core.hooksPath .githooks
	@echo "=== core.hooksPath -> .githooks (pre-commit + commit-msg hooks active) ==="

# Enforce CLAUDE.md Development Convention 9 (every deferral is a
# conscious deferral). Scans kernel source + design docs for deferral
# tokens (TODO/FIXME/eventually/placeholder/TBD/for-now/etc.) and flags
# any without a Revisit when: / Replace when: / named-concept trigger
# within 3 lines. Baseline exemptions in tools/check-deferrals-baseline.txt.
# The goal is to not grow the baseline; don't treat clearing it as a
# session-end imperative. Exits nonzero on new violations.
check-deferrals:
	python3 tools/check-deferrals.py

# Regenerate the deferrals baseline from scratch. Use when you've
# intentionally added a deferral that carries a real (but unrecognized)
# trigger, or when a legitimate cleanup removed pre-existing entries.
# Review the diff before committing.
update-deferrals-baseline:
	python3 tools/check-deferrals.py --update-baseline

# Enforce CLAUDE.md Development Convention 8 (every numeric bound is
# a conscious bound). Scans src/**/*.rs for `const NAME: <numeric> = …`
# declarations and flags any whose preceding 10 lines don't carry one
# of SCAFFOLDING / ARCHITECTURAL / HARDWARE / TUNING. Baseline
# exemptions in tools/check-assumptions-baseline.txt. The goal is to
# not grow the baseline. Exits nonzero on new violations.
check-assumptions:
	python3 tools/check-assumptions.py

# Regenerate the assumptions baseline from scratch. Use when you've
# intentionally added a tagged bound the lint didn't recognize, or
# when a cleanup removed pre-existing entries. Review the diff.
update-assumptions-baseline:
	python3 tools/check-assumptions.py --update-baseline

# Enforce ADR-021 Phase C — no `.expect()` / `panic!()` /
# `unimplemented!()` / `todo!()` in boot-path init code. Scans a
# curated list of files (src/boot/**/*.rs, src/interrupts/mod.rs,
# arch init modules). Runtime fault handlers are out of scope
# (deferred per ADR-019). Baseline exemptions in
# tools/check-boot-panics-baseline.txt; expected empty after
# 021.B.1-B.3 migrations. Exits nonzero on any new site.
check-boot-panics:
	python3 tools/check-boot-panics.py

# Enforcement fails closed (CLAUDE.md § Formal Verification; ADR-006
# § Divergence 2026-10-28): no new fail-open path, in code or in the
# comment describing it, without a reviewed argument. Scans kernel +
# user-space Rust; exempt a structural case with `// FAIL_OPEN_OK:`.
# Baseline at tools/check-fail-open-baseline.txt (expected empty).
check-fail-open:
	python3 tools/check-fail-open.py

update-fail-open-baseline:
	python3 tools/check-fail-open.py --update-baseline

# Regenerate the boot-panics baseline. Use only to acknowledge a
# regression you're intentionally accepting — review the diff and
# the justification before committing.
update-boot-panics-baseline:
	python3 tools/check-boot-panics.py --update-baseline

# Enforce CLAUDE.md Development Convention 1: every `unsafe { ... }`
# block must carry a `// SAFETY:` comment in its preceding comment
# block. Comment-block-aware scanner; cluster + assignment-continuation
# + attribute-line aware. Baseline at
# tools/check-unsafe-coverage-baseline.txt; expected empty after E1
# (prancy-manatee Tier 1 E1 + E3). Exits nonzero on any new site.
check-unsafe-coverage:
	python3 tools/check-unsafe-coverage.py

# Regenerate the unsafe-coverage baseline. Use only to acknowledge a
# regression you're intentionally accepting — review the diff and
# the justification before committing.
update-unsafe-coverage-baseline:
	python3 tools/check-unsafe-coverage.py --update-baseline

# AArch64 targets
KERNEL_AARCH64 := target/aarch64-unknown-none/release/cambios_microkernel
IMG_AARCH64 := cambios-aarch64.img
EFI_FW_AARCH64 := $(shell find /opt/homebrew/Cellar/qemu -name 'edk2-aarch64-code.fd' 2>/dev/null | head -1)

kernel-aarch64:
	cargo build --target aarch64-unknown-none --release

img-aarch64: kernel-aarch64 init-aarch64 manifest-aarch64 $(addsuffix $(SUFFIX_aarch64),$(STAGE_aarch64)) sign-tool limine
	@echo "=== Building AArch64 FAT boot image (signing mode: $(SIGN_MODE)) ==="
	rm -f $(IMG_AARCH64)
	dd if=/dev/zero of=$(IMG_AARCH64) bs=1M count=64
	mformat -i $(IMG_AARCH64) -F ::
	mmd -i $(IMG_AARCH64) ::/EFI
	mmd -i $(IMG_AARCH64) ::/EFI/BOOT
	mmd -i $(IMG_AARCH64) ::/boot
	mmd -i $(IMG_AARCH64) ::/boot/limine
	mcopy -i $(IMG_AARCH64) $(LIMINE_DIR)/BOOTAA64.EFI ::/EFI/BOOT/BOOTAA64.EFI
	mcopy -i $(IMG_AARCH64) $(KERNEL_AARCH64) ::/boot/cambios_microkernel
	# Copy + sign AArch64 boot modules (must match limine.conf module order)
	$(foreach c,$(STAGE_aarch64),cp $(ELF_$(c)_aarch64) /tmp/$(c)-signed.elf$(NL))
	$(foreach c,$(STAGE_aarch64),$(SIGN_ELF) $(SIGN_FLAGS) /tmp/$(c)-signed.elf$(NL))
	$(foreach c,$(STAGE_aarch64),mcopy -i $(IMG_AARCH64) /tmp/$(c)-signed.elf ::/boot/$(c).elf$(NL))
	# ADR-018 step 8 (commit D): init + the signed manifest blob.
	# manifest-aarch64.bin arrives signed by its prerequisite — do NOT
	# re-sign (stacked ARCSIG trailers break verification). Staged as
	# /boot/manifest.bin so the module name matches MANIFEST_MODULE_NAME.
	cp $(ELF_init_aarch64) /tmp/init-signed.elf
	$(SIGN_ELF) $(SIGN_FLAGS) /tmp/init-signed.elf
	mcopy -i $(IMG_AARCH64) /tmp/init-signed.elf ::/boot/init.elf
	rm -f /tmp/init-signed.elf
	mcopy -i $(IMG_AARCH64) manifest-aarch64.bin ::/boot/manifest.bin
	rm -f $(foreach c,$(STAGE_aarch64),/tmp/$(c)-signed.elf)
	mcopy -i $(IMG_AARCH64) limine-aarch64.conf ::/limine.conf
	mcopy -i $(IMG_AARCH64) limine-aarch64.conf ::/boot/limine/limine.conf
	@echo "=== $(IMG_AARCH64) ready ==="

# Serial-only run (no virtio-gpu device attached). Matches the pre-GUI
# aarch64 flow; the kernel + shell still boot, just with no scanout
# device for the compositor to bind to — compositor's handshake blocks
# indefinitely, which is expected in this mode.
run-aarch64: img-aarch64
	qemu-system-aarch64 \
		-machine virt,gic-version=3 \
		-cpu cortex-a72 \
		-smp 2 \
		-m 4G \
		-serial mon:stdio \
		-display none \
		-device qemu-xhci,id=xhci0 \
		-device usb-ccid,bus=xhci0.0 \
		-no-reboot \
		-bios $(EFI_FW_AARCH64) \
		-drive file=$(IMG_AARCH64),format=raw

# GUI-on-aarch64 run: attaches virtio-gpu-pci as the scanout carrier and
# virtio-keyboard-pci as an input carrier. The kernel's ECAM enumerator
# (src/pci/mod.rs `mod ecam`) discovers both; scanout-virtio-gpu +
# virtio-input + compositor + worm bind through them. `-display cocoa`
# opens a macOS window; on Linux swap for `-display gtk` or `sdl`.
run-aarch64-gui: img-aarch64
	qemu-system-aarch64 \
		-machine virt,gic-version=3 \
		-cpu cortex-a72 \
		-smp 2 \
		-m 4G \
		-serial mon:stdio \
		-display cocoa \
		-device virtio-gpu-pci \
		-device virtio-keyboard-pci \
		-device qemu-xhci,id=xhci0 \
		-device usb-ccid,bus=xhci0.0 \
		-no-reboot \
		-bios $(EFI_FW_AARCH64) \
		-drive file=$(IMG_AARCH64),format=raw

# ---------------------------------------------------------------------------
# RISC-V (riscv64gc) targets — Phase R-N (see docs/adr/013, plan file)
#
# Bootloader model: OpenSBI (M-mode) ships with QEMU via `-bios default`
# and hands control to our kernel in S-mode. The kernel's S-mode boot
# stub (src/boot/riscv.rs — Phase R-1) parses the DTB that OpenSBI
# passes in a1 and populates BootInfo. No Limine on RISC-V.
#
# Per the approved plan, hardware is TBD (CambiOS-designed); development
# target is QEMU `-machine virt` as the canonical standards-compliant
# RISC-V machine (NS16550 UART at 0x10000000, PLIC, CLINT, virtio-mmio).
# ---------------------------------------------------------------------------
KERNEL_RISCV64 := target/riscv64gc-unknown-none-elf/release/cambios_microkernel

kernel-riscv64:
	cargo build --target riscv64gc-unknown-none-elf --release

# Build + sign all RISC-V boot modules and pack them into the initrd the
# kernel parses at boot (see src/boot/initrd.rs + src/boot/riscv.rs
# /chosen walker). Produces $(INITRD_RISCV64) in the repo root; QEMU
# passes this via `-initrd`.
#
# Deferred: terminal-window (the GUI shell host) is intentionally NOT in
# the riscv64 initrd. It calls `GuiBackend::open()` before
# `sys::module_ready()`, which would block indefinitely on RISC-V because
# the riscv64 initrd ships no compositor / scanout-virtio-gpu /
# virtio-input — the boot-module release chain would stall and `shell`
# (downstream) would never start. The crate itself builds cleanly via
# `terminal-window-riscv64` so `make check-all` stays green.
# Why: HN demo target is x86_64 + aarch64 only (per plan
# `~/.claude/plans/hi-let-s-talk-about-scalable-sketch.md` § Verification:
# "RISC-V GUI parity is post-HN").
# Revisit when: compositor + scanout-virtio-gpu + virtio-input are
# shipping in the riscv64 initrd (i.e., when GUI parity for riscv64
# becomes a goal). At that point: add terminal-window-riscv64 to the
# img-riscv64 deps, copy + sign + --module here, and pick the right
# slot in BOOT_MODULE_ORDER (between compositor's last GUI dep and
# shell, mirroring x86_64).
img-riscv64: init-riscv64 manifest-riscv64 $(addsuffix $(SUFFIX_riscv64),$(STAGE_riscv64)) sign-tool mkinitrd
	@echo "=== Building RISC-V initrd (signing mode: $(SIGN_MODE)) ==="
	rm -rf initrd_root_riscv64
	mkdir -p initrd_root_riscv64
	# ADR-018 step 8: init rides the initrd signed like any module;
	# manifest-riscv64.bin arrives signed by its prerequisite (no
	# re-sign — stacked trailers break verification) and enters the
	# archive under the name MANIFEST_MODULE_NAME expects. Both first.
	cp $(ELF_init_riscv64) initrd_root_riscv64/init.elf
	$(foreach c,$(STAGE_riscv64),cp $(ELF_$(c)_riscv64) initrd_root_riscv64/$(c).elf$(NL))
	$(SIGN_ELF) $(SIGN_FLAGS) initrd_root_riscv64/init.elf
	$(foreach c,$(STAGE_riscv64),$(SIGN_ELF) $(SIGN_FLAGS) initrd_root_riscv64/$(c).elf$(NL))
	# Module order matches limine.conf on x86_64/aarch64 — the kernel's
	# BOOT_MODULE_ORDER release chain is positional, so the service
	# roster must be identical across arches (future ADR-018 manifest
	# will make this explicit).
	$(MKINITRD) --out $(INITRD_RISCV64) \
		--module manifest.bin=manifest-riscv64.bin \
		--module init=initrd_root_riscv64/init.elf \
		$(foreach c,$(STAGE_riscv64),--module $(c)=initrd_root_riscv64/$(c).elf)
	rm -rf initrd_root_riscv64
	@echo "=== $(INITRD_RISCV64) ready ==="

# Boot the RISC-V kernel in QEMU virt under OpenSBI, with the R-6
# signed boot modules delivered through -initrd.
run-riscv64: kernel-riscv64 img-riscv64
	qemu-system-riscv64 \
		-machine virt \
		-cpu rv64 \
		-smp 2 \
		-m 4G \
		-serial mon:stdio \
		-display none \
		-device qemu-xhci,id=xhci0 \
		-device usb-ccid,bus=xhci0.0 \
		-no-reboot \
		-bios default \
		-kernel $(KERNEL_RISCV64) \
		-initrd $(INITRD_RISCV64)

# ---------------------------------------------------------------------------
# Tri-architecture regression gate. Any commit that breaks any arch is
# blocked. Tracks ADR-013's "Tri-Architecture Regression Discipline".
#
# R-6 landed 2026-04-19 — riscv64 now boots to shell end-to-end under
# QEMU virt. check-all is the permanent gate; check-stable is retained
# only as an escape hatch for future temporary backend breakage during
# deep refactors.
#
#   - check-all: x86_64 + aarch64 + riscv64. The gate every commit
#     must pass.
#
#   - check-stable: x86_64 + aarch64 only. Use ONLY when deliberately
#     in the middle of a refactor that intentionally breaks riscv64,
#     and name the fact in the commit message.
#
# The discipline is the same either way — no commits that regress any
# *currently buildable* architecture.
# ---------------------------------------------------------------------------
check-all: $(addprefix check-,$(ARCHES))
	@echo "=== All three architectures build cleanly ==="

check-stable: check-x86_64 check-aarch64
	@echo "=== x86_64 + aarch64 build cleanly (RISC-V intentionally excluded — see Makefile comment) ==="

# One build rule and one clippy rule per architecture. check-x86 and
# check-clippy-x86 are the historical names for the x86_64 pair.
define ARCH_GATE_RULES
.PHONY: check-$(1) check-clippy-$(1)
check-$(1):
	cargo build --target $$(TRIPLE_$(1)) --release
check-clippy-$(1):
	cargo clippy --target $$(TRIPLE_$(1)) --release --lib
endef
$(foreach a,$(ARCHES),$(eval $(call ARCH_GATE_RULES,$(a))))

check-x86: check-x86_64

# ---------------------------------------------------------------------------
# Tri-arch clippy gate — runs clippy on all three backends so the #![deny]
# unsafe-discipline lints in src/lib.rs (multiple_unsafe_ops_per_block +
# undocumented_unsafe_blocks, Dev Convention 1) are enforced on arch-specific
# code too: x86_64 clippy alone never compiles the cfg-gated aarch64/riscv64
# paths, so a per-op violation there would slip through. missing_safety_doc
# (Cargo.toml [lints.clippy]) hard-fails here as well. CI runs this per-push;
# a genuinely-irreducible unsafe block takes a local `#[allow(...)]` + rationale.
# ---------------------------------------------------------------------------
check-clippy: $(addprefix check-clippy-,$(ARCHES))
	@echo "=== clippy clean on all three architectures ==="

check-clippy-x86: check-clippy-x86_64

# ---------------------------------------------------------------------------
# Fuzzing
#
# The fuzz targets build for an x86_64 host triple: the fuzz build
# exercises the x86_64 backend, which is the only one with host stand-ins
# (`fuzz_asm_stubs`) for the symbols its `global_asm!` blocks define on
# bare metal. A new assembly symbol the kernel references needs a
# stand-in there, or every fuzz target fails to link (`make fuzz-build`
# is what notices). On Apple Silicon the binaries run under Rosetta 2;
# on Linux pass FUZZ_TARGET=x86_64-unknown-linux-gnu.
#
# cargo-fuzz runs under the nightly pinned in rust-toolchain.toml, the
# same compiler that builds the kernel.
#
# `make fuzz-syscall-dispatcher` smoke-runs for 60 s; pass extra
# libfuzzer args via FUZZ_ARGS, e.g.
#   make fuzz-syscall-dispatcher FUZZ_ARGS="-max_total_time=86400"
# for a 24 h run.
.PHONY: fuzz-build fuzz-syscall-dispatcher
FUZZ_ARGS ?= -max_total_time=60 -print_final_stats=1
FUZZ_TARGET ?= x86_64-apple-darwin
fuzz-build:
	cargo fuzz build --fuzz-dir fuzz --target $(FUZZ_TARGET)

fuzz-syscall-dispatcher:
	cargo fuzz run --fuzz-dir fuzz --target $(FUZZ_TARGET) \
		fuzz_syscall_dispatcher -- $(FUZZ_ARGS)

# ---------------------------------------------------------------------------
# Kani proofs — Tier 1 step D (UserSlice invariants) plus the four prior
# proof crates. Each proof crate is workspace-excluded; cargo-kani uses its
# own pinned nightly toolchain. Run individual proof crates from this
# wrapper rather than `cd`-ing into each one.
# verify-<name> runs verification/<name>-proofs; the set is PROOF_CRATES.
VERIFY_TARGETS := $(patsubst %-proofs,verify-%,$(PROOF_CRATES))
.PHONY: verify-all $(VERIFY_TARGETS)
$(VERIFY_TARGETS): verify-%:
	cd verification/$*-proofs && cargo kani

verify-all: $(VERIFY_TARGETS)
	@echo "=== All proof crates verified ==="

clean:
	cargo clean
	rm -f $(ISO) $(IMG_X86) $(IMG_AARCH64) $(INITRD_RISCV64)
	rm -rf iso_root initrd_root_riscv64
