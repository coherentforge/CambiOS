# Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

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

KERNEL := target/x86_64-unknown-none/release/cambios_microkernel
ISO := cambios.iso
LIMINE_DIR := /tmp/limine
LIMINE_BRANCH := v8.x-binary
LIMINE_REPO := https://github.com/limine-bootloader/limine.git

# User-space ELF binaries (x86_64)
USER_ELF := user/hello.elf
USER_SRC := user/hello.S
USER_LD  := user/user.ld
FS_SERVICE_DIR := user/fs-service
FS_SERVICE_ELF := $(FS_SERVICE_DIR)/target/x86_64-unknown-none/release/arcos-fs-service
KS_SERVICE_DIR := user/key-store-service
KS_SERVICE_ELF := $(KS_SERVICE_DIR)/target/x86_64-unknown-none/release/arcos-key-store-service
NET_DRIVER_DIR := user/virtio-net
NET_DRIVER_ELF := $(NET_DRIVER_DIR)/target/x86_64-unknown-none/release/arcos-virtio-net
BLK_DRIVER_DIR := user/virtio-blk
BLK_DRIVER_ELF := $(BLK_DRIVER_DIR)/target/x86_64-unknown-none/release/arcos-virtio-blk
I219_DRIVER_DIR := user/i219-net
I219_DRIVER_ELF := $(I219_DRIVER_DIR)/target/x86_64-unknown-none/release/arcos-i219-net
UDP_STACK_DIR := user/udp-stack
UDP_STACK_ELF := $(UDP_STACK_DIR)/target/x86_64-unknown-none/release/arcos-udp-stack
SHELL_DIR := user/shell
SHELL_ELF := $(SHELL_DIR)/target/x86_64-unknown-none/release/arcos-shell
POLICY_SERVICE_DIR := user/policy-service
POLICY_SERVICE_ELF := $(POLICY_SERVICE_DIR)/target/x86_64-unknown-none/release/arcos-policy-service
FB_DEMO_DIR := user/fb-demo
FB_DEMO_ELF := $(FB_DEMO_DIR)/target/x86_64-unknown-none/release/arcos-fb-demo
COMPOSITOR_DIR := user/compositor
COMPOSITOR_ELF := $(COMPOSITOR_DIR)/target/x86_64-unknown-none/release/arcos-compositor

# User-space ELF binaries (RISC-V)
USER_ELF_RISCV64 := user/hello-riscv64.elf
USER_SRC_RISCV64 := user/hello-riscv64.S
USER_LD_RISCV64  := user/user-riscv64.ld
FS_SERVICE_ELF_RISCV64 := $(FS_SERVICE_DIR)/target/riscv64gc-unknown-none-elf/release/arcos-fs-service
KS_SERVICE_ELF_RISCV64 := $(KS_SERVICE_DIR)/target/riscv64gc-unknown-none-elf/release/arcos-key-store-service
BLK_DRIVER_ELF_RISCV64 := $(BLK_DRIVER_DIR)/target/riscv64gc-unknown-none-elf/release/arcos-virtio-blk
SHELL_ELF_RISCV64 := $(SHELL_DIR)/target/riscv64gc-unknown-none-elf/release/arcos-shell
POLICY_SERVICE_ELF_RISCV64 := $(POLICY_SERVICE_DIR)/target/riscv64gc-unknown-none-elf/release/arcos-policy-service

# RISC-V initrd artifacts
INITRD_RISCV64 := initrd-riscv64.img
MKINITRD_DIR := tools/mkinitrd
MKINITRD := $(MKINITRD_DIR)/target/aarch64-apple-darwin/release/mkinitrd

# User-space ELF binaries (AArch64)
USER_ELF_AARCH64 := user/hello-aarch64.elf
USER_SRC_AARCH64 := user/hello-aarch64.S
USER_LD_AARCH64  := user/user-aarch64.ld
FS_SERVICE_ELF_AARCH64 := $(FS_SERVICE_DIR)/target/aarch64-unknown-none/release/arcos-fs-service
KS_SERVICE_ELF_AARCH64 := $(KS_SERVICE_DIR)/target/aarch64-unknown-none/release/arcos-key-store-service
NET_DRIVER_ELF_AARCH64 := $(NET_DRIVER_DIR)/target/aarch64-unknown-none/release/arcos-virtio-net
BLK_DRIVER_ELF_AARCH64 := $(BLK_DRIVER_DIR)/target/aarch64-unknown-none/release/arcos-virtio-blk
I219_DRIVER_ELF_AARCH64 := $(I219_DRIVER_DIR)/target/aarch64-unknown-none/release/arcos-i219-net
UDP_STACK_ELF_AARCH64 := $(UDP_STACK_DIR)/target/aarch64-unknown-none/release/arcos-udp-stack
SHELL_ELF_AARCH64 := $(SHELL_DIR)/target/aarch64-unknown-none/release/arcos-shell
POLICY_SERVICE_ELF_AARCH64 := $(POLICY_SERVICE_DIR)/target/aarch64-unknown-none/release/arcos-policy-service
FB_DEMO_ELF_AARCH64 := $(FB_DEMO_DIR)/target/aarch64-unknown-none/release/arcos-fb-demo
COMPOSITOR_ELF_AARCH64 := $(COMPOSITOR_DIR)/target/aarch64-unknown-none/release/arcos-compositor

# ELF signing tool
SIGN_ELF_DIR := tools/sign-elf
SIGN_ELF := $(SIGN_ELF_DIR)/target/aarch64-apple-darwin/release/sign-elf

# Signing mode: "yubikey" (default) or "seed" (for CI/testing without hardware key)
SIGN_MODE ?= seed

# Bootstrap seed hex — only used when SIGN_MODE=seed (for dev/CI builds)
BOOTSTRAP_SEED_HEX := 4172634f532d426f6f7473747261702d4964656e746974792d50686173653021

# Resolve sign-elf flags based on signing mode
ifeq ($(SIGN_MODE),seed)
  SIGN_FLAGS := --seed $(BOOTSTRAP_SEED_HEX)
else
  SIGN_FLAGS :=
endif

.PHONY: all kernel iso run run-uefi test clean symbols img-x86 run-img-x86 img-usb run-img-usb usb verify-usb disk-img kernel-aarch64 img-aarch64 run-aarch64 kernel-riscv64 img-riscv64 run-riscv64 check-all check-stable check-x86 check-aarch64 check-riscv64 check-adrs check-deferrals update-deferrals-baseline user-elf fs-service key-store-service virtio-net virtio-blk i219-net udp-stack shell policy-service fb-demo compositor user-elf-aarch64 fs-service-aarch64 key-store-service-aarch64 virtio-net-aarch64 virtio-blk-aarch64 i219-net-aarch64 udp-stack-aarch64 shell-aarch64 policy-service-aarch64 fb-demo-aarch64 compositor-aarch64 fs-service-riscv64 key-store-service-riscv64 virtio-blk-riscv64 shell-riscv64 policy-service-riscv64 sign-tool mkinitrd export-pubkey

all: iso

kernel:
	cargo build --target x86_64-unknown-none --release

user-elf:
	@echo "=== Building user-space ELF ==="
	clang -target x86_64-unknown-none -nostdlib -ffreestanding -c $(USER_SRC) -o user/hello.o
	ld.lld -T $(USER_LD) -nostdlib --no-dynamic-linker -static user/hello.o -o $(USER_ELF)
	@echo "=== $(USER_ELF) ready ==="

fs-service:
	@echo "=== Building FS service ==="
	cd $(FS_SERVICE_DIR) && CARGO_ENCODED_RUSTFLAGS=$$(printf '%s\x1f%s\x1f%s\x1f%s' \
		'-Clink-arg=--script=link.ld' '-Clink-arg=-z' '-Clink-arg=noexecstack' \
		'-Crelocation-model=static') cargo build --release
	@echo "=== FS service ready ==="

key-store-service:
	@echo "=== Building Key Store service ==="
	cd $(KS_SERVICE_DIR) && CARGO_ENCODED_RUSTFLAGS=$$(printf '%s\x1f%s\x1f%s\x1f%s' \
		'-Clink-arg=--script=link.ld' '-Clink-arg=-z' '-Clink-arg=noexecstack' \
		'-Crelocation-model=static') cargo build --release
	@echo "=== Key Store service ready ==="

virtio-net:
	@echo "=== Building Virtio-Net driver ==="
	cd $(NET_DRIVER_DIR) && CARGO_ENCODED_RUSTFLAGS=$$(printf '%s\x1f%s\x1f%s\x1f%s' \
		'-Clink-arg=--script=link.ld' '-Clink-arg=-z' '-Clink-arg=noexecstack' \
		'-Crelocation-model=static') cargo build --release
	@echo "=== Virtio-Net driver ready ==="

virtio-blk:
	@echo "=== Building Virtio-Blk driver ==="
	cd $(BLK_DRIVER_DIR) && CARGO_ENCODED_RUSTFLAGS=$$(printf '%s\x1f%s\x1f%s\x1f%s' \
		'-Clink-arg=--script=link.ld' '-Clink-arg=-z' '-Clink-arg=noexecstack' \
		'-Crelocation-model=static') cargo build --release
	@echo "=== Virtio-Blk driver ready ==="

i219-net:
	@echo "=== Building Intel I219-LM driver ==="
	cd $(I219_DRIVER_DIR) && CARGO_ENCODED_RUSTFLAGS=$$(printf '%s\x1f%s\x1f%s\x1f%s' \
		'-Clink-arg=--script=link.ld' '-Clink-arg=-z' '-Clink-arg=noexecstack' \
		'-Crelocation-model=static') cargo build --release
	@echo "=== I219-LM driver ready ==="

udp-stack:
	@echo "=== Building UDP stack ==="
	cd $(UDP_STACK_DIR) && CARGO_ENCODED_RUSTFLAGS=$$(printf '%s\x1f%s\x1f%s\x1f%s' \
		'-Clink-arg=--script=link.ld' '-Clink-arg=-z' '-Clink-arg=noexecstack' \
		'-Crelocation-model=static') cargo build --release
	@echo "=== UDP stack ready ==="

shell:
	@echo "=== Building Shell ==="
	cd $(SHELL_DIR) && CARGO_ENCODED_RUSTFLAGS=$$(printf '%s\x1f%s\x1f%s\x1f%s' \
		'-Clink-arg=--script=link.ld' '-Clink-arg=-z' '-Clink-arg=noexecstack' \
		'-Crelocation-model=static') cargo build --release
	@echo "=== Shell ready ==="

policy-service:
	@echo "=== Building Policy service ==="
	cd $(POLICY_SERVICE_DIR) && CARGO_ENCODED_RUSTFLAGS=$$(printf '%s\x1f%s\x1f%s\x1f%s' \
		'-Clink-arg=--script=link.ld' '-Clink-arg=-z' '-Clink-arg=noexecstack' \
		'-Crelocation-model=static') cargo build --release
	@echo "=== Policy service ready ==="

fb-demo:
	@echo "=== Building fb-demo (Phase GUI-1) ==="
	cd $(FB_DEMO_DIR) && CARGO_ENCODED_RUSTFLAGS=$$(printf '%s\x1f%s\x1f%s\x1f%s' \
		'-Clink-arg=--script=link.ld' '-Clink-arg=-z' '-Clink-arg=noexecstack' \
		'-Crelocation-model=static') cargo build --release
	@echo "=== fb-demo ready ==="

compositor:
	@echo "=== Building compositor (Phase Scanout-1, ADR-014) ==="
	cd $(COMPOSITOR_DIR) && CARGO_ENCODED_RUSTFLAGS=$$(printf '%s\x1f%s\x1f%s\x1f%s' \
		'-Clink-arg=--script=link.ld' '-Clink-arg=-z' '-Clink-arg=noexecstack' \
		'-Crelocation-model=static') cargo build --release
	@echo "=== compositor ready ==="

# AArch64 user-space build targets
user-elf-aarch64:
	@echo "=== Building user-space ELF (AArch64) ==="
	clang -target aarch64-unknown-none -nostdlib -ffreestanding -c $(USER_SRC_AARCH64) -o user/hello-aarch64.o
	ld.lld -T $(USER_LD_AARCH64) -nostdlib --no-dynamic-linker -static user/hello-aarch64.o -o $(USER_ELF_AARCH64)
	@echo "=== $(USER_ELF_AARCH64) ready ==="

# RISC-V user-space build targets
user-elf-riscv64: $(USER_ELF_RISCV64)

$(USER_ELF_RISCV64): $(USER_SRC_RISCV64) $(USER_LD_RISCV64)
	@echo "=== Building user-space ELF (RISC-V) ==="
	clang -target riscv64-unknown-none-elf -march=rv64gc -mno-relax \
		-nostdlib -ffreestanding -c $(USER_SRC_RISCV64) -o user/hello-riscv64.o
	ld.lld -T $(USER_LD_RISCV64) -nostdlib --no-dynamic-linker -static \
		user/hello-riscv64.o -o $(USER_ELF_RISCV64)
	@echo "=== $(USER_ELF_RISCV64) ready ==="

fs-service-aarch64:
	@echo "=== Building FS service (AArch64) ==="
	cd $(FS_SERVICE_DIR) && CARGO_ENCODED_RUSTFLAGS=$$(printf '%s\x1f%s\x1f%s\x1f%s' \
		'-Clink-arg=--script=link-aarch64.ld' '-Clink-arg=-z' '-Clink-arg=noexecstack' \
		'-Crelocation-model=static') cargo build --target aarch64-unknown-none --release
	@echo "=== FS service (AArch64) ready ==="

key-store-service-aarch64:
	@echo "=== Building Key Store service (AArch64) ==="
	cd $(KS_SERVICE_DIR) && CARGO_ENCODED_RUSTFLAGS=$$(printf '%s\x1f%s\x1f%s\x1f%s' \
		'-Clink-arg=--script=link-aarch64.ld' '-Clink-arg=-z' '-Clink-arg=noexecstack' \
		'-Crelocation-model=static') cargo build --target aarch64-unknown-none --release
	@echo "=== Key Store service (AArch64) ready ==="

virtio-net-aarch64:
	@echo "=== Building Virtio-Net driver (AArch64) ==="
	cd $(NET_DRIVER_DIR) && CARGO_ENCODED_RUSTFLAGS=$$(printf '%s\x1f%s\x1f%s\x1f%s' \
		'-Clink-arg=--script=link-aarch64.ld' '-Clink-arg=-z' '-Clink-arg=noexecstack' \
		'-Crelocation-model=static') cargo build --target aarch64-unknown-none --release
	@echo "=== Virtio-Net driver (AArch64) ready ==="

virtio-blk-aarch64:
	@echo "=== Building Virtio-Blk driver (AArch64) ==="
	cd $(BLK_DRIVER_DIR) && CARGO_ENCODED_RUSTFLAGS=$$(printf '%s\x1f%s\x1f%s\x1f%s' \
		'-Clink-arg=--script=link-aarch64.ld' '-Clink-arg=-z' '-Clink-arg=noexecstack' \
		'-Crelocation-model=static') cargo build --target aarch64-unknown-none --release
	@echo "=== Virtio-Blk driver (AArch64) ready ==="

i219-net-aarch64:
	@echo "=== Building Intel I219-LM driver (AArch64) ==="
	cd $(I219_DRIVER_DIR) && CARGO_ENCODED_RUSTFLAGS=$$(printf '%s\x1f%s\x1f%s\x1f%s' \
		'-Clink-arg=--script=link-aarch64.ld' '-Clink-arg=-z' '-Clink-arg=noexecstack' \
		'-Crelocation-model=static') cargo build --target aarch64-unknown-none --release
	@echo "=== I219-LM driver (AArch64) ready ==="

udp-stack-aarch64:
	@echo "=== Building UDP stack (AArch64) ==="
	cd $(UDP_STACK_DIR) && CARGO_ENCODED_RUSTFLAGS=$$(printf '%s\x1f%s\x1f%s\x1f%s' \
		'-Clink-arg=--script=link-aarch64.ld' '-Clink-arg=-z' '-Clink-arg=noexecstack' \
		'-Crelocation-model=static') cargo build --target aarch64-unknown-none --release
	@echo "=== UDP stack (AArch64) ready ==="

shell-aarch64:
	@echo "=== Building Shell (AArch64) ==="
	cd $(SHELL_DIR) && CARGO_ENCODED_RUSTFLAGS=$$(printf '%s\x1f%s\x1f%s\x1f%s' \
		'-Clink-arg=--script=link-aarch64.ld' '-Clink-arg=-z' '-Clink-arg=noexecstack' \
		'-Crelocation-model=static') cargo build --target aarch64-unknown-none --release
	@echo "=== Shell (AArch64) ready ==="

policy-service-aarch64:
	@echo "=== Building Policy service (AArch64) ==="
	cd $(POLICY_SERVICE_DIR) && CARGO_ENCODED_RUSTFLAGS=$$(printf '%s\x1f%s\x1f%s\x1f%s' \
		'-Clink-arg=--script=link-aarch64.ld' '-Clink-arg=-z' '-Clink-arg=noexecstack' \
		'-Crelocation-model=static') cargo build --target aarch64-unknown-none --release
	@echo "=== Policy service (AArch64) ready ==="

fb-demo-aarch64:
	@echo "=== Building fb-demo (AArch64) ==="
	cd $(FB_DEMO_DIR) && CARGO_ENCODED_RUSTFLAGS=$$(printf '%s\x1f%s\x1f%s\x1f%s' \
		'-Clink-arg=--script=link-aarch64.ld' '-Clink-arg=-z' '-Clink-arg=noexecstack' \
		'-Crelocation-model=static') cargo build --target aarch64-unknown-none --release
	@echo "=== fb-demo (AArch64) ready ==="

compositor-aarch64:
	@echo "=== Building compositor (AArch64) ==="
	cd $(COMPOSITOR_DIR) && CARGO_ENCODED_RUSTFLAGS=$$(printf '%s\x1f%s\x1f%s\x1f%s' \
		'-Clink-arg=--script=link-aarch64.ld' '-Clink-arg=-z' '-Clink-arg=noexecstack' \
		'-Crelocation-model=static') cargo build --target aarch64-unknown-none --release
	@echo "=== compositor (AArch64) ready ==="

# RISC-V user-space build targets (R-6 / ADR-013)
# Services build with the same CARGO_ENCODED_RUSTFLAGS shape as x86_64/aarch64;
# only the linker script and target triple differ.
fs-service-riscv64:
	@echo "=== Building FS service (RISC-V) ==="
	cd $(FS_SERVICE_DIR) && CARGO_ENCODED_RUSTFLAGS=$$(printf '%s\x1f%s\x1f%s\x1f%s' \
		'-Clink-arg=--script=link-riscv64.ld' '-Clink-arg=-z' '-Clink-arg=noexecstack' \
		'-Crelocation-model=static') cargo build --target riscv64gc-unknown-none-elf --release
	@echo "=== FS service (RISC-V) ready ==="

key-store-service-riscv64:
	@echo "=== Building Key Store service (RISC-V) ==="
	cd $(KS_SERVICE_DIR) && CARGO_ENCODED_RUSTFLAGS=$$(printf '%s\x1f%s\x1f%s\x1f%s' \
		'-Clink-arg=--script=link-riscv64.ld' '-Clink-arg=-z' '-Clink-arg=noexecstack' \
		'-Crelocation-model=static') cargo build --target riscv64gc-unknown-none-elf --release
	@echo "=== Key Store service (RISC-V) ready ==="

virtio-blk-riscv64:
	@echo "=== Building Virtio-Blk driver (RISC-V) ==="
	cd $(BLK_DRIVER_DIR) && CARGO_ENCODED_RUSTFLAGS=$$(printf '%s\x1f%s\x1f%s\x1f%s' \
		'-Clink-arg=--script=link-riscv64.ld' '-Clink-arg=-z' '-Clink-arg=noexecstack' \
		'-Crelocation-model=static') cargo build --target riscv64gc-unknown-none-elf --release
	@echo "=== Virtio-Blk driver (RISC-V) ready ==="

shell-riscv64:
	@echo "=== Building Shell (RISC-V) ==="
	cd $(SHELL_DIR) && CARGO_ENCODED_RUSTFLAGS=$$(printf '%s\x1f%s\x1f%s\x1f%s' \
		'-Clink-arg=--script=link-riscv64.ld' '-Clink-arg=-z' '-Clink-arg=noexecstack' \
		'-Crelocation-model=static') cargo build --target riscv64gc-unknown-none-elf --release
	@echo "=== Shell (RISC-V) ready ==="

policy-service-riscv64:
	@echo "=== Building Policy service (RISC-V) ==="
	cd $(POLICY_SERVICE_DIR) && CARGO_ENCODED_RUSTFLAGS=$$(printf '%s\x1f%s\x1f%s\x1f%s' \
		'-Clink-arg=--script=link-riscv64.ld' '-Clink-arg=-z' '-Clink-arg=noexecstack' \
		'-Crelocation-model=static') cargo build --target riscv64gc-unknown-none-elf --release
	@echo "=== Policy service (RISC-V) ready ==="

sign-tool:
	@echo "=== Building ELF signing tool ==="
	cd $(SIGN_ELF_DIR) && cargo build --release
	@echo "=== sign-elf ready ==="

mkinitrd:
	@echo "=== Building mkinitrd host tool ==="
	cd $(MKINITRD_DIR) && cargo build --release
	@echo "=== mkinitrd ready ==="

# Export the bootstrap public key from the signing source.
# Run this once after setting up your YubiKey to generate bootstrap_pubkey.bin.
# Usage: make export-pubkey                   (from YubiKey)
#        make export-pubkey SIGN_MODE=seed    (from seed, for dev)
export-pubkey: sign-tool
	$(SIGN_ELF) $(SIGN_FLAGS) --export-pubkey bootstrap_pubkey.bin

# Auto-clone Limine if /tmp/limine was cleaned (reboot, macOS periodic cleanup, etc.)
$(LIMINE_DIR)/BOOTX64.EFI $(LIMINE_DIR)/BOOTAA64.EFI:
	@echo "=== Cloning Limine $(LIMINE_BRANCH) ==="
	git clone $(LIMINE_REPO) --branch=$(LIMINE_BRANCH) --depth=1 $(LIMINE_DIR)

limine: $(LIMINE_DIR)/BOOTX64.EFI

iso: kernel fs-service key-store-service virtio-blk shell policy-service fb-demo compositor sign-tool limine
	@echo "=== Building ISO (signing mode: $(SIGN_MODE)) ==="
	rm -rf iso_root
	mkdir -p iso_root/boot
	mkdir -p iso_root/boot/limine
	mkdir -p iso_root/EFI/BOOT
	# Copy kernel binary
	cp $(KERNEL) iso_root/boot/cambios_microkernel
	# Copy + sign boot modules (must match limine.conf module order)
	cp $(POLICY_SERVICE_ELF) iso_root/boot/policy-service.elf
	cp $(KS_SERVICE_ELF) iso_root/boot/key-store-service.elf
	cp $(FS_SERVICE_ELF) iso_root/boot/fs-service.elf
	cp $(BLK_DRIVER_ELF) iso_root/boot/virtio-blk.elf
	cp $(SHELL_ELF) iso_root/boot/shell.elf
	cp $(FB_DEMO_ELF) iso_root/boot/fb-demo.elf
	cp $(COMPOSITOR_ELF) iso_root/boot/compositor.elf
	$(SIGN_ELF) $(SIGN_FLAGS) iso_root/boot/policy-service.elf
	$(SIGN_ELF) $(SIGN_FLAGS) iso_root/boot/key-store-service.elf
	$(SIGN_ELF) $(SIGN_FLAGS) iso_root/boot/fs-service.elf
	$(SIGN_ELF) $(SIGN_FLAGS) iso_root/boot/virtio-blk.elf
	$(SIGN_ELF) $(SIGN_FLAGS) iso_root/boot/shell.elf
	$(SIGN_ELF) $(SIGN_FLAGS) iso_root/boot/fb-demo.elf
	$(SIGN_ELF) $(SIGN_FLAGS) iso_root/boot/compositor.elf
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
	rm -rf iso_root
	@echo "=== $(ISO) ready ==="

# Persistent backing file for the virtio-blk device. 64 MiB is enough for
# the Phase 4a.i DiskObjectStore with 4096-slot capacity (~32 MiB used) plus
# room to grow. The image file persists across `make run` invocations, which
# is the whole point — reboot-cycle testing needs the bytes to survive.
DISK_IMG := cambios-disk.img
DISK_SIZE_MB := 64

disk-img:
	@if [ ! -f $(DISK_IMG) ]; then \
		echo "=== Creating $(DISK_IMG) ($(DISK_SIZE_MB) MiB) ==="; \
		qemu-img create -f raw $(DISK_IMG) $(DISK_SIZE_MB)M; \
	else \
		echo "=== $(DISK_IMG) already exists; leaving it alone ==="; \
	fi

run: iso disk-img
	qemu-system-x86_64 \
		-cdrom $(ISO) \
		-serial mon:stdio \
		-smp 2 \
		-m 4G \
		-device virtio-net-pci \
		-drive file=$(DISK_IMG),if=none,format=raw,id=cambios-disk0 \
		-device virtio-blk-pci,drive=cambios-disk0 \
		-no-reboot

run-uefi: iso
	@cp $(EFI_VARS_X86) /tmp/cambios-efivars.fd
	qemu-system-x86_64 \
		-cdrom $(ISO) \
		-drive if=pflash,format=raw,readonly=on,file=$(EFI_FW_X86) \
		-drive if=pflash,format=raw,file=/tmp/cambios-efivars.fd \
		-serial mon:stdio \
		-m 4G \
		-no-reboot

# x86_64 FAT32 UEFI image — for USB boot on bare metal (Dell 3630 etc.)
# Usage: make img-x86 && sudo dd if=cambios-x86.img of=/dev/diskN bs=1M
IMG_X86 := cambios-x86.img

img-x86: kernel user-elf fs-service key-store-service virtio-net i219-net udp-stack shell policy-service virtio-blk compositor sign-tool limine
	@echo "=== Building x86_64 FAT boot image (signing mode: $(SIGN_MODE)) ==="
	rm -f $(IMG_X86)
	dd if=/dev/zero of=$(IMG_X86) bs=1M count=64
	mformat -i $(IMG_X86) -F ::
	mmd -i $(IMG_X86) ::/EFI
	mmd -i $(IMG_X86) ::/EFI/BOOT
	mmd -i $(IMG_X86) ::/boot
	mmd -i $(IMG_X86) ::/boot/limine
	mcopy -i $(IMG_X86) $(LIMINE_DIR)/BOOTX64.EFI ::/EFI/BOOT/BOOTX64.EFI
	mcopy -i $(IMG_X86) $(KERNEL) ::/boot/cambios_microkernel
	# Copy + sign all x86_64 user-space modules
	cp $(USER_ELF) /tmp/hello-signed.elf
	cp $(KS_SERVICE_ELF) /tmp/key-store-service-signed.elf
	cp $(FS_SERVICE_ELF) /tmp/fs-service-signed.elf
	cp $(NET_DRIVER_ELF) /tmp/virtio-net-signed.elf
	cp $(I219_DRIVER_ELF) /tmp/i219-net-signed.elf
	cp $(UDP_STACK_ELF) /tmp/udp-stack-signed.elf
	cp $(SHELL_ELF) /tmp/shell-signed.elf
	cp $(POLICY_SERVICE_ELF) /tmp/policy-service-signed.elf
	cp $(BLK_DRIVER_ELF) /tmp/virtio-blk-signed.elf
	cp $(COMPOSITOR_ELF) /tmp/compositor-signed.elf
	$(SIGN_ELF) $(SIGN_FLAGS) /tmp/hello-signed.elf
	$(SIGN_ELF) $(SIGN_FLAGS) /tmp/key-store-service-signed.elf
	$(SIGN_ELF) $(SIGN_FLAGS) /tmp/fs-service-signed.elf
	$(SIGN_ELF) $(SIGN_FLAGS) /tmp/virtio-net-signed.elf
	$(SIGN_ELF) $(SIGN_FLAGS) /tmp/i219-net-signed.elf
	$(SIGN_ELF) $(SIGN_FLAGS) /tmp/udp-stack-signed.elf
	$(SIGN_ELF) $(SIGN_FLAGS) /tmp/shell-signed.elf
	$(SIGN_ELF) $(SIGN_FLAGS) /tmp/policy-service-signed.elf
	$(SIGN_ELF) $(SIGN_FLAGS) /tmp/virtio-blk-signed.elf
	$(SIGN_ELF) $(SIGN_FLAGS) /tmp/compositor-signed.elf
	mcopy -i $(IMG_X86) /tmp/hello-signed.elf ::/boot/hello.elf
	mcopy -i $(IMG_X86) /tmp/key-store-service-signed.elf ::/boot/key-store-service.elf
	mcopy -i $(IMG_X86) /tmp/fs-service-signed.elf ::/boot/fs-service.elf
	mcopy -i $(IMG_X86) /tmp/virtio-net-signed.elf ::/boot/virtio-net.elf
	mcopy -i $(IMG_X86) /tmp/i219-net-signed.elf ::/boot/i219-net.elf
	mcopy -i $(IMG_X86) /tmp/udp-stack-signed.elf ::/boot/udp-stack.elf
	mcopy -i $(IMG_X86) /tmp/shell-signed.elf ::/boot/shell.elf
	mcopy -i $(IMG_X86) /tmp/policy-service-signed.elf ::/boot/policy-service.elf
	mcopy -i $(IMG_X86) /tmp/virtio-blk-signed.elf ::/boot/virtio-blk.elf
	mcopy -i $(IMG_X86) /tmp/compositor-signed.elf ::/boot/compositor.elf
	rm -f /tmp/hello-signed.elf /tmp/key-store-service-signed.elf /tmp/fs-service-signed.elf /tmp/virtio-net-signed.elf /tmp/i219-net-signed.elf /tmp/udp-stack-signed.elf /tmp/shell-signed.elf /tmp/policy-service-signed.elf /tmp/virtio-blk-signed.elf /tmp/compositor-signed.elf
	mcopy -i $(IMG_X86) limine.conf ::/limine.conf
	mcopy -i $(IMG_X86) limine.conf ::/boot/limine/limine.conf
	@echo "=== $(IMG_X86) ready ==="
	@echo "To write to USB: sudo dd if=$(IMG_X86) of=/dev/diskN bs=1M"

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
		-device virtio-net-pci \
		-no-reboot

# ============================================================================
# USB boot image (GPT-partitioned, UEFI-bootable)
# ============================================================================
#
# Builds a GPT-partitioned disk image with a single EFI System Partition
# (ESP) containing all kernel + signed user-space modules. Suitable for
# `dd`-ing to a USB stick and booting on bare-metal UEFI systems
# (Dell 3630, etc.).
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
run-img-usb: img-usb
	@cp $(EFI_VARS_X86) /tmp/cambios-efivars.fd
	qemu-system-x86_64 \
		-drive file=$(IMG_USB),format=raw \
		-drive if=pflash,format=raw,readonly=on,file=$(EFI_FW_X86) \
		-drive if=pflash,format=raw,file=/tmp/cambios-efivars.fd \
		-serial mon:stdio \
		-smp 2 \
		-m 4G \
		-device virtio-net-pci \
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
	@echo "Reading $(IMG_USB_SIZE_MB) MiB from $(DEVICE)..."
	@diskutil unmountDisk $(DEVICE) 2>/dev/null || true
	sudo dd if=$(DEVICE) of=/tmp/cambios-usb-readback.img bs=1M count=$(IMG_USB_SIZE_MB) status=progress
	@echo "Comparing to $(IMG_USB)..."
	@if cmp -s /tmp/cambios-usb-readback.img $(IMG_USB); then \
		echo "✓ USB matches source image (verified $(IMG_USB_SIZE_MB) MiB)"; \
		rm -f /tmp/cambios-usb-readback.img; \
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
# Run after any change to a proven module (currently: BuddyAllocator).
# A proof failure means the property no longer holds — investigate before
# committing.
# =============================================================================
.PHONY: verify
verify:
	@echo "=== Kani proofs: BuddyAllocator ==="
	cd verification/buddy-proofs && cargo kani

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
stats:
	@echo "=== CambiOS stats (derived from source) ==="
	@printf "Syscalls:        "
	@sed -n '/^pub enum SyscallNumber/,/^}/p' src/syscalls/mod.rs | grep -Ec '^[[:space:]]+[A-Z][A-Za-z]+ = [0-9]+,'
	@printf "Kernel .rs:      "
	@find src -name '*.rs' | wc -l | tr -d ' '
	@printf "Userspace .rs:   "
	@find user -name '*.rs' -not -path '*/target/*' | wc -l | tr -d ' '
	@printf "Tests (lib):     "
	@RUST_MIN_STACK=8388608 cargo test --lib --target x86_64-apple-darwin -- --list 2>/dev/null | awk '/^[0-9]+ tests?,/ {print $$1; found=1; exit} END {if (!found) print "(build first: make test)"}'

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

# AArch64 targets
KERNEL_AARCH64 := target/aarch64-unknown-none/release/cambios_microkernel
IMG_AARCH64 := cambios-aarch64.img
EFI_FW_AARCH64 := $(shell find /opt/homebrew/Cellar/qemu -name 'edk2-aarch64-code.fd' 2>/dev/null | head -1)

kernel-aarch64:
	cargo build --target aarch64-unknown-none --release

img-aarch64: kernel-aarch64 fs-service-aarch64 key-store-service-aarch64 virtio-blk-aarch64 shell-aarch64 policy-service-aarch64 compositor-aarch64 sign-tool limine
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
	cp $(POLICY_SERVICE_ELF_AARCH64) /tmp/policy-service-signed.elf
	cp $(KS_SERVICE_ELF_AARCH64) /tmp/key-store-service-signed.elf
	cp $(FS_SERVICE_ELF_AARCH64) /tmp/fs-service-signed.elf
	cp $(BLK_DRIVER_ELF_AARCH64) /tmp/virtio-blk-signed.elf
	cp $(SHELL_ELF_AARCH64) /tmp/shell-signed.elf
	cp $(COMPOSITOR_ELF_AARCH64) /tmp/compositor-signed.elf
	$(SIGN_ELF) $(SIGN_FLAGS) /tmp/policy-service-signed.elf
	$(SIGN_ELF) $(SIGN_FLAGS) /tmp/key-store-service-signed.elf
	$(SIGN_ELF) $(SIGN_FLAGS) /tmp/fs-service-signed.elf
	$(SIGN_ELF) $(SIGN_FLAGS) /tmp/virtio-blk-signed.elf
	$(SIGN_ELF) $(SIGN_FLAGS) /tmp/shell-signed.elf
	$(SIGN_ELF) $(SIGN_FLAGS) /tmp/compositor-signed.elf
	mcopy -i $(IMG_AARCH64) /tmp/policy-service-signed.elf ::/boot/policy-service.elf
	mcopy -i $(IMG_AARCH64) /tmp/key-store-service-signed.elf ::/boot/key-store-service.elf
	mcopy -i $(IMG_AARCH64) /tmp/fs-service-signed.elf ::/boot/fs-service.elf
	mcopy -i $(IMG_AARCH64) /tmp/virtio-blk-signed.elf ::/boot/virtio-blk.elf
	mcopy -i $(IMG_AARCH64) /tmp/shell-signed.elf ::/boot/shell.elf
	mcopy -i $(IMG_AARCH64) /tmp/compositor-signed.elf ::/boot/compositor.elf
	rm -f /tmp/policy-service-signed.elf /tmp/key-store-service-signed.elf /tmp/fs-service-signed.elf /tmp/virtio-blk-signed.elf /tmp/shell-signed.elf /tmp/compositor-signed.elf
	mcopy -i $(IMG_AARCH64) limine.conf ::/limine.conf
	mcopy -i $(IMG_AARCH64) limine.conf ::/boot/limine/limine.conf
	@echo "=== $(IMG_AARCH64) ready ==="

run-aarch64: img-aarch64
	qemu-system-aarch64 \
		-machine virt,gic-version=3 \
		-cpu cortex-a72 \
		-smp 2 \
		-m 4G \
		-serial mon:stdio \
		-display none \
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

# hello-riscv64.elf is no longer include_bytes!'d by the kernel (R-6
# replaced it with the initrd path), so no user-elf dependency here.
# The user/hello-riscv64.S assembly source remains for one-off smoke
# testing via `make user-elf-riscv64`.
kernel-riscv64:
	cargo build --target riscv64gc-unknown-none-elf --release

# Build + sign all RISC-V boot modules and pack them into the initrd the
# kernel parses at boot (see src/boot/initrd.rs + src/boot/riscv.rs
# /chosen walker). Produces $(INITRD_RISCV64) in the repo root; QEMU
# passes this via `-initrd`.
img-riscv64: policy-service-riscv64 key-store-service-riscv64 fs-service-riscv64 virtio-blk-riscv64 shell-riscv64 sign-tool mkinitrd
	@echo "=== Building RISC-V initrd (signing mode: $(SIGN_MODE)) ==="
	rm -rf initrd_root_riscv64
	mkdir -p initrd_root_riscv64
	cp $(POLICY_SERVICE_ELF_RISCV64) initrd_root_riscv64/policy-service.elf
	cp $(KS_SERVICE_ELF_RISCV64)     initrd_root_riscv64/key-store-service.elf
	cp $(FS_SERVICE_ELF_RISCV64)     initrd_root_riscv64/fs-service.elf
	cp $(BLK_DRIVER_ELF_RISCV64)     initrd_root_riscv64/virtio-blk.elf
	cp $(SHELL_ELF_RISCV64)          initrd_root_riscv64/shell.elf
	$(SIGN_ELF) $(SIGN_FLAGS) initrd_root_riscv64/policy-service.elf
	$(SIGN_ELF) $(SIGN_FLAGS) initrd_root_riscv64/key-store-service.elf
	$(SIGN_ELF) $(SIGN_FLAGS) initrd_root_riscv64/fs-service.elf
	$(SIGN_ELF) $(SIGN_FLAGS) initrd_root_riscv64/virtio-blk.elf
	$(SIGN_ELF) $(SIGN_FLAGS) initrd_root_riscv64/shell.elf
	# Module order matches limine.conf on x86_64/aarch64 — the kernel's
	# BOOT_MODULE_ORDER release chain is positional, so the service
	# roster must be identical across arches (future ADR-018 manifest
	# will make this explicit).
	$(MKINITRD) --out $(INITRD_RISCV64) \
		--module policy-service=initrd_root_riscv64/policy-service.elf \
		--module key-store-service=initrd_root_riscv64/key-store-service.elf \
		--module fs-service=initrd_root_riscv64/fs-service.elf \
		--module virtio-blk=initrd_root_riscv64/virtio-blk.elf \
		--module shell=initrd_root_riscv64/shell.elf
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
		-no-reboot \
		-bios default \
		-kernel $(KERNEL_RISCV64) \
		-initrd $(INITRD_RISCV64)

# ---------------------------------------------------------------------------
# Tri-architecture regression gate. Any commit that breaks any arch is
# blocked. Tracks ADR-013's "Tri-Architecture Regression Discipline".
#
# Two gates exist:
#
#   - check-stable: x86_64 + aarch64 only. Use this during Phases R-1
#     through R-6 of the RISC-V port, when the riscv64 backend is
#     under construction and not expected to build between phase
#     boundaries. Every commit during the RISC-V buildup must pass
#     check-stable.
#
#   - check-all: all three including riscv64. Use this once a RISC-V
#     phase milestone has restored the backend to a buildable state,
#     and as the permanent gate after Phase R-6 lands. Every commit
#     post-R-6 must pass check-all.
#
# The discipline is the same either way — no commits that regress any
# *currently buildable* architecture. The two gates exist only because
# the riscv64 backend is mid-construction.
# ---------------------------------------------------------------------------
check-all: check-x86 check-aarch64 check-riscv64
	@echo "=== All three architectures build cleanly ==="

check-stable: check-x86 check-aarch64
	@echo "=== x86_64 + aarch64 build cleanly (RISC-V intentionally excluded — see Makefile comment) ==="

check-x86:
	cargo build --target x86_64-unknown-none --release

check-aarch64:
	cargo build --target aarch64-unknown-none --release

check-riscv64:
	cargo build --target riscv64gc-unknown-none-elf --release

clean:
	cargo clean
	rm -f $(ISO) $(IMG_X86) $(IMG_AARCH64) $(INITRD_RISCV64)
	rm -rf iso_root initrd_root_riscv64
