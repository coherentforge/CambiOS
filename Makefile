# Copyright (C) 2024-2026 Jason Ricca. All rights reserved.

# ArcOS Makefile - Build kernel and Limine bootable ISO
#
# Usage:
#   make all     - Build kernel + ISO
#   make run     - Build + run in QEMU (BIOS)
#   make run-uefi - Build + run in QEMU (UEFI)
#   make clean   - Remove build artifacts
#   make test    - Run unit tests
#
# Signing modes:
#   make run                        # YubiKey signing (default, requires ARCOS_SIGN_PIN)
#   make run SIGN_MODE=seed         # Seed-based signing (CI/testing)
#   ARCOS_SIGN_PIN=123456 make run  # YubiKey with PIN via env var

KERNEL := target/x86_64-unknown-none/release/arcos_microkernel
ISO := arcos.iso
LIMINE_DIR := /tmp/limine

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
UDP_STACK_DIR := user/udp-stack
UDP_STACK_ELF := $(UDP_STACK_DIR)/target/x86_64-unknown-none/release/arcos-udp-stack
SHELL_DIR := user/shell
SHELL_ELF := $(SHELL_DIR)/target/x86_64-unknown-none/release/arcos-shell

# User-space ELF binaries (AArch64)
USER_ELF_AARCH64 := user/hello-aarch64.elf
USER_SRC_AARCH64 := user/hello-aarch64.S
USER_LD_AARCH64  := user/user-aarch64.ld
FS_SERVICE_ELF_AARCH64 := $(FS_SERVICE_DIR)/target/aarch64-unknown-none/release/arcos-fs-service
KS_SERVICE_ELF_AARCH64 := $(KS_SERVICE_DIR)/target/aarch64-unknown-none/release/arcos-key-store-service
NET_DRIVER_ELF_AARCH64 := $(NET_DRIVER_DIR)/target/aarch64-unknown-none/release/arcos-virtio-net
UDP_STACK_ELF_AARCH64 := $(UDP_STACK_DIR)/target/aarch64-unknown-none/release/arcos-udp-stack
SHELL_ELF_AARCH64 := $(SHELL_DIR)/target/aarch64-unknown-none/release/arcos-shell

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

.PHONY: all kernel iso run run-uefi test clean img-x86 run-img-x86 img-usb run-img-usb usb verify-usb kernel-aarch64 img-aarch64 run-aarch64 user-elf fs-service key-store-service virtio-net udp-stack shell user-elf-aarch64 fs-service-aarch64 key-store-service-aarch64 virtio-net-aarch64 udp-stack-aarch64 shell-aarch64 sign-tool export-pubkey

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

# AArch64 user-space build targets
user-elf-aarch64:
	@echo "=== Building user-space ELF (AArch64) ==="
	clang -target aarch64-unknown-none -nostdlib -ffreestanding -c $(USER_SRC_AARCH64) -o user/hello-aarch64.o
	ld.lld -T $(USER_LD_AARCH64) -nostdlib --no-dynamic-linker -static user/hello-aarch64.o -o $(USER_ELF_AARCH64)
	@echo "=== $(USER_ELF_AARCH64) ready ==="

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

sign-tool:
	@echo "=== Building ELF signing tool ==="
	cd $(SIGN_ELF_DIR) && cargo build --release
	@echo "=== sign-elf ready ==="

# Export the bootstrap public key from the signing source.
# Run this once after setting up your YubiKey to generate bootstrap_pubkey.bin.
# Usage: make export-pubkey                   (from YubiKey)
#        make export-pubkey SIGN_MODE=seed    (from seed, for dev)
export-pubkey: sign-tool
	$(SIGN_ELF) $(SIGN_FLAGS) --export-pubkey bootstrap_pubkey.bin

iso: kernel user-elf fs-service key-store-service virtio-net udp-stack shell
	@echo "=== Building ISO (signing mode: $(SIGN_MODE)) ==="
	rm -rf iso_root
	mkdir -p iso_root/boot
	mkdir -p iso_root/boot/limine
	mkdir -p iso_root/EFI/BOOT
	# Copy kernel binary
	cp $(KERNEL) iso_root/boot/arcos_microkernel
	# Copy user-space ELF modules
	cp $(USER_ELF) iso_root/boot/hello.elf
	cp $(KS_SERVICE_ELF) iso_root/boot/key-store-service.elf
	cp $(FS_SERVICE_ELF) iso_root/boot/fs-service.elf
	cp $(NET_DRIVER_ELF) iso_root/boot/virtio-net.elf
	cp $(UDP_STACK_ELF) iso_root/boot/udp-stack.elf
	cp $(SHELL_ELF) iso_root/boot/shell.elf
	# Sign all modules (single invocation avoids repeated card contention)
	$(SIGN_ELF) $(SIGN_FLAGS) iso_root/boot/hello.elf
	$(SIGN_ELF) $(SIGN_FLAGS) iso_root/boot/key-store-service.elf
	$(SIGN_ELF) $(SIGN_FLAGS) iso_root/boot/fs-service.elf
	$(SIGN_ELF) $(SIGN_FLAGS) iso_root/boot/virtio-net.elf
	$(SIGN_ELF) $(SIGN_FLAGS) iso_root/boot/udp-stack.elf
	$(SIGN_ELF) $(SIGN_FLAGS) iso_root/boot/shell.elf
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

run: iso
	qemu-system-x86_64 \
		-cdrom $(ISO) \
		-serial mon:stdio \
		-smp 2 \
		-m 128M \
		-device virtio-net-pci \
		-no-reboot

run-uefi: iso
	@cp $(EFI_VARS_X86) /tmp/arcos-efivars.fd
	qemu-system-x86_64 \
		-cdrom $(ISO) \
		-drive if=pflash,format=raw,readonly=on,file=$(EFI_FW_X86) \
		-drive if=pflash,format=raw,file=/tmp/arcos-efivars.fd \
		-serial mon:stdio \
		-m 128M \
		-no-reboot

# x86_64 FAT32 UEFI image — for USB boot on bare metal (Dell 3630 etc.)
# Usage: make img-x86 && sudo dd if=arcos-x86.img of=/dev/diskN bs=1M
IMG_X86 := arcos-x86.img

img-x86: kernel user-elf fs-service key-store-service virtio-net udp-stack shell sign-tool
	@echo "=== Building x86_64 FAT boot image (signing mode: $(SIGN_MODE)) ==="
	rm -f $(IMG_X86)
	dd if=/dev/zero of=$(IMG_X86) bs=1M count=64
	mformat -i $(IMG_X86) -F ::
	mmd -i $(IMG_X86) ::/EFI
	mmd -i $(IMG_X86) ::/EFI/BOOT
	mmd -i $(IMG_X86) ::/boot
	mmd -i $(IMG_X86) ::/boot/limine
	mcopy -i $(IMG_X86) $(LIMINE_DIR)/BOOTX64.EFI ::/EFI/BOOT/BOOTX64.EFI
	mcopy -i $(IMG_X86) $(KERNEL) ::/boot/arcos_microkernel
	# Copy + sign all x86_64 user-space modules
	cp $(USER_ELF) /tmp/hello-signed.elf
	cp $(KS_SERVICE_ELF) /tmp/key-store-service-signed.elf
	cp $(FS_SERVICE_ELF) /tmp/fs-service-signed.elf
	cp $(NET_DRIVER_ELF) /tmp/virtio-net-signed.elf
	cp $(UDP_STACK_ELF) /tmp/udp-stack-signed.elf
	cp $(SHELL_ELF) /tmp/shell-signed.elf
	$(SIGN_ELF) $(SIGN_FLAGS) /tmp/hello-signed.elf
	$(SIGN_ELF) $(SIGN_FLAGS) /tmp/key-store-service-signed.elf
	$(SIGN_ELF) $(SIGN_FLAGS) /tmp/fs-service-signed.elf
	$(SIGN_ELF) $(SIGN_FLAGS) /tmp/virtio-net-signed.elf
	$(SIGN_ELF) $(SIGN_FLAGS) /tmp/udp-stack-signed.elf
	$(SIGN_ELF) $(SIGN_FLAGS) /tmp/shell-signed.elf
	mcopy -i $(IMG_X86) /tmp/hello-signed.elf ::/boot/hello.elf
	mcopy -i $(IMG_X86) /tmp/key-store-service-signed.elf ::/boot/key-store-service.elf
	mcopy -i $(IMG_X86) /tmp/fs-service-signed.elf ::/boot/fs-service.elf
	mcopy -i $(IMG_X86) /tmp/virtio-net-signed.elf ::/boot/virtio-net.elf
	mcopy -i $(IMG_X86) /tmp/udp-stack-signed.elf ::/boot/udp-stack.elf
	mcopy -i $(IMG_X86) /tmp/shell-signed.elf ::/boot/shell.elf
	rm -f /tmp/hello-signed.elf /tmp/key-store-service-signed.elf /tmp/fs-service-signed.elf /tmp/virtio-net-signed.elf /tmp/udp-stack-signed.elf /tmp/shell-signed.elf
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
	@cp $(EFI_VARS_X86) /tmp/arcos-efivars.fd
	qemu-system-x86_64 \
		-drive file=$(IMG_X86),format=raw \
		-drive if=pflash,format=raw,readonly=on,file=$(EFI_FW_X86) \
		-drive if=pflash,format=raw,file=/tmp/arcos-efivars.fd \
		-serial mon:stdio \
		-smp 2 \
		-m 128M \
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

IMG_USB := arcos-usb.img
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
		--change-name=1:"ArcOS ESP" \
		$(IMG_USB) >/dev/null
	# Embed the FAT32 ESP image at LBA 2048 (offset = 2048 * 512 = 1 MiB).
	dd if=$(IMG_X86) of=$(IMG_USB) bs=1M seek=1 conv=notrunc status=none
	@echo "=== $(IMG_USB) ready ($(IMG_USB_SIZE_MB) MiB, GPT + FAT32 ESP) ==="
	@echo "Test in QEMU:    make run-img-usb"
	@echo "Write to USB:    make usb DEVICE=/dev/diskN"

# Test the GPT image in QEMU UEFI (validates before writing to USB)
run-img-usb: img-usb
	@cp $(EFI_VARS_X86) /tmp/arcos-efivars.fd
	qemu-system-x86_64 \
		-drive file=$(IMG_USB),format=raw \
		-drive if=pflash,format=raw,readonly=on,file=$(EFI_FW_X86) \
		-drive if=pflash,format=raw,file=/tmp/arcos-efivars.fd \
		-serial mon:stdio \
		-smp 2 \
		-m 128M \
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
	sudo dd if=$(DEVICE) of=/tmp/arcos-usb-readback.img bs=1M count=$(IMG_USB_SIZE_MB) status=progress
	@echo "Comparing to $(IMG_USB)..."
	@if cmp -s /tmp/arcos-usb-readback.img $(IMG_USB); then \
		echo "✓ USB matches source image (verified $(IMG_USB_SIZE_MB) MiB)"; \
		rm -f /tmp/arcos-usb-readback.img; \
	else \
		echo "✗ MISMATCH: USB does not match $(IMG_USB)"; \
		echo "  Readback saved to /tmp/arcos-usb-readback.img for inspection"; \
		exit 1; \
	fi

test:
	RUST_MIN_STACK=8388608 cargo test --lib --target x86_64-apple-darwin

# AArch64 targets
KERNEL_AARCH64 := target/aarch64-unknown-none/release/arcos_microkernel
IMG_AARCH64 := arcos-aarch64.img
EFI_FW_AARCH64 := $(shell find /opt/homebrew/Cellar/qemu -name 'edk2-aarch64-code.fd' 2>/dev/null | head -1)

kernel-aarch64:
	cargo build --target aarch64-unknown-none --release

img-aarch64: kernel-aarch64 user-elf-aarch64 fs-service-aarch64 key-store-service-aarch64 virtio-net-aarch64 udp-stack-aarch64 shell-aarch64 sign-tool
	@echo "=== Building AArch64 FAT boot image (signing mode: $(SIGN_MODE)) ==="
	rm -f $(IMG_AARCH64)
	dd if=/dev/zero of=$(IMG_AARCH64) bs=1M count=64
	mformat -i $(IMG_AARCH64) -F ::
	mmd -i $(IMG_AARCH64) ::/EFI
	mmd -i $(IMG_AARCH64) ::/EFI/BOOT
	mmd -i $(IMG_AARCH64) ::/boot
	mmd -i $(IMG_AARCH64) ::/boot/limine
	mcopy -i $(IMG_AARCH64) $(LIMINE_DIR)/BOOTAA64.EFI ::/EFI/BOOT/BOOTAA64.EFI
	mcopy -i $(IMG_AARCH64) $(KERNEL_AARCH64) ::/boot/arcos_microkernel
	# Copy + sign all AArch64 user-space modules
	cp $(USER_ELF_AARCH64) /tmp/hello-signed.elf
	cp $(KS_SERVICE_ELF_AARCH64) /tmp/key-store-service-signed.elf
	cp $(FS_SERVICE_ELF_AARCH64) /tmp/fs-service-signed.elf
	cp $(NET_DRIVER_ELF_AARCH64) /tmp/virtio-net-signed.elf
	cp $(UDP_STACK_ELF_AARCH64) /tmp/udp-stack-signed.elf
	cp $(SHELL_ELF_AARCH64) /tmp/shell-signed.elf
	$(SIGN_ELF) $(SIGN_FLAGS) /tmp/hello-signed.elf
	$(SIGN_ELF) $(SIGN_FLAGS) /tmp/key-store-service-signed.elf
	$(SIGN_ELF) $(SIGN_FLAGS) /tmp/fs-service-signed.elf
	$(SIGN_ELF) $(SIGN_FLAGS) /tmp/virtio-net-signed.elf
	$(SIGN_ELF) $(SIGN_FLAGS) /tmp/udp-stack-signed.elf
	$(SIGN_ELF) $(SIGN_FLAGS) /tmp/shell-signed.elf
	mcopy -i $(IMG_AARCH64) /tmp/hello-signed.elf ::/boot/hello.elf
	mcopy -i $(IMG_AARCH64) /tmp/key-store-service-signed.elf ::/boot/key-store-service.elf
	mcopy -i $(IMG_AARCH64) /tmp/fs-service-signed.elf ::/boot/fs-service.elf
	mcopy -i $(IMG_AARCH64) /tmp/virtio-net-signed.elf ::/boot/virtio-net.elf
	mcopy -i $(IMG_AARCH64) /tmp/udp-stack-signed.elf ::/boot/udp-stack.elf
	mcopy -i $(IMG_AARCH64) /tmp/shell-signed.elf ::/boot/shell.elf
	rm -f /tmp/hello-signed.elf /tmp/key-store-service-signed.elf /tmp/fs-service-signed.elf /tmp/virtio-net-signed.elf /tmp/udp-stack-signed.elf /tmp/shell-signed.elf
	mcopy -i $(IMG_AARCH64) limine.conf ::/limine.conf
	mcopy -i $(IMG_AARCH64) limine.conf ::/boot/limine/limine.conf
	@echo "=== $(IMG_AARCH64) ready ==="

run-aarch64: img-aarch64
	qemu-system-aarch64 \
		-machine virt,gic-version=3 \
		-cpu cortex-a72 \
		-smp 2 \
		-m 256M \
		-serial mon:stdio \
		-display none \
		-no-reboot \
		-bios $(EFI_FW_AARCH64) \
		-drive file=$(IMG_AARCH64),format=raw

clean:
	cargo clean
	rm -f $(ISO) $(IMG_X86) $(IMG_AARCH64)
	rm -rf iso_root
