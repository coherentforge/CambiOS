# ArcOS Makefile - Build kernel and Limine bootable ISO
#
# Usage:
#   make all     - Build kernel + ISO
#   make run     - Build + run in QEMU (BIOS)
#   make run-uefi - Build + run in QEMU (UEFI)
#   make clean   - Remove build artifacts
#   make test    - Run unit tests

KERNEL := target/x86_64-unknown-none/release/arcos_microkernel
ISO := arcos.iso
LIMINE_DIR := /tmp/limine

# User-space ELF binaries
USER_ELF := user/hello.elf
USER_SRC := user/hello.S
USER_LD  := user/user.ld
FS_SERVICE_DIR := user/fs-service
FS_SERVICE_ELF := $(FS_SERVICE_DIR)/target/x86_64-unknown-none/release/arcos-fs-service

.PHONY: all kernel iso run run-uefi test clean kernel-aarch64 img-aarch64 run-aarch64 user-elf fs-service

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

iso: kernel user-elf fs-service
	@echo "=== Building ISO ==="
	rm -rf iso_root
	mkdir -p iso_root/boot
	mkdir -p iso_root/boot/limine
	mkdir -p iso_root/EFI/BOOT
	# Copy kernel binary
	cp $(KERNEL) iso_root/boot/arcos_microkernel
	# Copy user-space ELF modules
	cp $(USER_ELF) iso_root/boot/hello.elf
	cp $(FS_SERVICE_ELF) iso_root/boot/fs-service.elf
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
		-no-reboot

run-uefi: iso
	qemu-system-x86_64 \
		-cdrom $(ISO) \
		-serial mon:stdio \
		-m 128M \
		-no-reboot \
		-bios /opt/homebrew/share/qemu/edk2-x86_64-code.fd

test:
	RUST_MIN_STACK=8388608 cargo test --lib --target x86_64-apple-darwin

# AArch64 targets
KERNEL_AARCH64 := target/aarch64-unknown-none/release/arcos_microkernel
IMG_AARCH64 := arcos-aarch64.img
EFI_FW_AARCH64 := /opt/homebrew/share/qemu/edk2-aarch64-code.fd

kernel-aarch64:
	cargo build --target aarch64-unknown-none --release

img-aarch64: kernel-aarch64
	@echo "=== Building AArch64 FAT boot image ==="
	rm -f $(IMG_AARCH64)
	dd if=/dev/zero of=$(IMG_AARCH64) bs=1M count=64
	mformat -i $(IMG_AARCH64) -F ::
	mmd -i $(IMG_AARCH64) ::/EFI
	mmd -i $(IMG_AARCH64) ::/EFI/BOOT
	mmd -i $(IMG_AARCH64) ::/boot
	mmd -i $(IMG_AARCH64) ::/boot/limine
	mcopy -i $(IMG_AARCH64) $(LIMINE_DIR)/BOOTAA64.EFI ::/EFI/BOOT/BOOTAA64.EFI
	mcopy -i $(IMG_AARCH64) $(KERNEL_AARCH64) ::/boot/arcos_microkernel
	mcopy -i $(IMG_AARCH64) $(USER_ELF) ::/boot/hello.elf
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
	rm -f $(ISO) $(IMG_AARCH64)
	rm -rf iso_root
