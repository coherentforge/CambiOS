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

.PHONY: all kernel iso run run-uefi test clean

all: iso

kernel:
	cargo build --target x86_64-unknown-none --release

iso: kernel
	@echo "=== Building ISO ==="
	rm -rf iso_root
	mkdir -p iso_root/boot
	mkdir -p iso_root/boot/limine
	mkdir -p iso_root/EFI/BOOT
	# Copy kernel binary
	cp $(KERNEL) iso_root/boot/arcos_microkernel
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

# AArch64 targets (scaffold — library only, no binary yet)
kernel-aarch64:
	cargo build --target aarch64-unknown-none --lib --release

clean:
	cargo clean
	rm -f $(ISO)
	rm -rf iso_root
