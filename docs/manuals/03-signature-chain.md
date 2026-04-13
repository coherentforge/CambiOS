# The Signature Chain

*How CambiOS knows the code it runs is the code that was built.*

---

## The Problem

Before a single instruction of user code runs on CambiOS, the kernel must answer a question: is this binary authentic? Not "is it valid" — the ELF headers could be perfect. Not "is it safe" — the code could pass every structural check. The question is more fundamental: did the person who built this system actually produce this binary, or did something change it along the way?

This is the code authenticity problem, and most operating systems don't solve it at the kernel level. They rely on package managers, signature checks in user-space tools, or the hope that the boot media wasn't tampered with. CambiOS solves it with a chain of trust that starts in hardware and ends in the kernel's refusal to allocate memory for anything it can't verify.

## The Hardware Root

The chain begins with a YubiKey — a small hardware security module that contains an Ed25519 private key. This key was generated on the device and has never left it. The YubiKey's OpenPGP interface allows the `sign-elf` tool to ask it to sign things, but the tool never sees the private key itself. It sends data in, and a signature comes out.

The corresponding public key — 32 bytes — is extracted once:

```
./tools/sign-elf/target/release/sign-elf --export-pubkey bootstrap_pubkey.bin
```

This file, `bootstrap_pubkey.bin`, is the root of trust for the entire system. It gets compiled into the kernel binary via `include_bytes!()`. Every CambiOS kernel binary contains a copy of this public key, burned into its `.rodata` section at build time.

The private key stays on the YubiKey. The public key travels with the kernel. That asymmetry is the whole point.

## Signing a Binary

When a developer builds a user-space module — the filesystem service, the key-store, the virtio-net driver — the resulting ELF binary is unsigned. It's just code and data in a standard format. To sign it, they run:

```
./tools/sign-elf/target/release/sign-elf user/fs-service/target/.../fs-service
```

The `sign-elf` tool does three things:

**First**, it reads the entire ELF binary and computes its Blake3 hash. Blake3 is a cryptographic hash function — fast, collision-resistant, and operating in `no_std` mode inside the kernel too. The result is a 32-byte digest that uniquely identifies the binary's contents.

**Second**, it sends that 32-byte hash to the YubiKey for signing. Not the whole binary — just the hash. This is important: smart card interfaces communicate in small APDUs, and piping megabytes through a USB smart card is unreliable. By hashing first and signing the hash, the tool keeps the hardware interaction minimal and deterministic. The YubiKey performs the Ed25519 signature operation internally and returns 64 bytes: the signature.

**Third**, it appends a 72-byte trailer to the end of the ELF binary:

```
[original ELF bytes][64-byte Ed25519 signature][8-byte magic: "ARCSIG\x01\x00"]
```

The magic bytes serve as a marker — the kernel can look at the last 8 bytes of any binary and know immediately whether it has an ARCSIG trailer. The version byte (`\x01`) allows the format to evolve without ambiguity.

The signed binary is slightly larger than the original. That's it. No separate signature file. No detached metadata. The signature travels with the code.

For CI environments or development without a YubiKey, the tool supports seed-based signing: `--seed <hex>` derives a deterministic keypair from a 32-byte seed. This is less secure (the seed is a software secret, not hardware-protected) but produces an identical format. The kernel doesn't know or care how the signature was created — it only checks whether the signature matches a trusted public key.

## The Kernel's Refusal

At boot, after the kernel has initialized its heap, frame allocator, process table, IPC manager, capability manager, and bootstrap identity, the scheduler begins loading boot modules. Limine loaded these binaries into memory alongside the kernel. Now the kernel must decide: does each one get to run?

The `SignedBinaryVerifier` is constructed with the bootstrap public key — the 32 bytes compiled in from `bootstrap_pubkey.bin`. It can hold up to four trusted keys (to support key rotation), but typically has just one.

For each boot module, the verifier runs:

**Step 1: Find the trailer.** Read the last 8 bytes. If they aren't `ARCSIG\x01\x00`, stop. The binary has no signature. Return `Deny(MissingSignature)`.

**Step 2: Extract the signature.** The 64 bytes immediately before the magic are the Ed25519 signature. The everything before that — the first `len - 72` bytes — is the original ELF binary.

**Step 3: Hash the ELF.** Compute the Blake3 hash of the original bytes (everything before the trailer). This produces the same 32-byte digest that the signing tool computed. If the binary has been modified — even one byte changed — this hash will be different from the one that was signed.

**Step 4: Verify.** Check whether the signature, applied to this hash, is valid under any of the trusted public keys. Ed25519 verification is a pure mathematical operation: given a public key, a message (the hash), and a signature, it returns true or false. If the signature is all zeros (an empty/unsigned placeholder), it always fails.

If verification fails — wrong key, modified binary, corrupted trailer, no signature — the verifier returns `Deny(InvalidSignature)`. The loader propagates this as `LoaderError::Denied`. **No memory is allocated. No pages are mapped. No process is created.** The binary is simply skipped. The kernel prints a warning and moves on to the next module.

This ordering is deliberate: verification happens *before* any resource allocation. A malicious binary that fails signature verification consumes zero system resources. It doesn't get a page table. It doesn't get stack pages. It doesn't get a process ID. The kernel spends a few microseconds computing a hash and checking a signature, and then it's done.

## After the Signature: The Structural Gate

Even if a binary's signature is valid — proving it was built by someone with the signing key — the verifier doesn't stop. The `SignedBinaryVerifier` delegates to the `DefaultVerifier`, which performs structural checks on the ELF itself:

- **Entry point validation.** The binary's entry point must fall within one of its loadable segments. A binary that jumps to an address it didn't map is either corrupt or crafted to exploit the loader.

- **Kernel space rejection.** All loadable segments must be in user space — below `0x0000_8000_0000_0000` on x86_64. A binary that maps segments into kernel address space could overwrite kernel data.

- **W^X enforcement.** No memory segment is both writable and executable. This prevents the most basic form of code injection: writing shellcode to a buffer and jumping to it.

- **Overlap detection.** Loadable segments must not overlap in virtual address space. Overlapping segments create confused-deputy vulnerabilities where permissions on one segment inadvertently apply to another.

- **Memory limits.** The total memory footprint must not exceed 256 MB. This prevents denial-of-service through resource exhaustion.

A signed binary with a kernel-space segment is still rejected. A signed binary with W+X pages is still rejected. The signature proves authenticity, but the structural checks prove safety. Both must pass.

## The Trust Chain, End to End

```
YubiKey hardware
   contains Ed25519 private key (never extracted)
        |
        | sign-elf tool sends Blake3 hash to card
        v
   64-byte signature returned
        |
        | appended as ARCSIG trailer to ELF
        v
   signed binary on disk
        |
        | Limine loads into memory at boot
        v
   raw bytes in RAM
        |
        | kernel reads bootstrap_pubkey.bin (compiled-in)
        | SignedBinaryVerifier strips trailer, hashes ELF, verifies signature
        v
   signature valid?
        |
   yes: structural verification (entry point, W^X, kernel space, overlaps, size)
        |
   structural pass?
        |
   yes: allocate frames, create page tables, map segments, create process
   no:  LoaderError::Denied — zero resources consumed, binary never executes
```

There are no shortcuts in this chain. There is no "debug mode" that skips verification. There is no kernel flag that says "trust this binary anyway." The `load_elf_process()` function takes a `verifier: &dyn BinaryVerifier` as a required parameter, and the verify call is unconditional. The only way to load a binary without verification is to modify the kernel source code and recompile — which would change the kernel's own signature.

## What This Means

If you're running CambiOS, and the kernel booted, and a user-space service is running, you know:

1. The service binary was signed by someone who possesses the YubiKey (or knows the development seed).
2. The binary has not been modified since it was signed — not one byte.
3. The binary's code and data segments don't violate W^X, don't extend into kernel space, and don't overlap.
4. No system resources were spent on any binary that failed these checks.

The kernel didn't take the binary's word for any of this. It verified. And it verified before it invested anything in the result.

That's the signature chain: hardware root, build-time signing, boot-time verification, and a kernel that would rather run fewer processes than run one it can't trust.
