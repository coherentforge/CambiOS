# ADR-032: Full-Disk Encryption Below the Substrate

- **Status:** Proposed
- **Date:** 2026-05-17
- **Depends on:** [ADR-004](004-cryptographic-integrity.md) (Ed25519 + the bootstrap-pubkey-baked-into-kernel pattern; volume header verification reuses it), [ADR-025](025-principal-as-aid.md) (AID as 32-byte identity; volume UUID is the bootstrap AID at format time), [ADR-031](031-unified-storage-substrate.md) (the substrate that sits above this layer; needs a forthcoming Divergence to add inline MAC to journal records)
- **Related:** [ADR-010](010-persistent-object-store-on-disk-format.md) + [ADR-029](029-posix-file-storage-model.md) (the two metadata layers above the substrate; both forward-reference this ADR for at-rest confidentiality), [ADR-000](000-zta-and-cap.md) (the zero-trust framing this slots into at the disk-layer), [ADR-026](026-identity-transcription-at-the-kernel-ring.md) (transcribe-not-interpret; the volume UUID is opaque AID bytes, never branched on)
- **Supersedes:** N/A.
- **Context:** [ADR-010](010-persistent-object-store-on-disk-format.md) and [ADR-029](029-posix-file-storage-model.md) both explicitly defer encryption-at-rest as "out of scope" / "higher-layer concern," with their § "What is not in scope" lines forward-referencing this ADR. The implicit reasoning across both was that at-rest threats are physical-possession threats; if someone has the disk they've bypassed OS access control anyway, so higher-layer tools (FDE) address it. This ADR is that higher layer — a transparent block-device decorator that encrypts every block before it hits the underlying storage, decrypts every block on read, and keeps the substrate ([ADR-031](031-unified-storage-substrate.md)) and both metadata layers oblivious to its existence.

## Problem

CambiOS brands itself "Security First" with hardware-rooted (YubiKey) cryptographic identity. The Dell 3630 v1 hardware target is a portable workstation that fits in a backpack. **A device with plaintext on disk and a strong-identity-but-no-FDE story has the wrong shape for the brand and the threat model.** Three specific gaps motivate this ADR:

### 1. Physical possession threat is structurally outside OS access control

The kernel's identity gate ([ADR-026](026-identity-transcription-at-the-kernel-ring.md)), capability machinery ([ADR-000](000-zta-and-cap.md)), and ACL checks ([ADR-029](029-posix-file-storage-model.md) § Decision 3) all run *inside* a booted, trusted CambiOS. An attacker with offline disk access bypasses every one of them. The only mitigation at that layer is cryptographic — encrypt the bytes such that "having the disk" isn't enough; the attacker also needs the unwrap credential.

### 2. Hardware root of trust already exists; the runtime path is the gap

The bootstrap pubkey is YubiKey-derived and baked into the kernel binary ([ADR-004](004-cryptographic-integrity.md) Phase 1B). Signed-ELF verification works. What does *not* exist yet is the **runtime YubiKey path in `user/key-store-service/`** — it currently runs in degraded mode (no runtime PIV channel) per [STATUS.md](../../STATUS.md). FDE forces that gap to be closed: an FDE-with-YubiKey-primary unlock cannot work until key-store-service can talk to the YubiKey at runtime. The forcing function is structural, not optional.

### 3. Block-device-level encryption is the right architectural layer

Per-file or per-Principal encryption breaks content-addressed deduplication (same plaintext → different ciphertext under different keys → no dedup; the hash-as-identity property degrades). Convergent encryption (key = hash(plaintext)) preserves dedup but weakens against known-plaintext attacks. Whole-disk encryption at the substrate boundary preserves dedup (both metadata layers see plaintext, share the same bytes-on-disk) and matches industry FDE practice (dm-crypt, FileVault, BitLocker).

## Decision

A transparent block-device decorator that encrypts the entire substrate-managed volume.

### 1. `EncryptedBlockDevice<B: BlockDevice>` wraps the underlying device

```
STORAGE (substrate per ADR-031)
   uses BlockDevice trait
       provided by EncryptedBlockDevice<VirtioBlkDevice>
           wraps VirtioBlkDevice (or other concrete BlockDevice)
```

`EncryptedBlockDevice<B>` implements the `BlockDevice` trait. Reads decrypt; writes encrypt. The substrate and both metadata layers (ADR-010, ADR-029) see plaintext block reads and write plaintext blocks — they have no awareness that ciphertext is what hits the disk. No metadata-layer code changes because of FDE; the boundary is at the substrate's `device` field, not above it.

The XTS-AES-256 transform is length-preserving: a 4 KiB plaintext block encrypts to exactly 4 KiB of ciphertext. LBA addressing, alignment, and the substrate's bitmap math are unchanged. The `tweak` argument to XTS is the LBA — standard FDE practice; ensures the same plaintext block encrypts to different ciphertext at different LBAs.

### 2. Cipher: XTS-AES-256, uniform, v1

One cipher, one mode, one key schedule to reason about. No runtime cipher selection at v1. Dell 3630 has AES-NI; QEMU x86_64 has AES support; aarch64 v8.2+ targets we support have ARMv8 Crypto Extensions; RISC-V boards without Zk* extensions get software-AES (slower but uniform).

The volume header carries `cipher_id: u32` for future additivity — Adiantum or post-quantum block ciphers land as `cipher_id = 0x02` / `0x03` / etc. without changing any v1 byte layout. The cipher-selection-at-format-time path is **not** built in v1; one transform is one verification target.

### 3. Volume UUID = bootstrap AID at format time

The volume header carries a `volume_uuid: [u8; 32]` field set at format time to the bootstrap Principal's AID (the 32-byte YubiKey-derived public key per ADR-025). Stable forever; recovery operations do not change it.

Properties:

- **Cryptographic anchor.** The volume header is signed by the bootstrap private key (via YubiKey at format time). A reader verifies the signature against `volume_uuid` interpreted as a pubkey. A header-swap attack (replace the header with one signed by a different YubiKey) is detected by the AID-vs-signature-pubkey mismatch.
- **Cross-machine portability.** Move the disk to another machine — the AID stays the same; the disk identifies the original device. The new machine reads the disk only if it has a YubiKey that unwraps a slot.
- **Identity-model coherence.** The volume UUID, `did:key`-encoded ([identity.md](../identity.md) Phase 4), becomes the device's stable cryptographic name (`did:key:z6Mk...`). Aligns with YubiKey-as-root-of-trust.
- **Rotation-stable.** If the YubiKey is replaced (loss/recovery), the volume UUID stays as the *original* AID. The wrapped master key gets re-wrapped under the new YubiKey at credential-rotation time; the new YubiKey's pubkey becomes the *signing key* for the header but is *not* the volume UUID. A future reader sees: "this volume's UUID is AID X; this volume was last signed by AID Y; AID Y is the current credential holder, AID X is the format-time identity that names this volume."

### 4. Volume header

Lives at fixed LBAs on the underlying device — **before** the substrate's region map. The substrate's `posix_inode_region_lba` / `cambio_slot_region_lba` / `data_region_lba` all sit above the FDE header range.

**Primary header at LBA 0** (the substrate's global superblock moves to LBA after the FDE header). **Secondary header at fixed offset from end of volume** — provides recovery against single-sector corruption in the header LBA range. Reader prefers primary; falls back to secondary on read failure or signature failure. Header writes are atomic-update: write secondary first, `fsync`, write primary, `fsync` — so a torn write during header update (credential rotation, slot add/remove) leaves the secondary intact and the primary recoverable.

Header byte layout (v1 target; ~16 KiB total to leave room for slot table growth):

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 8 | `magic` | `"ARCVOL01"` — format-family tag with version. |
| 8 | 4 | `header_length` | u32 LE. Total header byte length. Allows future versions to grow without breaking v1 readers' bounds checks. |
| 12 | 4 | `cipher_id` | u32 LE. `0x01 = AES-256-XTS`. Other values reserved for future cipher additions. |
| 16 | 32 | `volume_uuid` | Bootstrap AID at format time. |
| 48 | 4 | `format_generation` | u32 LE. Bumped on every successful mount + every credential rotation. |
| 52 | 4 | `kdf_id` | u32 LE. `0x01 = Argon2id` (for recovery slots; YubiKey slots have their own unwrap path with no KDF). |
| 56 | 32 | `kdf_params` | KDF-specific parameter blob. For Argon2id: time (u32), memory KiB (u32), parallelism (u32), salt (16 bytes), reserved (4 bytes). |
| 88 | 4 | `slot_count` | u32 LE. Active slots in the table, ≤ `MAX_SLOTS = 16` (SCAFFOLDING). |
| 92 | 4 | `master_rotation_progress` | u32 LE. Reserved for future master-key rotation (full re-encrypt) checkpoint; `0` = no rotation in progress. v1 does not implement; field reserved for additive landing. |
| 96 | 4 | `reserved_flags` | u32 LE. Zero in v1. |
| 100 | 12 | *reserved* | Zero-filled. |
| 112 | `slot_count * 256` | `slot_table` | Each slot: 256 bytes fixed (see § Slot table below). |
| ... | varies | *reserved* | Zero-filled. Future format extensions land here. |
| `header_length - 64` | 64 | `signature` | Ed25519 signature by the bootstrap private key over `[0..header_length-64]`. Verified at mount against `volume_uuid` interpreted as a pubkey — and against the in-kernel bootstrap pubkey (must match each other and the signature). |

**Slot table** (256 bytes per slot, fixed-size for bounded iteration):

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 1 | `slot_type` | `0x00 = empty`, `0x01 = YubiKey (PIV)`, `0x02 = Argon2id-passphrase`. Other values reserved. |
| 1 | 1 | `slot_class` | `0x00 = live (normal unlock)`, `0x01 = recovery (single-use, triggers re-key on use)`. |
| 2 | 2 | `wrapped_key_len` | u16 LE. Length of wrapped master key in this slot. |
| 4 | 32 | `slot_principal` | Optional: the AID of the YubiKey owning this slot (for YubiKey slots). Zero for Argon2id recovery slots. |
| 36 | 220 | `wrapped_key` | Wrapped master key bytes. Variable up to 220 bytes (covers PIV-wrapped AES-256 keys + envelope; Argon2id wraps are smaller and the trailing bytes are zero-filled). |

The wrapped key for slot type 0x01 is a PIV-decrypt envelope holding the AES-256 master key. The wrapped key for slot type 0x02 is the AES-256 master key encrypted under an Argon2id-derived key (using the KDF parameters from the header).

#### YubiKey slot (0x01) envelope byte layout

The slot-0x01 `wrapped_key` field carries an 80-byte envelope:

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 32 | `ephemeral_pk` | The formatter's ephemeral X25519 public key. |
| 32 | 48 | `ciphertext` | `ChaCha20-Poly1305(symmetric_key, [0u8; 12], aad=empty, plaintext=master_key)` — 32 bytes of ciphertext followed by a 16-byte Poly1305 tag. |

`symmetric_key` is derived from the X25519 ECDH shared secret:

```
shared_secret  = ECDH(formatter_ephemeral_sk, slot_9d_pk)        // 32 bytes
symmetric_key  = blake3::derive_key(
                     "cambios.org 2026-05-18 fde-master-key-wrap v1",
                     shared_secret)                              // 32 bytes
```

The nonce is fixed at twelve zero bytes — justified because the symmetric key is unique per envelope (a fresh formatter ephemeral keypair per format operation drives a fresh ECDH output drives a fresh `symmetric_key`). The AAD is empty in v1; binding the envelope to the slot's `slot_principal` field via AAD is a forward-additive change (new `cipher_id` discriminator), reserved for a future Divergence if the threat model warrants.

The unwrap procedure (`fde-mount` boot module, stream A A-v.a):

1. Read `ephemeral_pk = wrapped_key[..32]`.
2. Call `piv_decrypt(slot=KeyManagement, ephemeral_pk)` → 32-byte `shared_secret` (the kernel-side ECDH performed by `SwPivBackend` or `CcidPivBackend` against the slot-9D X25519 private key).
3. `symmetric_key = blake3::derive_key("cambios.org 2026-05-18 fde-master-key-wrap v1", &shared_secret)`.
4. `master_key = ChaCha20-Poly1305-decrypt(symmetric_key, [0u8; 12], aad=empty, &wrapped_key[32..80])`.

ChaCha20-Poly1305 (vs AES-256-GCM) is chosen for the wrap step specifically to avoid forcing AES code into userspace — `fde-mount` runs in ring 3 and only the kernel (XTS path at A-v.c) needs AES code. Pure-software ChaCha20-Poly1305 via the audited RustCrypto `chacha20poly1305` crate is well within `fde-mount`'s budget; the kernel's eventual AES path is unaffected.

#### Argon2id slot (0x02) envelope byte layout

Reserved for the recovery-slot Divergence that lands when recovery enrollment ships (see § Open Questions). The v1 sketch: 48-byte ChaCha20-Poly1305 ciphertext over the same master key, keyed under the Argon2id-derived bytes from the header's KDF params — no ephemeral pubkey field (the KDF input *is* the passphrase). Locked when the recovery boot path (a future stream A substage or a separate recovery-design ADR) is ratified.

`MAX_SLOTS = 16` is SCAFFOLDING per Convention 8. Rationale: a v1 device hosts 1-3 YubiKey live slots (primary + backup) plus 1-2 recovery slots, with headroom for future N-of-1 unlock with multiple authorized YubiKeys. Memory cost: 256 bytes × 16 = 4 KiB inline in the header. Replace when a deployment surfaces > 4 active live slots in practice.

### 5. Slot policy: YubiKey-primary live, Argon2id-recovery, signed mutations

Two unlock postures, not symmetric alternatives:

- **Live slots** (`slot_class = 0x00`, `slot_type = 0x01 YubiKey`): the slots used in normal boot. N-of-1 unlock — any one of the live YubiKey slots can unwrap the master key. Multiple YubiKeys (primary, hardware backup, second admin's key) occupy multiple live slots.
- **Recovery slots** (`slot_class = 0x01`, `slot_type = 0x02 Argon2id-passphrase`): single-use. The passphrase is long, written down, stored offline (in a safe). Use of a recovery slot:
  1. Unlocks the volume normally for the current boot.
  2. Logs an audit event ([ADR-007](007-capability-revocation-and-telemetry.md) audit ring) noting the recovery-slot use, the AID it triggered for, and the timestamp.
  3. Forces a credential rotation on the next successful YubiKey unlock: the master key is unwrapped via the YubiKey, re-wrapped under a fresh Argon2id-derived key with a fresh salt, and the old recovery slot is overwritten. The recovery passphrase that was used is no longer valid; the user must enroll a new one (different long phrase, different physical safe location).

**Forced-disclosure property.** If the user is compelled to reveal a recovery passphrase, the act of using it triggers rotation. There's still a window where the disclosed credential works (one boot), but it's not an ongoing capability — the attacker doesn't get persistent access. This is a meaningful sovereignty-oriented property; explicit in the threat model below.

**Slot mutations require bootstrap-key authority.** Adding, removing, or modifying any slot is a kernel operation that requires a fresh signature by the bootstrap private key (via the live YubiKey). The kernel rejects header writes whose signature does not verify against the in-kernel bootstrap pubkey *and* against the new header's `volume_uuid`. An offline attacker with disk access cannot add a slot (no YubiKey, no signature) and cannot modify the slot table (would invalidate the signature). This closes a class of attack: "swap the disk into your own machine, add your own YubiKey-wrapped slot, swap the disk back into the victim's machine, attacker now has a permanent backdoor." Without bootstrap-key authority on slot mutations, this attack works against vanilla FDE.

### 6. Integrity at rest — what is and isn't covered

This ADR provides **confidentiality at rest** via XTS-AES-256. It does **not** provide block-level adversarial integrity. The integrity story across the storage stack:

- **CambiObjects** (ADR-010): per-object Blake3 integrity check on every read. An attacker who flips bits in a CambiObject's ciphertext breaks the Blake3 hash — detected on read. **Adversarial-integrity protected.**
- **Substrate journal records** (ADR-031): journal records will carry inline MAC under a key derived from the volume master key. Journal records are atomic-or-discarded; the MAC field is added to the record format as a forthcoming ADR-031 Divergence. **Adversarial-integrity protected for substrate-metadata mutations.**
- **POSIX inode headers** (ADR-029): 8-byte Blake3-prefix checksum, accidental-corruption catcher. An attacker who knows the layout can recompute it. **Not adversarial-strength.**
- **POSIX file content blocks**: no integrity at the block layer. An attacker with offline write access can flip bits in the XTS ciphertext and the OS cannot detect the modification on read. **Documented gap.**

This is the same gap standard FDE (dm-crypt, FileVault, BitLocker-without-XTS-with-diffuser) has accepted for a decade. The alternatives:

- **AEAD with auth tag per block** breaks length-preservation: every 4 KiB logical block becomes a 4112-byte (or similar) physical block. Misaligned device I/O, RMW on every partial-block write, substrate bitmap math gets a maintenance hazard. **Rejected.**
- **Per-block MAC in a sidecar region** (dm-integrity style) costs ~6% capacity plus a MAC journal plus an atomicity story for the data-write/MAC-write pair plus a recovery model when MAC verification fails. Real format work. **Deferred.** **Revisit when:** a v1 deployment surfaces a threat model where physical-tamper-without-detection is unacceptable.

The honest framing the ADR commits to:

> At-rest confidentiality is provided by XTS-AES-256 below the substrate. At-rest integrity is provided per-object (Blake3) for CambiObjects and per-record (inline MAC) for substrate journal records. Block-level integrity is **not** provided for POSIX-namespace content. An attacker with offline write access to the disk can perform undetected ciphertext modifications to POSIX file content. Detection of such modifications, when required, is the responsibility of the consumer (per-file MAC at libposix, application-level integrity, or substrate-level dm-integrity-style sidecar in a future ADR).

### 7. Rotation operations

Three distinct operations with different cost profiles and threat-model implications:

**Credential rotation** (v1, cheap, single header write):
Change what unlocks slot N. Unwrap the master key via the *old* credential for slot N, re-wrap under the *new* credential, write the updated header (secondary first, primary second). Master key untouched. Data untouched. This is the normal "I'm rotating my passphrase" / "I'm enrolling a new YubiKey" / "I'm retiring an old YubiKey from a live slot" operation.

**Compromise-recovery rotation** (v1, automatic, single header write):
Triggered automatically on next successful YubiKey unlock after a recovery slot has been used. Mechanics: unwrap master via YubiKey, re-wrap a fresh Argon2id-derived key from a fresh salt, overwrite the recovery slot, write the updated header. The user is prompted to enroll a new recovery passphrase before the next reboot.

**Master key rotation** (full re-encrypt of every block; not v1):
Required when the master key itself is suspected compromised (e.g., a kernel memory dump leaked it). Re-encrypt every data block on disk under a new master key. Days of I/O on a large volume; must be resumable across reboot (progress in `master_rotation_progress` header field). Standard dm-crypt has `cryptsetup reencrypt` for this shape; real format work. The header reserves the checkpoint field so the operation lands as additive, not a format break. **Revisit when:** the master key is suspected compromised in a real deployment, or proactively before v1 ships if a stress-test surfaces a leak path.

## Architecture

`src/fs/crypto/` module. Owns:

- `EncryptedBlockDevice<B: BlockDevice>` — the wrapper type. Implements `BlockDevice`. Holds the master AES-256 key plus a reference to the underlying device. `read_block(lba, buf)` decrypts the block at `lba`; `write_block(lba, buf)` encrypts. The LBA is the XTS tweak.
- `VolumeHeader` — the parsed header struct. Pure-codec encode/decode + signature verify (against the in-kernel bootstrap pubkey).
- `SlotTable` — the slot table parser and policy enforcer. Bounded iteration over `MAX_SLOTS`. Per-slot unwrap helpers (PIV decrypt path for YubiKey slots, Argon2id-derive-and-decrypt for recovery slots).
- `format_volume(device, bootstrap_aid, initial_slot) -> Result<VolumeHeader>` — host-side tool wrapper. Writes a fresh header (primary + secondary) signed by the bootstrap key.
- `mount_volume(device, slot_unwrap_fn) -> Result<EncryptedBlockDevice<B>>` — runtime: read header (primary, fallback to secondary), verify signature, call `slot_unwrap_fn` (which talks to key-store-service for live YubiKey unwrap or prompts for recovery passphrase), construct the EncryptedBlockDevice with the unwrapped master key.

Kernel-runtime singleton: `EncryptedBlockDevice` is held by the substrate's STORAGE singleton; not a separate global lock. The boot path looks like:

```
kernel main ()
   -> bootstrap_pubkey baked-in (existing)
   -> start key-store-service (existing)
   -> key-store-service.is_yubikey_live (new gate; was always degraded before)
   -> read volume header from raw VirtioBlkDevice
   -> verify header signature against bootstrap_pubkey (and volume_uuid)
   -> ask key-store-service to unwrap a live slot via the YubiKey
   -> construct EncryptedBlockDevice<VirtioBlkDevice> with the master key
   -> hand the EncryptedBlockDevice to STORAGE
   -> STORAGE.mount(encrypted_device) — substrate sees plaintext throughout
```

If the YubiKey is not present or no live slot unwraps, the boot path prompts for a recovery passphrase. If neither works, the volume does not mount; the system boots into a recovery shell that can read CambiObjects but not anything stored under the substrate.

**No new locks.** `EncryptedBlockDevice` is held by STORAGE; the existing `BLOCK_BITMAP_LOCK(12)` and `JOURNAL_LOCK(13)` cover all substrate-mediated access. Crypto operations (per-block XTS) are CPU-bound and stateless; no concurrency concern.

## Threat Model

### What this ADR protects against

| Threat | Mitigation |
|---|---|
| Physical disk theft → attacker reads file contents | XTS-AES-256 below the substrate. Without a slot unwrap (YubiKey or recovery passphrase), the disk is ciphertext. |
| Header-swap attack (replace volume header with one signed by attacker's YubiKey) | Header signature verifies against `volume_uuid` AND the in-kernel bootstrap pubkey. Attacker's header would have a different `volume_uuid`; the in-kernel bootstrap pubkey verification catches the mismatch. |
| Slot-injection (attacker with offline disk access adds their own slot) | Slot mutations require bootstrap-key authority. Offline attacker has no YubiKey, cannot produce a valid header signature, cannot add a slot. |
| Recovery-credential persistence (attacker compels disclosure of recovery passphrase, hopes for ongoing access) | Recovery-slot use triggers automatic credential rotation on next YubiKey unlock. The disclosed passphrase is invalidated; one-shot use only. |
| Header corruption (single-sector failure) | Primary + secondary header at fixed offsets, atomic-update write order, reader fallback. |
| Cross-machine disk theft (attacker moves disk to their hardware to attack) | Cipher key is wrapped by YubiKey-derived secret. Without the YubiKey, the attacker's machine cannot unwrap. The bootstrap pubkey baked into the attacker's kernel won't match `volume_uuid`. |
| Journal-replay (attacker rolls back the substrate journal to undo a metadata mutation) | Substrate journal records carry inline MAC under a key derived from the master key (forthcoming ADR-031 Divergence). Replaying an old record without re-MAC fails verification. |

### What this ADR does NOT protect against

| Risk | Mitigation |
|---|---|
| POSIX file content adversarial-integrity tampering | Documented gap. Detection is consumer's responsibility (per-file MAC at libposix, app-level integrity, future per-block MAC sidecar ADR). |
| Cold-boot attack against the running kernel's master key in RAM | Out of scope. Standard FDE vulnerability. Mitigations are higher-layer (memory encryption, fast-suspend-with-key-zeroize) and not addressed here. |
| Compromised live YubiKey | If the live YubiKey is physically compromised (theft + extraction or coercion), the attacker has live unlock authority. Mitigation: revoke the slot for that YubiKey via credential rotation by another live YubiKey, or use a recovery slot to trigger rotation. |
| Compromised kernel binary (malicious kernel with attacker's bootstrap pubkey baked in) | Out of scope at this layer. Secure boot ([ADR-021](021-typed-boot-error-propagation.md) and beyond, plus Dell-3630-specific UEFI/SB story per project memory) is the mitigation path. FDE does not protect against a malicious kernel that the user voluntarily boots. |
| Per-Principal isolation at the FDE layer | Not provided. FDE is device-level confidentiality (the disk vs the world). Per-Principal isolation is the OS access control layer's job (ACL on POSIX inodes per ADR-029, capability checks on CambiObjects per ADR-003). One booted user can read another user's files at the FDE layer; only the OS layer above prevents it. |
| Side-channel attack against AES (cache-timing, power analysis) | Out of scope. AES-NI hardware is constant-time on Intel; software AES has timing exposure but the threat model accepts it for v1. Worth re-examining when adversarial environments enter scope. |

## Verification Stance

One cipher, one mode, one key schedule — small Kani-amenable verification surface. Four claims to prove:

1. **`EncryptedBlockDevice` round-trip correctness.** `write_block(lba, plaintext); read_block(lba, &mut buf); assert!(buf == plaintext)` for every `lba` and every `plaintext`. The XTS transform is the verifier's target; the surrounding `BlockDevice` plumbing is uniform.
2. **Header signature gate.** A mounted volume's header signature verifies against both the in-kernel bootstrap pubkey AND the header's `volume_uuid` (which the bootstrap pubkey IS — `volume_uuid == bootstrap_aid` at format-time, and the bootstrap pubkey IS that AID). Any header that fails this gate refuses to mount.
3. **Slot policy correctness.** A slot mutation request that lacks a valid bootstrap signature is rejected. A recovery-slot unlock triggers the rotation flow on next YubiKey unlock. Live-slot unlock does not trigger rotation.
4. **Key custody invariant.** The master AES-256 key exists only in:
   - The YubiKey's PIV chip (in wrapped form, never extracted).
   - Argon2id-wrapped form in the volume header (recovery slots).
   - The running kernel's RAM (after unwrap, while the volume is mounted).
   No other site holds the master key. No kernel-readable disk location stores it unwrapped.

Substrate-side claims (journal-record inline MAC verification) become a [ADR-031](031-unified-storage-substrate.md) verification target when the Divergence lands.

## Why Not Other Options

### Option A: No FDE in v1, document and defer

Continue with plaintext at rest. Confidentiality is "higher-layer concern."

**Why considered.** Smaller v1 scope. Pushes the YubiKey runtime work to post-v1.

**Why rejected.** The pre-user-period rule (CLAUDE.md § "Build with the End in Mind") explicitly says: post-user encryption retrofits cost migration tools, version skew, backwards-compat shims. Pre-user is the cheapest time to honor a v1-shape decision; "Security First" without FDE is a v1-shape contradiction.

### Option B: AEAD per block (AES-GCM, ChaCha20-Poly1305)

Every encrypted block carries an auth tag (16 bytes); each 4 KiB logical block becomes a 4112-byte physical block (or 16 bytes of tag stored elsewhere).

**Why considered.** Adversarial integrity at the block layer, for free with the encryption operation.

**Why rejected.** Breaks length-preservation. Misaligned device I/O kills SSD throughput, every partial-block write becomes a read-modify-write on the trailing block, substrate's LBA-and-bitmap math gets a maintenance hazard forever. Worse trade than the documented integrity gap.

### Option C: Per-block MAC sidecar (dm-integrity style)

Substrate stores a MAC table in a dedicated region; each data-region block has a corresponding MAC slot at a known offset. MAC verified on read; mismatch fails the read or routes to a recovery path.

**Why considered.** Closes the POSIX content adversarial-integrity gap without breaking length-preservation.

**Why rejected for v1.** Costs ~6% capacity + a MAC journal (atomicity between data write and MAC update) + a recovery story (what does the OS do when MAC verification fails — fail the read? Fall back to plaintext? Each answer has consequences). Real format work; substantial verification surface. Becomes a future ADR. **Revisit when:** a v1 deployment surfaces a threat model where physical-tamper-without-detection is unacceptable.

### Option D: Per-Principal encryption (each Principal's content under their key)

Master key per Principal; content encrypted under the owning Principal's key.

**Why considered.** Cryptographic per-Principal isolation at the disk layer.

**Why rejected.** Breaks content-addressed dedup (same plaintext under different keys → different ciphertext → no dedup). Breaks CambiObject ACL-shared-read (an object shared to multiple Principals can't be encrypted under just the author's key). Convergent encryption resolves dedup at the cost of known-plaintext-attack weakness. The trade-offs aren't worth the per-Principal-at-FDE-layer property when OS access control + FDE-as-device-level already covers the threat model adequately.

### Option E: TPM-rooted keys

Use a TPM (or fTPM, or Intel ME equivalent) to wrap the master key; YubiKey is the second factor.

**Why considered.** TPM is widely available on commodity hardware.

**Why rejected.** YubiKey is the project's chosen hardware root of trust (per project memory + ADR-004 + bootstrap_pubkey.bin pattern). TPM introduces a second cryptographic vendor surface, a TPM-attestation story we don't have, and conflicts with the "no telemetry, no phone-home" stance ([CambiOS.md](../CambiOS.md) project vision — TPMs vary in remote-attestation behavior). Single hardware root of trust = YubiKey.

## Migration Path

1. **This ADR lands as Proposed.** Citations from ADR-010 + ADR-029 "encryption at rest" forward-reference lines resolve.
2. **YubiKey runtime path completes in `user/key-store-service/`.** PC/SC stack in userspace, YubiKey driver, key-store-service holds a live PIV channel. STATUS.md flips from "degraded mode" to "live YubiKey integration." **Implementation prerequisite for everything after this point.**
3. **[ADR-031](031-unified-storage-substrate.md) Divergence: inline MAC in journal records.** Substrate journal record format gains a MAC field, keyed under a substrate-master-key derived from the FDE master key. Closes the journal-replay attack named in this ADR's threat model.
4. **`src/fs/crypto/` module lands.** `EncryptedBlockDevice<B>`, `VolumeHeader` parser, `SlotTable` parser. No I/O integration yet.
5. **Host-side `format_volume` tool.** Mirrors the existing `tools/sign-elf/` pattern. Writes a fresh signed header with one YubiKey slot + one Argon2id recovery slot. Runs against a raw disk image; user passes YubiKey for slot 0 signature.
6. **Kernel mount path integration.** Kernel boot reads the volume header before the substrate's superblock; invokes key-store-service for slot unwrap; constructs `EncryptedBlockDevice<VirtioBlkDevice>`; substrate mounts on top of the encrypted device.
7. **Credential rotation + compromise-recovery rotation operations.** Two kernel operations (credential rotation, compromise-recovery rotation). Both involve header rewrites — secondary first, primary second.
8. **Recovery shell** (when no slot unwraps). Boot into a minimal shell that can read CambiObjects (which are content-addressed and don't require volume decrypt for their own integrity check) but cannot read the substrate. User can re-enroll a recovery slot from this shell if they hold the bootstrap YubiKey.

Each step independently bisectable. Step 2 (YubiKey runtime) is its own multi-session sub-project; everything after step 2 sequences off it.

## Cross-References

- **[ADR-004](004-cryptographic-integrity.md)** — Ed25519 + the bootstrap-pubkey-baked-into-kernel pattern; header signature verification reuses it.
- **[ADR-025](025-principal-as-aid.md)** — AID as 32-byte identity; the bootstrap AID becomes the volume UUID.
- **[ADR-026](026-identity-transcription-at-the-kernel-ring.md)** — Transcribe-not-interpret; the `volume_uuid` is treated as opaque AID bytes by the kernel.
- **[ADR-031](031-unified-storage-substrate.md)** — The substrate this ADR sits beneath. Substrate journal records gain inline MAC per a forthcoming Divergence.
- **[ADR-010](010-persistent-object-store-on-disk-format.md)** + **[ADR-029](029-posix-file-storage-model.md)** — Metadata layers; both forward-reference this ADR for at-rest confidentiality.
- **[ADR-007](007-capability-revocation-and-telemetry.md)** — Audit ring; recovery-slot use is logged here.
- **[ADR-023](023-audit-consumer-capability.md)** — Audit consumer cap; `audit-tail` will surface recovery-slot-use events to a watching admin.

## See Also in CLAUDE.md

When this ADR's implementation lands:

- **§ "Required Reading by Subsystem"** — add a row for "Volume encryption / FDE / boot-time unlock" pointing at this ADR.
- **§ "Lock Ordering"** — no change. `EncryptedBlockDevice` is held by STORAGE; no new top-level lock.
- **§ "Design Documents"** — no new entry; this ADR is the design doc.
- **§ "Quick Reference"** — add the `format_volume` host-side tool invocation pattern alongside the existing `sign-elf` examples.
- **§ "Critical Rules"** — no change. Boot ordering is updated implicitly via STATUS.md when the YubiKey runtime work completes.

## Open Questions / Deferred

> **Deferred decision.** Master key rotation (full re-encrypt of every block). v1 reserves the `master_rotation_progress` header field; the rotation tool itself is post-v1. **Revisit when:** the master key is suspected compromised in a real deployment, or proactively before v1 ships if a stress-test surfaces a leak path.

> **Deferred decision.** Per-block MAC sidecar for POSIX content adversarial integrity. Not v1; documented gap. **Revisit when:** a v1 deployment surfaces a threat model where physical-tamper-without-detection is unacceptable.

> **Deferred decision.** Cipher additions beyond AES-256-XTS. Header carries `cipher_id` for future additivity. **Revisit when:** a deployment surfaces a hardware target where AES-NI is unavailable AND software-AES throughput is unacceptable (Adiantum or similar lands at that point as `cipher_id = 0x02`).

> **Deferred decision.** TPM-based slot type. Not v1; YubiKey-only. **Revisit when:** a deployment target lacks a YubiKey path but has a TPM and a workable attestation story.

> **Deferred decision.** Multi-YubiKey enrollment UX. v1 spec supports N-of-1 unlock with multiple live YubiKey slots; the *operational tooling* for enrolling additional keys (interactive prompts, key-presence verification, slot accounting) lands when the first multi-YubiKey workflow appears. **Revisit when:** a user (Jason) wants to enroll a backup YubiKey alongside the primary.

> **Deferred decision.** YubiKey-rotation operational protocol. When the bootstrap YubiKey is replaced, the kernel binary needs to be rebuilt with the new pubkey baked in (Phase 1B per ADR-004). The transition (boot once with old kernel + old header signature → re-sign header with new YubiKey → rebuild kernel with new pubkey → reboot with new kernel + new header signature) needs an explicit operational sequence. **Revisit when:** the first bootstrap YubiKey rotation is needed in real life.
