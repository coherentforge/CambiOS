# Adding a User Crate

A user crate is a separate cargo package under `user/`, outside the kernel's workspace. Several files have to agree about it before it builds, ships in an image and is allowed to start. `make check-lists` compares most of them and names the one that is missing, so the working loop is: make a change, run `make check-lists`, fix what it reports.

This walkthrough adds a service called `example`. An existing small service such as `user/udp-stack` is the template to copy from.

## 1. The crate

Create `user/example/` with:

- `Cargo.toml`. The package name is `cambios-example` (`cambios-` plus the directory name; `check-lists` enforces it). Copy the `[profile.release]` table from the template.
- `src/main.rs`, `#![no_std]` and `#![no_main]`, using the service entry point from `cambios-libsys-rt` (ADR-037, the native application framework).
- One linker script per architecture the crate builds for: `link.ld` (x86_64), `link-aarch64.ld`, `link-riscv64.ld`. Copy them from the template.
- The SPDX (Software Package Data Exchange) license header and copyright line on every new file, as CLAUDE.md § Critical Rules gives them.

A library crate (no `src/main.rs`) needs only step 3 and, if it has tests, step 6. Its dependents build it.

## 2. The build lists

In the Makefile's "Build lists" section, add `example` to one list per architecture:

- `STAGE_<arch>` if the binary ships in that architecture's boot image.
- `UNSTAGED_<arch>` if it should build there and not ship.

That is the whole build rule. `make example`, `make example-aarch64` and `make example-riscv64` now exist, and `make check-user` builds them with every other crate.

## 3. The workspace exclude list

Add `user/example` to `workspace.exclude` in the root `Cargo.toml`. Without it cargo treats the crate as a broken member of the kernel workspace.

## 4. The boot configuration

For each architecture that stages the crate, the bootloader has to load the binary as a module:

- x86_64: a `module_path: boot():/boot/example.elf` line in `limine.conf`.
- aarch64: the same line in `limine-aarch64.conf`.
- riscv64: nothing to add. The initrd is built from `STAGE_riscv64`.

## 5. The manifest

A binary that is loaded and has no entry in `manifest.toml` cannot be started: the manifest is the only spawn authority (ADR-018, the init process and boot manifest). Add a `[[service]]` entry. The header comment of `manifest.toml` describes each field; the ones every entry needs:

- `name`: the directory name.
- `syscalls`: the canonical names of exactly the system calls the service makes. The policy service enforces this set, and a call outside it is denied.
- `endpoints`: the IPC (inter-process communication) endpoints the service owns. The endpoint map at the top of the file shows which numbers are taken.
- `system`: system capabilities, if the code needs any.
- `depends_on` or `depends_on_endpoints`: hard startup dependencies only.
- `arch` and `profile` tags when the entry does not ship everywhere. `check-lists` rejects a tag it does not know, because an unknown tag silently drops the entry from every image.
- `lifetime = "on-demand"` for an application that init does not start.

`check-lists` does not yet compare the manifest's entries with the staged crates. The boot is what notices: `make run-quiet` requires the line `boot wave settled: N ready, 0 spawn-failed, 0 dep-failed`.

## 6. Host tests

If the crate has `#[test]` functions, put the testable code in a lib target (`src/lib.rs`, as `user/ping` does) and add `user/example` to `HOST_TEST_CRATES` in the Makefile. `make test-user` then runs them, and `make host-test-user-example` runs just this crate. `check-lists` fails when a crate with tests is in neither `HOST_TEST_CRATES` nor `HOST_TEST_EXEMPT`.

## 7. Check

```bash
make check-lists            # every list agrees
make check-user             # the crate builds for every architecture that lists it
make test-user              # host tests, if any
make run-quiet              # x86_64 boots to the shell with nothing failed
```

The pre-commit hook runs the lints. Two of them apply to user code without any configuration: every `unsafe { }` block needs a `// SAFETY:` comment (`check-unsafe-coverage`), and no enforcement decision may default to allow (`check-fail-open`).

## What check-lists reports at each stage

Measured by adding a scratch crate:

| State | Report |
|---|---|
| Directory with a `Cargo.toml` and `src/main.rs`, nothing else | `user/example: is a binary crate with no build rule`; `workspace.exclude: missing user/example` |
| Added to `STAGE_x86_64` | `workspace.exclude: missing user/example`; `limine.conf: module_path entries: missing example.elf` |
| Excluded from the workspace, module line added | no disagreements |
