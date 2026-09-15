// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! CambiOS boot-manifest builder (ADR-018 migration step 2).
//!
//! Reads the endpoint-registry source artifact (`manifest.toml`, the
//! ADR-037 Phase-2 artifact — the single source the manifest is
//! generated from), derives the v1 service AIDs, assembles the default
//! grant set per entry (narrow receive on reserved endpoints, wildcard
//! send, declared System capabilities), emits the CBOSMANI blob via
//! `cambios-manifest`, and self-checks the result by parsing it back
//! through the same parser the kernel and init use (structural parse +
//! uniqueness + DAG order).
//!
//! The output is **unsigned**. ARCSIG signing stays in `tools/sign-elf`
//! (the one place with YubiKey / seed / dev-piv key access):
//!
//! ```text
//! build-manifest manifest.toml -o manifest.bin
//! sign-elf $(SIGN_FLAGS) manifest.bin        # appends the trailer
//! ```
//!
//! `make manifest` runs both.

use std::process::exit;

use cambios_manifest::{
    emit_manifest, emitted_size, system_caps, topo_order, validate_unique, CapabilityGrant,
    EntryDef, Manifest, Rights, ServiceLifetime, INIT_AID_DOMAIN_TAG, INIT_ENDPOINT,
    MAX_MANIFEST_ENTRIES, SERVICE_AID_DOMAIN_TAG,
};
use serde::Deserialize;

/// Mirror of the kernel's `MAX_ENDPOINTS` (src/ipc/mod.rs). The kernel
/// transcription path re-rejects out-of-range endpoints at boot with a
/// typed error; failing here at build time is the friendlier surface.
/// Keep in lockstep.
const KERNEL_MAX_ENDPOINTS: u32 = 64;

// ============================================================================
// Registry TOML schema
// ============================================================================

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Registry {
    #[serde(default)]
    init: InitSection,
    #[serde(default, rename = "service")]
    services: Vec<ServiceDef>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InitSection {
    #[serde(default = "default_init_endpoint")]
    endpoint: u32,
}

impl Default for InitSection {
    fn default() -> Self {
        InitSection { endpoint: INIT_ENDPOINT }
    }
}

fn default_init_endpoint() -> u32 {
    INIT_ENDPOINT
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceDef {
    name: String,
    /// Endpoints this service owns exclusively (reserved to its AID).
    #[serde(default)]
    endpoints: Vec<u32>,
    /// System capabilities by kebab-case name (see `system_cap_id`).
    #[serde(default)]
    system: Vec<String>,
    /// "persistent" (default), "one-shot", or "on-demand" (not part
    /// of init's boot wave — spawned later by a CreateProcess holder;
    /// may not declare or be named in `depends_on`).
    #[serde(default = "default_lifetime")]
    lifetime: String,
    /// Restart/backoff parameters — only meaningful for persistent.
    #[serde(default)]
    restart: RestartDef,
    #[serde(default)]
    depends_on: Vec<String>,
    /// Dependencies by *endpoint*: "whoever serves endpoint N must be
    /// ready before I spawn". Resolved to the owning entry's name after
    /// the arch/profile filters, so a role several entries can fill
    /// (the scanout driver on endpoint 27: virtio-gpu by default, the
    /// linear-framebuffer fallback under another profile) is named by
    /// the thing the dependant actually talks to. The wire manifest
    /// still carries a plain name dependency; init and the kernel are
    /// unaware of this field.
    #[serde(default)]
    depends_on_endpoints: Vec<u32>,
    /// Architectures this service ships on. Empty (default) = all
    /// arches. `--arch <name>` filters the emitted manifest to entries
    /// whose list is empty or contains the name — the ADR-018 rule
    /// that each deployment's manifest matches its reality (riscv64
    /// carries no GUI stack; a manifest that lists it would make init
    /// report phantom spawn failures every boot).
    #[serde(default)]
    arch: Vec<String>,
    /// Deployment profiles this service ships in. Empty (default) =
    /// every profile. `--profile <name>` (default `default`) keeps
    /// entries whose list is empty or contains the name — the seam for
    /// declaring a service the default images must not carry (the
    /// framebuffer-fallback scanout driver for hosts without
    /// virtio-gpu) without hiding it from the registry.
    #[serde(default)]
    profile: Vec<String>,
}

fn default_lifetime() -> String {
    "persistent".to_string()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RestartDef {
    initial_ms: u32,
    max_ms: u32,
    max_restarts: u16,
    window_ms: u32,
}

impl Default for RestartDef {
    fn default() -> Self {
        // House defaults: fast first retry, 5 s ceiling, give up after
        // 5 consecutive failures inside a minute (ADR-018 § Restart).
        RestartDef { initial_ms: 100, max_ms: 5000, max_restarts: 5, window_ms: 60_000 }
    }
}

fn system_cap_id(name: &str) -> Option<u32> {
    Some(match name {
        "create-process" => system_caps::CREATE_PROCESS,
        "create-channel" => system_caps::CREATE_CHANNEL,
        "legacy-port-io" => system_caps::LEGACY_PORT_IO,
        "map-framebuffer" => system_caps::MAP_FRAMEBUFFER,
        "large-channel" => system_caps::LARGE_CHANNEL,
        "emit-input-audit" => system_caps::EMIT_INPUT_AUDIT,
        "audit-consumer" => system_caps::AUDIT_CONSUMER,
        "set-wallclock" => system_caps::SET_WALLCLOCK,
        "create-cluster" => system_caps::CREATE_CLUSTER,
        "cluster-revoke" => system_caps::CLUSTER_REVOKE,
        "unlock-volume" => system_caps::UNLOCK_VOLUME,
        _ => return None,
    })
}

// ============================================================================
// AID derivation (v1: domain-tagged Blake3 of the module name)
// ============================================================================

fn service_aid(name: &str) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(SERVICE_AID_DOMAIN_TAG.as_bytes());
    h.update(name.as_bytes());
    *h.finalize().as_bytes()
}

fn init_aid() -> [u8; 32] {
    *blake3::hash(INIT_AID_DOMAIN_TAG.as_bytes()).as_bytes()
}

// ============================================================================
// Main
// ============================================================================

fn usage(prog: &str) -> ! {
    eprintln!(
        "Usage: {} <registry.toml> [-o <manifest.bin>] [--arch <name>] [--profile <name>]",
        prog
    );
    eprintln!();
    eprintln!("Emits an UNSIGNED CBOSMANI manifest blob. Sign it with:");
    eprintln!("  sign-elf [--seed <hex>] <manifest.bin>");
    eprintln!();
    eprintln!("--arch <name>: emit only services whose `arch` list is empty");
    eprintln!("  (all arches) or contains <name>. A kept service depending on");
    eprintln!("  a filtered-out one is an error — the emitted dependency graph");
    eprintln!("  must be closed. Omitted = no filtering (every entry emits).");
    eprintln!("--profile <name>: emit only services whose `profile` list is");
    eprintln!("  empty (every profile) or contains <name>. Same closure rule.");
    eprintln!("  Omitted = `default`, so profile-tagged entries never emit by");
    eprintln!("  accident.");
    exit(2);
}

/// Keep the services whose `tags(s)` list is empty or names `target`;
/// then require the kept set's `depends_on` graph to be closed.
fn filter_registry(
    registry: &mut Registry,
    dimension: &str,
    target: &str,
    tags: impl Fn(&ServiceDef) -> &Vec<String>,
) {
    let kept: Vec<String> = registry
        .services
        .iter()
        .filter(|s| tags(s).is_empty() || tags(s).iter().any(|t| t == target))
        .map(|s| s.name.clone())
        .collect();
    registry.services.retain(|s| kept.contains(&s.name));
    for svc in &registry.services {
        for dep in &svc.depends_on {
            if !kept.contains(dep) {
                eprintln!(
                    "service '{}' depends on '{}', which is filtered out \
                     for {} '{}' — fix the {} tags in the registry",
                    svc.name, dep, dimension, target, dimension
                );
                exit(1);
            }
        }
    }
    eprintln!("{} filter '{}': {} service(s) kept", dimension, target, registry.services.len());
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let prog = argv.first().map(String::as_str).unwrap_or("build-manifest");

    let mut input: Option<&str> = None;
    let mut output = "manifest.bin".to_string();
    let mut arch: Option<String> = None;
    let mut profile = "default".to_string();
    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "-o" | "--output" => {
                i += 1;
                match argv.get(i) {
                    Some(p) => output = p.clone(),
                    None => usage(prog),
                }
            }
            "--arch" => {
                i += 1;
                match argv.get(i) {
                    Some(a) => arch = Some(a.clone()),
                    None => usage(prog),
                }
            }
            "--profile" => {
                i += 1;
                match argv.get(i) {
                    Some(p) => profile = p.clone(),
                    None => usage(prog),
                }
            }
            "-h" | "--help" => usage(prog),
            arg if input.is_none() => input = Some(arg),
            _ => usage(prog),
        }
        i += 1;
    }
    let input = input.unwrap_or("manifest.toml");

    let toml_text = std::fs::read_to_string(input).unwrap_or_else(|e| {
        eprintln!("Failed to read '{}': {}", input, e);
        exit(1);
    });
    let mut registry: Registry = toml::from_str(&toml_text).unwrap_or_else(|e| {
        eprintln!("Failed to parse '{}': {}", input, e);
        exit(1);
    });

    // --arch / --profile filters: keep entries with an empty tag list
    // (all arches / all profiles) or one naming the target. Then
    // require the kept set's dependency graph to be closed — a kept
    // service depending on a filtered-out one means the registry's
    // tags are wrong, not that the dependency should silently vanish.
    if let Some(target) = &arch {
        filter_registry(&mut registry, "arch", target, |s| &s.arch);
    }
    filter_registry(&mut registry, "profile", &profile, |s| &s.profile);

    // Resolve endpoint dependencies against the KEPT set: exactly one
    // kept entry owns each endpoint (validate_unique enforces this on
    // the emitted blob too), so the owner's name is the dependency.
    // Owned storage: the resolved list is `depends_on` + the owners.
    let resolved_deps: Vec<Vec<String>> = registry
        .services
        .iter()
        .map(|svc| {
            let mut deps = svc.depends_on.clone();
            for &ep in &svc.depends_on_endpoints {
                if ep == registry.init.endpoint {
                    eprintln!(
                        "service '{}' depends on endpoint {}, which is init's — init is \
                         not a spawnable dependency",
                        svc.name, ep
                    );
                    exit(1);
                }
                let owners: Vec<&str> = registry
                    .services
                    .iter()
                    .filter(|o| o.endpoints.contains(&ep))
                    .map(|o| o.name.as_str())
                    .collect();
                match owners.as_slice() {
                    [owner] => {
                        if *owner == svc.name {
                            eprintln!(
                                "service '{}' depends on its own endpoint {}",
                                svc.name, ep
                            );
                            exit(1);
                        }
                        deps.push((*owner).to_string());
                    }
                    [] => {
                        eprintln!(
                            "service '{}' depends on endpoint {}, but no kept entry serves it \
                             (arch '{}', profile '{}') — tag an owner into this build",
                            svc.name,
                            ep,
                            arch.as_deref().unwrap_or("any"),
                            profile
                        );
                        exit(1);
                    }
                    many => {
                        eprintln!(
                            "service '{}' depends on endpoint {}, which {} kept entries claim \
                             ({}) — the profile tags must select exactly one",
                            svc.name,
                            ep,
                            many.len(),
                            many.join(", ")
                        );
                        exit(1);
                    }
                }
            }
            deps
        })
        .collect();

    if registry.services.len() > MAX_MANIFEST_ENTRIES {
        eprintln!(
            "{} services exceeds MAX_MANIFEST_ENTRIES = {}",
            registry.services.len(),
            MAX_MANIFEST_ENTRIES
        );
        exit(1);
    }

    // Per-service owned storage for the EntryDef borrows.
    let mut grants_store: Vec<Vec<CapabilityGrant>> = Vec::new();
    let mut deps_store: Vec<Vec<&str>> = Vec::new();

    for svc in &registry.services {
        // Default grant posture (ADR-018 § 2): narrow receive on each
        // reserved endpoint + wildcard send + declared System caps.
        let mut grants: Vec<CapabilityGrant> = Vec::new();
        for &ep in &svc.endpoints {
            if ep == 0 || ep == registry.init.endpoint {
                eprintln!(
                    "service '{}' reserves endpoint {} (0 is the REPLY_ENDPOINT \
                     sentinel; {} is init's)",
                    svc.name, ep, registry.init.endpoint
                );
                exit(1);
            }
            if ep >= KERNEL_MAX_ENDPOINTS {
                eprintln!(
                    "service '{}' reserves endpoint {} >= kernel MAX_ENDPOINTS ({})",
                    svc.name, ep, KERNEL_MAX_ENDPOINTS
                );
                exit(1);
            }
            grants.push(CapabilityGrant::Endpoint { endpoint: ep, rights: Rights::RECEIVE });
        }
        grants.push(CapabilityGrant::AllEndpoints { rights: Rights::SEND });
        for cap in &svc.system {
            match system_cap_id(cap) {
                Some(kind) => grants.push(CapabilityGrant::System { kind }),
                None => {
                    eprintln!("service '{}': unknown system capability '{}'", svc.name, cap);
                    exit(1);
                }
            }
        }
        grants_store.push(grants);
    }
    for deps in &resolved_deps {
        deps_store.push(deps.iter().map(String::as_str).collect());
    }

    // On-demand entries sit outside init's boot wave, so they can
    // neither wait on anything nor be waited on. Both directions are
    // registry errors here (init's engine re-checks the same rule).
    let on_demand: Vec<&str> = registry
        .services
        .iter()
        .filter(|s| s.lifetime == "on-demand")
        .map(|s| s.name.as_str())
        .collect();
    for (svc, deps) in registry.services.iter().zip(&resolved_deps) {
        if svc.lifetime == "on-demand" && !deps.is_empty() {
            eprintln!(
                "service '{}' is on-demand but declares dependencies — init never \
                 sequences on-demand entries, so dependencies cannot be honored",
                svc.name
            );
            exit(1);
        }
        for dep in deps {
            if on_demand.contains(&dep.as_str()) {
                eprintln!(
                    "service '{}' depends on '{}', which is on-demand — the boot \
                     wave can never satisfy that dependency",
                    svc.name, dep
                );
                exit(1);
            }
        }
    }

    let mut defs: Vec<EntryDef> = Vec::new();
    for (i, svc) in registry.services.iter().enumerate() {
        let lifetime = match svc.lifetime.as_str() {
            "one-shot" => ServiceLifetime::OneShot,
            "on-demand" => ServiceLifetime::OnDemand,
            "persistent" => ServiceLifetime::Persistent {
                initial_delay_ms: svc.restart.initial_ms,
                max_delay_ms: svc.restart.max_ms,
                max_restarts: svc.restart.max_restarts,
                failure_window_ms: svc.restart.window_ms,
            },
            other => {
                eprintln!(
                    "service '{}': lifetime must be 'persistent', 'one-shot', or \
                     'on-demand', got '{}'",
                    svc.name, other
                );
                exit(1);
            }
        };
        defs.push(EntryDef {
            module_name: &svc.name,
            principal: service_aid(&svc.name),
            reserved_endpoints: &svc.endpoints,
            grants: &grants_store[i],
            lifetime,
            depends_on: &deps_store[i],
        });
    }
    // Emit, then self-check through the same parser the kernel + init
    // use: structural parse, cross-record uniqueness, DAG order.
    let size = emitted_size(&defs).unwrap_or_else(|e| {
        eprintln!("emit sizing failed: {:?}", e);
        exit(1);
    });
    let mut blob = vec![0u8; size];
    let written = emit_manifest(init_aid(), registry.init.endpoint, &defs, &mut blob)
        .unwrap_or_else(|e| {
            eprintln!("emit failed: {:?}", e);
            exit(1);
        });
    assert_eq!(written, size);

    let parsed = Manifest::parse(&blob).unwrap_or_else(|e| {
        eprintln!("self-check parse failed (tool bug): {:?}", e);
        exit(1);
    });
    if let Err(e) = validate_unique(&parsed) {
        eprintln!("validation failed: {:?}", e);
        exit(1);
    }
    let mut order = [0u16; MAX_MANIFEST_ENTRIES];
    let n = topo_order(&parsed, &mut order).unwrap_or_else(|e| {
        eprintln!("dependency validation failed: {:?}", e);
        exit(1);
    });

    std::fs::write(&output, &blob).unwrap_or_else(|e| {
        eprintln!("Failed to write '{}': {}", output, e);
        exit(1);
    });

    println!(
        "manifest: {} entries, {} bytes -> '{}' (unsigned)",
        parsed.entry_count(),
        written,
        output
    );
    println!("  init endpoint: {}", parsed.init_endpoint());
    println!("  spawn order (on-demand entries listed last; init does not spawn them):");
    let boot_wave = order[..n].iter().filter(|&&i| {
        parsed.entry(i as usize).map(|e| !e.lifetime().is_on_demand()).unwrap_or(false)
    });
    let on_demand_idx = order[..n].iter().filter(|&&i| {
        parsed.entry(i as usize).map(|e| e.lifetime().is_on_demand()).unwrap_or(false)
    });
    for &idx in boot_wave.chain(on_demand_idx) {
        if let Some(e) = parsed.entry(idx as usize) {
            let eps: Vec<String> =
                e.reserved_endpoints().map(|ep| ep.to_string()).collect();
            println!(
                "    {:>2}. {:<20} eps [{}] {}",
                idx,
                e.module_name(),
                eps.join(","),
                match e.lifetime() {
                    ServiceLifetime::OneShot => "one-shot".to_string(),
                    ServiceLifetime::OnDemand => "on-demand".to_string(),
                    ServiceLifetime::Persistent { max_restarts, .. } =>
                        format!("persistent(max_restarts={})", max_restarts),
                }
            );
        }
    }
    println!("  sign with: sign-elf [--seed <hex>] {}", output);
}
