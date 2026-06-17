// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Jason Ricca

//! Render the canonical audit event taxonomy to markdown.
//!
//! Reads `cambios_abi::audit::TAXONOMY` (the single source of truth, defined
//! by the `audit_taxonomy!` macro) and prints a deterministic markdown
//! document to stdout. The Makefile redirects this to
//! `docs/generated/audit-taxonomy.md`:
//!
//! - `make audit-taxonomy`        — regenerate the doc.
//! - `make check-audit-taxonomy`  — regenerate to a pipe, diff against the
//!                                  committed file, fail if stale.
//!
//! Output is derived entirely from the const slice — there is no hand-written
//! second copy of the event list, so the doc cannot drift from the ABI. Class
//! names and the version come from the ABI too; nothing is hardcoded here that
//! could fall out of sync.

use cambios_abi::audit::{AUDIT_TAXONOMY_VERSION, TAXONOMY};

fn main() {
    let mut out = String::new();

    out.push_str("# Audit Event Taxonomy\n\n");
    out.push_str(
        "<!-- GENERATED FILE — do not edit by hand. Regenerate with `make audit-taxonomy`. -->\n",
    );
    out.push_str(
        "<!-- Source of truth: cambios-abi/src/audit.rs (the `audit_taxonomy!` macro). -->\n",
    );
    out.push_str(
        "<!-- ADR-007 carries the categories and rationale; this file is the enumeration. -->\n\n",
    );

    out.push_str(&format!("**Taxonomy version:** {AUDIT_TAXONOMY_VERSION}\n\n"));

    out.push_str(
        "Each kernel audit event is a 64-byte `RawAuditEvent`. Byte 0 is the\n\
         discriminant (`disc`) below; the flags byte (byte 1) carries the sampled\n\
         bit (bit 0) and the [`AuditClass`] (bits 1..=3). The `domain.action` name\n\
         is the canonical, greppable vocabulary — the `domain` prefix groups\n\
         events by subsystem, the `class` is the coarse on-wire filter.\n\n",
    );

    // Classes present, in first-appearance order — derived from the data so
    // this legend cannot list a class the taxonomy does not use, or omit one
    // it does.
    out.push_str("## Classes in use\n\n");
    let mut seen: Vec<&str> = Vec::new();
    for entry in TAXONOMY {
        let c = entry.class.name();
        if !seen.contains(&c) {
            seen.push(c);
        }
    }
    out.push_str(&seen.join(", "));
    out.push_str("\n\n");

    out.push_str("## Events\n\n");
    out.push_str("| disc | domain.action | class | arguments |\n");
    out.push_str("|---:|---|---|---|\n");
    for entry in TAXONOMY {
        out.push_str(&format!(
            "| {} | `{}` | {} | {} |\n",
            entry.discriminant,
            entry.name,
            entry.class.name(),
            // Escape `|` so an args cell like `allowed(0|1)` does not break
            // the markdown table column boundary.
            entry.args_doc.replace('|', "\\|"),
        ));
    }

    print!("{out}");
}
