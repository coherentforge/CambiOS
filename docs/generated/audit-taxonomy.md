# Audit Event Taxonomy

<!-- GENERATED FILE — do not edit by hand. Regenerate with `make audit-taxonomy`. -->
<!-- Source of truth: cambios-abi/src/audit.rs (the `audit_taxonomy!` macro). -->
<!-- ADR-007 carries the categories and rationale; this file is the enumeration. -->

**Taxonomy version:** 1

Each kernel audit event is a 64-byte `RawAuditEvent`. Byte 0 is the
discriminant (`disc`) below; the flags byte (byte 1) carries the sampled
bit (bit 0) and the [`AuditClass`] (bits 1..=3). The `domain.action` name
is the canonical, greppable vocabulary — the `domain` prefix groups
events by subsystem, the `class` is the coarse on-wire filter.

## Classes in use

security, dataflow, lifecycle, anomaly, meta, context

## Events

| disc | domain.action | class | arguments |
|---:|---|---|---|
| 0 | `cap.granted` | security | subject=grantor object=endpoint arg0=grantee arg1=rights |
| 1 | `cap.revoked` | security | subject=revoker object=endpoint arg0=holder |
| 2 | `cap.denied` | security | subject=caller object=endpoint |
| 3 | `ipc.send` | dataflow | subject=sender object=endpoint arg0=payload_len |
| 4 | `ipc.recv` | dataflow | subject=receiver object=endpoint arg0=payload_len |
| 5 | `chan.created` | lifecycle | subject=creator object=channel arg0=size_pages |
| 6 | `chan.attached` | lifecycle | subject=attacher object=channel |
| 7 | `chan.closed` | lifecycle | subject=closer object=channel arg0=bytes_transferred arg1=lifetime_ticks |
| 8 | `enforce.syscall_denied` | security | subject=caller arg0=syscall_number |
| 9 | `loader.binary_loaded` | security | subject=0(kernel) arg0=binary_size arg1..arg3=content_hash[0..24] |
| 10 | `loader.binary_rejected` | security | subject=0(kernel) arg0=rejection_reason |
| 11 | `proc.created` | lifecycle | subject=pid object=parent_pid |
| 12 | `proc.terminated` | lifecycle | subject=pid arg0=exit_code arg1=runtime_ticks |
| 13 | `enforce.policy_query` | security | subject=queried_pid arg0=syscall_number arg1=allowed(0\|1) |
| 14 | `ai.anomaly_hook` | anomaly | reserved for AI watcher anomaly flagging |
| 15 | `meta.audit_dropped` | meta | subject=0(kernel) arg0=dropped_count arg1=cpu_id |
| 16 | `ui.input_focus_change` | context | subject=compositor object=new_window_id arg0=old_window_id arg1..arg3=new_owner_principal[0..24] |
| 17 | `cluster.created` | lifecycle | subject=creator object=cluster_id arg0=policy arg1=member_count |
| 18 | `cluster.revoked` | lifecycle | subject=initiator object=cluster_id arg0=member_count arg1=channel_count arg2=reason |
| 19 | `chan.teardown.started` | lifecycle | subject=initiator object=channel arg0=teardown_kind(0=Close,1=Revoke) |
| 20 | `chan.teardown.completed` | lifecycle | subject=completer object=channel arg0=teardown_kind(0=Close,1=Revoke) arg1=num_pages |
| 21 | `meta.reap_would_free_active_root` | meta | subject=0(kernel) arg0=active_root_phys |
