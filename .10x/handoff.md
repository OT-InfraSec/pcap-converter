# Current Handoff

> This file tracks the context passed from one role to the next. Each role overwrites the "Current Handoff" section when passing work forward. Previous handoffs are preserved in the History section below.

## From: init-project → To: First active role
**Date:** 2026-10-20
**Phase:** Setup → Brainstorming

### Context
Project state initialized. Ready for the first role to begin work.
Pending input: segment-data requirements (VLAN/Subnet) from /Users/patrick/gitRepos/pcap-importer/web_visualizer_go/docs/pcap-importer-requirements.md. Requirements split into cycles (see `specs/2026-10-20-segment-data-overview.md`): cycle 1 VLAN (R1,R2,R3,R5), cycle 2 subnets (R4), cycle 3 CDP. Schema/version question resolved: breaking changes OK, no migrations, `user_version = 1` set in cycle 1 only (see decisions.md). Next: brainstorm/design cycle 1.

### Open Questions
- What are we building?
- What problem does this solve?
- Who is the target user?

---

## Handoff History
(none yet)

> Update 2026-10-20: cycle 1 design drafted in `specs/2026-10-20-vlan-data-design.md`; user review pending before Phase 1-3 state files, ADR and implementation.

> Phase 3 complete: ADR-001, tasks in decisions/engineering-manager/vlan-data.md. SDE implements tasks 1-5.

> Cycle 1 complete (commit feat: store VLAN tags). Visualizer contract: NULL = untagged; devices.vlans tokens `untagged,10,10.200`; user_version=1. Open items: tech debt in decisions/sde/vlan-data.md. Next: brainstorm cycle 2 (subnets, R4).

> Phase 3 complete (cycle 2 subnet-data): spec specs/2026-10-20-subnet-data-design.md, ADR-002, tasks in decisions/engineering-manager/subnet-data.md. Next: user reviews spec, then SDE implements tasks 1-7 (use tdd, synthesized pcaps).

> Phase 4 complete (cycle 2 subnet-data): see decisions/sde/subnet-data.md and decisions/dba/subnet-data.md. Test: extractors with malformed bytes (security: parser handles untrusted packets), IA_PD semantics, VLAN/NULL handling, re-import widening. Known gaps: DHCPv6 relay messages not unwrapped; db_schema.md class diagram lacks subnets. Next: QA + Security verification.

> Phase 5 complete (cycle 2 subnet-data): QA and security reviews written, no open findings. Gaps from phase 4 fixed (relay unwrapping, schema diagram, `kind` column per ADR-003, 100k cap). Visualizer contract: `subnets(cidr, vlan_id NULL=untagged, source dhcp|ra, kind on-link|delegated, first_seen, last_seen)`; one prefix can be two rows; `user_version` still 1. Open: 5 iec62443 test failures (unrelated). Next: cycle 3 (CDP) is optional.

> Phase 3 complete (cycle 3 cdp-data): spec specs/2026-10-20-cdp-data-design.md, ADR-004, tasks in decisions/engineering-manager/cdp-data.md. Next: user reviews spec, then SDE implements tasks 1-6 (tdd, synthesized CDP frames, fuzz the extractor).

> Added `user-decisions.md`: all user decisions of cycles 2-3 with declined alternatives and assumed reasons (to be corrected by the user where wrong).

> Phase 4 complete (cycle 3 cdp-data): see decisions/sde/cdp-data.md and decisions/dba/cdp-data.md. Visualizer contract: `cdp_neighbors(src_mac, port_id, vlan_id NULL=untagged, device_id, platform, software_version, sys_name, capabilities, addresses, mgmt_addresses, native_vlan NULL, management_vlan NULL, fingerprint, first_seen, last_seen)`; pick the row with latest `last_seen` per interface; CDP prefixes are `subnets` rows `cdp`/`advertised`. Test/review in phase 5: tagged-CDP fallback (`cdpInfoFromPacket`), hostile frames. **Security finding:** `SkipDecodeRecovery=true` lets an untagged CDP frame with prefix length > 32 panic the whole import (gopacket nil deref); pre-existing, needs a user decision. Next: QA + Security verification.

> Phase 5 complete (cycle 3 cdp-data): QA and security reviews in reviews/2026-10-21-cdp-*.md, no open findings. Fixed in this phase: `SkipDecodeRecovery` re-enabled (hostile frame no longer aborts an import; benchmark showed no cost). Visualizer contract unchanged from the phase 4 note. Open: 5 iec62443 test failures (unrelated); try one real CDP capture; `lib/layers` decoders not audited. Cycles 1-3 are done.
