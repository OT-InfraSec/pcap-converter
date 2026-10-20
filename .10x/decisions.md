# Project Decisions

> This file is the shared brain of the 10x-Team. Every role reads it before acting and writes to it after deciding. Append only — never delete or overwrite another role's decisions.

## Project: pcap-converter
Started: 2026-10-20

---

<!-- Decisions are appended below by each role. Format:
### [Date] — [Role]: [Decision Title]
- **Decision:** What was decided
- **Why:** Business/technical justification
- **Alternatives considered:** What else was evaluated
- **Trade-offs accepted:** What we're giving up
- **Impacts:** Which roles/components this affects
-->

### 2026-10-20 — User: No backward compatibility for schema
- **Decision:** Breaking changes are fine; old data is not kept. Databases are regenerated, no migrations, no intermediate `user_version` per cycle. An incomplete database between cycles is acceptable.
- **Why:** No existing data to preserve; matches AGENTS.md "database regeneration" approach.
- **Alternatives considered:** Per-cycle version bumps (v1 VLAN, v2 subnets).
- **Trade-offs accepted:** Interim databases lack subnets; visualizer sees `user_version = 1` without subnet data.
- **Impacts:** DBA/Architect (in-place schema edits in `createTables`), SDE (no migration code), cycle 2 (no version bump).
