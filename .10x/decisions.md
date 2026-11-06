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

### 2026-10-20 — User + 10x-team: Subnet evidence scope (cycle 2)
- **Decision:** Sources are DHCPv4 (mask + offered address, validated by router option), DHCPv6 IA_PD and ICMPv6 RA on-link prefixes. No inference. New `source` value `ra`; DHCPv4 and DHCPv6 both `dhcp`. Row key is `(cidr, vlan, source)`.
- **Why:** Evidence-backed first; CDP/EIGRP/OSPF are sizeable and deferred. See ADR-002.
- **Alternatives considered:** DHCP only; inference of /24 and /64; extra `dhcpv6`/`dhcp-pd` source values.
- **Trade-offs accepted:** Networks without DHCP router option or RA give no row; IA_PD rows may not be on-link and are indistinguishable by `source`.
- **Impacts:** Visualizer needs a label for `ra` and a note on delegated prefixes; repository interface and mocks change.

### 2026-10-20 — User + 10x-team: `kind` column for subnets (ADR-003)
- **Decision:** `subnets.kind` = `on-link` (DHCPv4, RA) or `delegated` (DHCPv6 IA_PD), part of the row key. DHCPv6 relay-wrapped Replies are unwrapped. Subnet count is capped at 100,000.
- **Why:** `source` could not tell a delegated prefix from an on-link subnet; hostile captures could grow the map without bound.
- **Alternatives considered:** source `dhcp-pd`; documentation only.
- **Trade-offs accepted:** One prefix can appear as two rows; `Observe` signature changed.
- **Impacts:** Visualizer (label `ra`, handle `delegated`), repository interface and mocks.

### 2026-10-20 — User + 10x-team: CDP data (cycle 3, ADR-004)
- **Decision:** Extract native/management VLAN, identity, addresses and IP prefixes from CDP. Store in a separate `cdp_neighbors` table keyed by (src MAC, port ID, VLAN, fingerprint of advertised values). Prefixes go to `subnets` as `source=cdp`, `kind=advertised`.
- **Why:** devices are keyed by IP but CDP frames have no IP header; CDP prefixes do not prove on-link in the capture VLAN.
- **Alternatives considered:** columns on devices; match by MAC; last-value-wins key; kind on-link.
- **Trade-offs accepted:** visualizer joins by address lists and picks the latest row; flapping values create extra rows (capped at 100k).
- **Impacts:** repository interface and mocks, visualizer (new table, `advertised` kind, `cdp` label).

### 2026-11-06 — User: VLAN open decisions (gaps G4, G5)
- **Decision:** (G4) Confirmed: VID 0 counts as untagged (NULL), and the `devices.vlans` token format `untagged` / `N` / `N.M`, comma-joined and sorted, stays as written in the cycle 1 design. (G5) No size cap on `devices.vlans` for now. The size is bounded by the distinct VLAN combinations per IP.
- **Why:** G4: the VID 0 rule was already decided in `user-decisions.md` A2; the user confirmed the token format in the same reply. G5: the user judged the limit adequate for now.
- **Alternatives considered:** G5: a cap like `subnets` (100,000) with a drop-and-count policy.
- **Trade-offs accepted:** G5: a QinQ-heavy or hostile capture can produce a long string that is loaded on every `GetDevice` and `GetDevices`. Revisit if a benchmark or a real capture shows a problem.
- **Impacts:** Visualizer must still confirm the token contract ([docs/VLAN_VISUALIZER_CHECKLIST.md](../docs/VLAN_VISUALIZER_CHECKLIST.md)). Converter: no code change. Design note on size added.

### 2026-10-20 — 10x-team: User decision log written
- **Decision:** All user decisions of cycles 2 and 3, with rejected alternatives and assumed reasons, are recorded in `user-decisions.md`.
- **Why:** User asked for every decision, its alternatives and why they were declined to be documented. Reasons are inferred, not stated by the user, and are labelled as such.
- **Impacts:** Reference for ADR-002/003/004 and future cycles.
