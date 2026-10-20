# ADR-001: VLAN stored as nullable columns plus device VLAN set

**Status:** Accepted
**Date:** 2026-10-20
**Feature:** vlan-data
**Author:** 10x-Team (Architect + Staff Engineer)

## Context
The visualizer needs VLAN (outer and QinQ inner) per packet and flow, and the VLAN set per device. The converter discards 802.1Q tags. Devices are keyed by IP. Breaking changes are allowed.

## Decision
- `packets` and `flows` get nullable `vlan_id`, `vlan_inner_id` (NULL = untagged / no QinQ; VID 0 treated as untagged).
- The flow key includes outer and inner VLAN.
- `devices.vlans` is a sorted comma-joined text set (`untagged`, `100`, `100.200`), mirroring `mac_addresses`.
- `PRAGMA user_version = 1` set in `createTables`; an old DB (version 0 with existing `packets` table) is rejected with a re-import error.

## Alternatives Considered
| Alternative | Pros | Cons | Why Not |
|-------------|------|------|---------|
| Separate `device_vlans` join table | Normalized, queryable | New table, more repo code, visualizer joins | Overkill; existing sets are text columns |
| Store VLAN only in `layers` JSON | No schema change | Not queryable, cannot key flows | Fails R1/R2 |
| Store untagged as VLAN 1 | Simpler | Cannot detect untagged-only captures | Violates R1 |
| Version migrations | Keeps old data | Complexity, no data to keep | User: no backward compat |

## Consequences
### Positive
Minimal change per layer; consistent with existing patterns.
### Negative
Text set is not indexable; interface signatures change (managers, mocks).
### Risks
Packet-to-flow linking (commit 629e6d2) may depend on the old flow key; verify in tests.

## Dependencies
Visualizer parses the `vlans` token format. Cycle 2 (subnets) reuses the NULL convention.
