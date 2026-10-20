# ADR-003: `kind` column distinguishes on-link from delegated subnets

**Status:** Accepted (amends ADR-002; ADR-002 itself is unchanged)
**Date:** 2026-10-20
**Feature:** subnet-data
**Author:** 10x-Team (Architect + Staff Engineer)

## Context
ADR-002 stores DHCPv6 IA_PD prefixes as `source = dhcp`. A delegated prefix is handed to a router for downstream use and need not be on-link in the VLAN where it was observed, but `source` could not express that, so the visualizer could not avoid presenting it as that VLAN's subnet. Found in the cycle 2 review; the user chose a dedicated column.

## Decision
- `subnets.kind TEXT NOT NULL`: `on-link` (DHCPv4, RA) or `delegated` (DHCPv6 IA_PD).
- `kind` is part of the uniqueness key `(tenant_id, cidr, COALESCE(vlan_id,-1), source, kind)` and of `SubnetManager`'s key. `source` values stay `dhcp`/`ra`.
- In-place schema edit, no `user_version` bump (ADR-001: no migrations).
- Also: DHCPv6 Replies inside Relay-Reply messages are unwrapped, depth-limited to 8.

## Alternatives Considered
| Alternative | Pros | Cons | Why Not |
|-------------|------|------|---------|
| New source `dhcp-pd` | No new column | Reverses the user's earlier source choice; mixes mechanism and meaning | User chose a column |
| Document only | No change | Visualizer cannot tell rows apart | Leaves the gap open |

## Consequences
### Positive
Visualizer can filter or label delegated prefixes explicitly; future sources can declare their own kind.
### Negative
Repository, model and manager signatures changed (`Observe` takes a kind); the same prefix can appear twice (as on-link and delegated).
### Risks
Visualizer must handle two rows for one prefix; documented in docs/db_schema.md.

## Dependencies
Amends ADR-002; relies on ADR-001 (no migrations).
