# ADR-004: CDP stored in a `cdp_neighbors` table; CDP prefixes are `advertised` subnets

**Status:** Accepted (extends ADR-002 and ADR-003; both unchanged)
**Date:** 2026-10-20
**Feature:** cdp-data
**Author:** 10x-Team (Architect + Staff Engineer)

## Context
The visualizer needs per-device native and management VLAN (to place untagged traffic) and benefits from CDP identity and prefix data. Devices are keyed by IP while a CDP frame has no IP header and is sent from a per-port MAC. CDP IPPrefixes list networks a router is connected to, not necessarily the capture VLAN.

## Decision
- New table `cdp_neighbors` keyed by `(tenant, src_mac, port_id, outer VLAN, fingerprint of all advertised values)`; a changed value is a new row, repeats widen first/last seen. `devices` is not changed; the visualizer joins through `addresses`/`mgmt_addresses`.
- Native/management VLAN 0 or > 4094 is NULL.
- CDP IPPrefixes become `subnets` rows with `source = cdp`, new `kind = advertised`, VLAN of the frame.
- In-memory `CDPManager`, one batched write at the end of `ParseFile`; row cap 100,000. No `user_version` bump.

## Alternatives Considered
| Alternative | Pros | Cons | Why Not |
|-------------|------|------|---------|
| Columns on `devices` keyed by Addresses TLV IPs | No join | Needs device creation from CDP, mixes per-interface data into per-IP rows | User chose a separate table |
| Match by source MAC to devices | Works without Addresses TLV | Routers reuse one MAC for many IPs, mislabels | Unreliable |
| Key (MAC, port), last value wins | Fewer rows | Loses reconfiguration | User chose full-value key |
| CDP prefixes as `on-link` | Simplest | Wrong VLAN for a router's other interfaces | Over-claims what CDP proves |

## Consequences
### Positive
Faithful per-interface data with history; no change to the device model; prefix evidence reuses the cycle 2 table.
### Negative
Visualizer must join and pick the latest row; a flapping value creates many rows (bounded by the cap).
### Risks
Hostile frames with varying values (mitigation: cap, bounded strings); spoofed CDP is accepted as evidence (provenance kept in the table and `source`).

## Dependencies
ADR-001 (NULL = untagged), ADR-002/003 (`subnets`, `kind`).
