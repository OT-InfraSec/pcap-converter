# ADR-002: Subnets collected from protocol evidence into a dedicated table

**Status:** Accepted
**Date:** 2026-10-20
**Feature:** subnet-data
**Author:** 10x-Team (Architect + Staff Engineer)

## Context
The visualizer needs the IP subnets of each VLAN, with the provenance of each prefix. The converter stores only devices, flows and packets; subnet masks live only in packet layer JSON. Breaking schema changes are allowed (ADR-001, decisions.md). DHCP, RA and (later) CDP/EIGRP/OSPF carry prefix evidence of different reliability.

## Decision
- New `subnets` table: `tenant_id, cidr, vlan_id (NULL = untagged), source, first_seen, last_seen`; unique per `(tenant_id, cidr, vlan_id, source)`.
- A `SubnetManager` accumulates evidence in memory and writes once at the end of `ParseFile` (no concurrent DB writes).
- First delivery uses DHCPv4 (mask + offered address, validated by router option), DHCPv6 IA_PD and ICMPv6 RA (on-link prefixes). `source` values written: `dhcp`, `ra`. No inference; `inferred`, `cdp`, `eigrp`, `ospf` reserved.
- Device membership is not stored; the visualizer does longest-prefix match within the VLAN.
- No `user_version` bump (stays 1).

## Alternatives Considered
| Alternative | Pros | Cons | Why Not |
|-------------|------|------|---------|
| Keep subnet info in layer JSON, visualizer derives | No schema change | Not queryable, no dedup, no VLAN scoping | Fails R4 |
| One row per prefix, sources merged into a list | Fewer rows | Loses per-source first/last seen, harder to query | Visualizer can collapse |
| Store device-to-subnet membership | Direct lookup | Stale when merging captures; redundant | User decision: not stored |
| Infer /24 etc. for uncovered addresses | More coverage | Guesses prefix lengths | User: no inference now |
| Include CDP/EIGRP/OSPF now | Full coverage | EIGRP TLV decode and OSPF are sizeable | Deferred to later cycles |

## Consequences
### Positive
Authoritative, queryable subnets with provenance and VLAN scoping; reuses the deferred-write pattern; reserved source values keep the visualizer contract stable.
### Negative
Networks without DHCP/RA traffic or without a DHCP router option yield no subnet. IA_PD rows may not be on-link and are indistinguishable by `source`. Repository interface and mocks change.
### Risks
Malformed packet bytes in new decoders (mitigation: bounds checks, tests with truncated input). Duplicated repository paths missing the new table (mitigation: grep all Add/Upsert/Get paths).

## Dependencies
Depends on ADR-001 (NULL = untagged convention). Constrains later cycles: new evidence sources feed `SubnetManager.Observe` with their own `source` value.
