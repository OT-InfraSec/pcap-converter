# QA report: subnet-data (cycle 2)

Date: 2026-10-20. Scope: `subnets` table, `SubnetManager`, DHCPv4 / DHCPv6 IA_PD / RA extractors, repository, parser wiring.

## Result: pass
`go test ./...` green except the 5 `internal/iec62443` tests that fail on HEAD without this work (heuristic vs. test mismatch, needs a product decision; untouched). `go vet` clean on touched packages.

## What was verified
| Area | Tests |
|---|---|
| Model | canonical CIDR (host bits masked, IPv6 compressed lowercase), `Validate` for CIDR, source and kind |
| Extractors (table tests) | DHCPv4: valid, second router inside prefix, router outside, no router, no mask, zero offered address, non-contiguous /0 /32 masks, truncated options, request. RA: L set, A-only, link-local, /0, >128, truncated, host bits. DHCPv6: IA_PD, multiple prefixes, IA_NA, solicit, truncated and lying sub-option lengths, Relay-Reply single/nested/over depth/garbage/Relay-Forward/relayed solicit |
| SubnetManager | collapse + widen time range, key = prefix+outer VLAN+source+kind, inner QinQ tag not identity, no aliasing of the caller's VLAN pointer, invalid prefix, clear, 100k cap |
| Repository | NULL `vlan_id` round-trip and `IS NULL` filter, VLAN 10 vs 20 vs untagged = 3 rows, upsert widens first/last seen (also earlier timestamps), source and kind in key, tenant isolation, invalid rows rejected, unknown filter keys rejected, `user_version` still 1 |
| End to end (synthesized pcaps) | DHCPv4 untagged/VLAN 10 (same prefix, two rows), router outside prefix dropped, RA on-link kept and A-only dropped, DHCPv6 IA_PD stored as `delegated`, relayed DHCPv6 in VLAN 30, capture without evidence gives no rows |
| Fuzz | 3 targets x 20 s (about 9M executions): no panic, every prefix valid, masked and within bounds |

Coverage of new code: extractors and manager 93-100%; repository subnet methods 83-94% (uncovered lines are DB error branches).

## Bugs and gaps found during the review (all fixed)
1. DHCPv6 Relay-Reply messages were ignored. Now unwrapped (depth 8).
2. `docs/db_schema.md` class diagram lacked `subnets`. Added.
3. `source` could not tell delegated (IA_PD) from on-link prefixes. Added `kind` column (ADR-003).
4. Unbounded subnet map under hostile input. Capped at 100,000 distinct subnets with a one-time warning.

## Residual risks and notes
- Evidence is taken at face value: a spoofed RA or DHCP reply in a capture produces a row (inherent to passive analysis; `source` and `kind` show provenance).
- Networks without DHCP traffic, without a DHCP router option, or without RA yield no subnet by design (no inference).
- The cap silently drops further new subnets after the warning; real captures are far below it.
- Visualizer must handle one prefix appearing twice (on-link and delegated) and a label for source `ra`.
