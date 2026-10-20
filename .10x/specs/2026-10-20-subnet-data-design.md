# Cycle 2 design: Subnet data (R4)

Requirements: [subnet-data-requirements](2026-10-20-subnet-data-requirements.md). Status: **approved design, awaiting spec review before implementation**.
Constraint: breaking schema changes allowed, no migrations, `user_version` stays 1.

## Scope (decided with user)
- Evidence sources: **DHCPv4, DHCPv6 (IA_PD), ICMPv6 Router Advertisement**. CDP, EIGRP, OSPF are out of scope (later cycles).
- **No inference.** `inferred` stays a reserved `source` value; nothing writes it.
- `source` values written: `dhcp` (v4 and v6), `ra`. Reserved: `cdp`, `eigrp`, `ospf`, `inferred`.

## Approach
A `SubnetManager` collects evidence in memory during parsing and everything is written once at the end of `ParseFile` (SQLite exclusive-lock deadlock history, see AGENTS.md).

| Layer | Change |
|---|---|
| `lib/model` | `Subnet{TenantID, CIDR string, VlanID *int, Source string, FirstSeen, LastSeen time.Time}`. |
| `internal/parser` | `SubnetManager.Observe(prefix netip.Prefix, vlan VLANTag, source string, ts)` upserts by `cidr+vlan+source`, widening first/last seen. Extractors for DHCPv4, DHCPv6 and RA. |
| Repository | `UpsertSubnets([]*Subnet)`, `GetSubnets(tenantID, filters)` (nil VLAN filter maps to `IS NULL`, as `GetFlows`). Interface, SQLite implementation, `testutil` mock. |
| Schema | `subnets(tenant_id, cidr, vlan_id NULL, source, first_seen, last_seen)`, unique on `(tenant_id, cidr, vlan_id, source)` (NULL-safe, via expression/COALESCE index). |

- `vlan_id` is the outer tag; untagged and VID 0 are NULL. Same prefix in two VLANs = two rows. QinQ inner tag is not part of subnet identity.
- `source` is part of the key: the same prefix seen via DHCP and RA is two rows. The visualizer may collapse them.
- Device membership is not stored (visualizer does longest-prefix match within the VLAN).
- CIDR is canonical: masked network address, IPv4 dotted, IPv6 lowercase compressed (`netip.Prefix.Masked().String()`).

## Evidence rules
**DHCPv4** (replies only, as today): require option 1 (subnet mask) and a non-zero `YourClientIP`. Mask must be contiguous and between /1 and /31. Prefix = `YourClientIP` masked. Emit only if **at least one router address (option 3) lies inside the prefix**; with no router option, or none inside, the evidence is dropped. Relays need no special code (the offered address is in the client's subnet). Several servers offering the same prefix collapse into one row.

**Router Advertisement** (ICMPv6 type 134): for each Prefix Information option (type 3, length 4 units of 8 bytes) with the on-link (L) flag set, emit prefix/length with source `ra`. Skip A-only prefixes, link-local (`fe80::/10`) and prefix length > 128 or malformed options.

**DHCPv6**: gopacket gives raw options, so decode manually in replies. IA_NA (option 3) carries no prefix length, so it yields no row. IA_PD (option 25) with IAPREFIX sub-option (26: preferred 4, valid 4, prefix-len 1, prefix 16) yields a prefix, stored as `dhcp`. **Caveat for the visualizer:** an IA_PD prefix is delegated to a router for downstream use and need not be on-link in the VLAN where it was observed; `source` alone cannot tell the two cases apart.

## Error handling
Parsing never fails on subnet evidence. Truncated or malformed options are dropped with a debug log. Extractors treat bytes as untrusted: bounds-check every option length, prefix length <= 32 (v4) / 128 (v6).

## Testing
Synthesized frames following `internal/parser/gopacket_parser_vlan_test.go`.
- DHCPv4: valid reply gives a row; router outside prefix, no router, bad or /0 /32 mask, zero offered address give none; two servers give one row; VLAN 10 vs 20 gives two rows; untagged gives NULL; IPv4 only prefixes canonical.
- RA: L set gives a row; A-only, link-local, truncated options give none.
- DHCPv6: IA_PD gives a row; IA_NA gives none; truncated sub-options give none.
- Repository: round-trip with NULL `vlan_id`, upsert widens first/last seen, `IS NULL` filter, `user_version == 1`.
- Existing tests stay green; the 5 failing `internal/iec62443` tests predate this work.

## Out of scope
CDP/EIGRP/OSPF evidence, inference, cycle 3 (CDP native/management VLAN), device membership storage, migrations.

## Amendment 2026-10-20 (see ADR-003)
- `subnets.kind` (`on-link` | `delegated`) was added and is part of the key and row identity: DHCPv4 and RA rows are `on-link`, DHCPv6 IA_PD rows are `delegated`. This replaces the "source cannot tell" caveat above.
- DHCPv6 Replies wrapped in Relay-Reply messages are unwrapped (max nesting 8, per RFC 8415); Relay-Forward and non-Reply inner messages are not evidence.
