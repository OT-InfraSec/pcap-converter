# Cycle 2: Subnet data (R4)

Part of [segment data overview](2026-10-20-segment-data-overview.md). Depends on cycle 1 (`vlan_id` semantics and NULL convention).

## R4: `subnets` table
One row per detected Subnet:

| Column | Meaning |
|---|---|
| `cidr` | Network prefix in canonical form, e.g. `10.0.1.0/24`, `2001:db8:1::/64` |
| `vlan_id` | VLAN the Subnet was observed in (NULL = untagged). The same prefix in two VLANs is two rows. |
| `source` | How the prefix was determined: `dhcp`, `cdp`, `eigrp`, `ospf`, `inferred`. Shown to the analyst on the Subnet box. |
| `first_seen`, `last_seen` | Time range of the evidence |

- Device membership is **not** stored; the visualizer assigns device IPs to Subnets by longest-prefix match within the device's VLAN (also needed when merging several capture files).
- Candidate evidence sources, most reliable first: DHCP option 1 combined with the offered address / router option; CDP `IPPrefixes`; decoded EIGRP/OSPF routes for directly connected networks; any converter inference (must be marked `inferred`).
- Both IPv4 and IPv6 are required.

## Open questions for design
- Which evidence sources are in scope for the first delivery (DHCP only vs. also CDP/EIGRP/OSPF)? EIGRP TLV decoding and OSPF support are sizeable on their own.
- Inference rules and confidence for `inferred` prefixes.
- Schema version bump (see cycle 1 open questions).
