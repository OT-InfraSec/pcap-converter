# Cycle 3 design: CDP data

Part of [segment data overview](2026-10-20-segment-data-overview.md). Depends on cycle 1 (VLAN NULL convention) and cycle 2 (`subnets`, ADR-003 `kind`). Status: **approved design, awaiting spec review before implementation**.
Constraint: breaking schema changes allowed, no migrations, `user_version` stays 1.

## Scope (decided with user)
- Extract from CDP frames: native VLAN, management VLAN, device identity (device ID, platform, software version, sys name, capabilities), addresses, and IP prefixes.
- Storage: separate `cdp_neighbors` table (devices are not touched; the visualizer joins through the address lists).
- IP prefixes also go to `subnets` with `source = cdp`, `kind = advertised`.
- Out of scope: the visualizer's "map untagged traffic to a VLAN" feature, LLDP, changes to `devices` or `flows`.

## Facts
gopacket already decodes CDP (SNAP 0x2000 -> `layers.LayerTypeCiscoDiscovery` -> `layers.LayerTypeCiscoDiscoveryInfo`). The parser only has to read the info layer. The copy in `lib/layers/ciscoDiscovery.go` is not used and stays untouched. `ManagementVLAN` sits in the optional cluster-management TLV and is usually 0.

## Approach
A `CDPManager` collects in memory while parsing and everything is written once at the end of `ParseFile` (SQLite exclusive-lock history, AGENTS.md). Pure extractor functions turn the decoded layer into a neighbor record and prefixes.

## Table `cdp_neighbors`
| Column | Meaning |
|---|---|
| `tenant_id`, `src_mac`, `port_id` | The advertising interface (a switch sends from a different MAC/port ID per port) |
| `vlan_id` | VLAN the frame was seen in (outer tag; NULL = untagged) |
| `device_id`, `platform`, `software_version`, `sys_name` | Identity strings |
| `capabilities` | Sorted comma-joined tokens: `router`, `switch`, `host`, `phone`, `bridge`, `repeater`, `igmp`, `remote-managed` (empty if none) |
| `addresses`, `mgmt_addresses` | Comma-joined IPs in advertised order (canonical text) |
| `native_vlan`, `management_vlan` | Nullable; 0 or > 4094 is stored as NULL |
| `fingerprint` | SHA-256 hex of all advertised values above (not of timestamps) |
| `first_seen`, `last_seen` | Time range |

Identity: unique on `(tenant_id, src_mac, port_id, COALESCE(vlan_id,-1), fingerprint)`. The same advertisement repeated widens `first_seen`/`last_seen`; a changed value (e.g. native VLAN reconfigured) is a second row with its own range. The visualizer picks the row with the latest `last_seen`.

## Subnets from CDP
Each valid entry of the IP Prefix TLV becomes `Subnet{source: cdp, kind: advertised, vlan: frame's outer VLAN}`. `advertised` means the neighbor claims to be connected to the prefix; it is not proof the prefix is on-link in the capture VLAN (a router lists its connected networks of other interfaces too). Same bounds as cycle 2: canonical masked prefix, length 1..max, no link-local/loopback/multicast. `SubnetKindAdvertised` is added to the model and `Validate`.

## Details
- CDP frames carry no IP header; the source MAC comes from Ethernet. Frames without a CDP info layer or with no device ID and no addresses are skipped.
- Strings are truncated to 255 bytes and stripped of NUL/control characters before storage.
- Row cap: 100,000 distinct neighbor rows (warning once), like the subnet cap. Known rows still widen their time range.
- No `user_version` bump.

## Error handling
Decode failures (truncated TLVs) are handled by gopacket; failed frames are skipped. Extractors never fail parsing.

## Testing
Synthesized CDP frames (SNAP/LLC + CDP TLVs serialized in the test) following `gopacket_parser_subnet_test.go`.
- Extractor tables: full frame, native VLAN 0 and 4095, management VLAN, capabilities encoding, addresses and mgmt addresses, odd strings, truncated/malformed TLVs.
- Manager: repeat collapses and widens, changed native VLAN gives two rows, same MAC with different port ID gives two rows, VLAN NULL vs tagged, cap.
- Repository: round-trip incl. NULL VLANs and NULL native/management VLAN, upsert widens, tenant isolation, filters whitelisted.
- End to end: a capture with a CDP frame yields a neighbor row and (with IPPrefixes) `cdp`/`advertised` subnets.
- Fuzz the extractor input bytes.
