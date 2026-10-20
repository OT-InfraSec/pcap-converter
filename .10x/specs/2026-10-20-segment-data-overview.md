# Segment data: requirements overview

Source: `/Users/patrick/gitRepos/pcap-importer/web_visualizer_go/docs/pcap-importer-requirements.md` (the visualizer's ADR 0001, 0002, 0005 and GLOSSARY.md live in that repo).

The visualizer draws VLANs and Subnets as nested boxes and shows VLAN/Subnet columns in the device table. The converter stores none of the data this needs. The source requirements are split into independent cycles, each with its own brainstorm, design, ADR and implementation:

| Cycle | Spec | Requirements | Status |
|---|---|---|---|
| 1 | [vlan-data](2026-10-20-vlan-data-requirements.md) | R1, R2, R3, R5 | Requirements captured, design pending |
| 2 | [subnet-data](2026-10-20-subnet-data-requirements.md) | R4 (+ R5 version bump) | Blocked on cycle 1 (subnets are keyed by VLAN) |
| 3 | CDP (nice to have) | Register CDP parser, store NativeVLAN / ManagementVLAN per device | Not started; can feed cycle 2 evidence |

## Current state (importer `v0.0.0-20250727123807-b96eb01bcdb4`, per source doc)

- 802.1Q tags are decoded by gopacket but discarded; the parser reads only Ethernet src/dst MAC and `ethernet_type` (`internal/parser/gopacket_parser.go`, around line 537 in this repo). No VLAN column on `packets`, `devices` or `flows`. QinQ not handled.
- No subnet, netmask or prefix stored per device. DHCP option 1 only appears in `packets.layers` JSON, for DHCP replies only.
- EIGRP route TLVs are not decoded (`lib/layers/eigrp.go`), OSPF is unsupported, and the CDP layer exists but is not registered in the parser.
- Devices are keyed by IP (`address_type:address`), one row per IP.
