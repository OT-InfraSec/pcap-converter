# SDE: vlan-data (built)
Commit: feat: store VLAN tags on packets, flows and devices.
- `lib/model`: `VLANTag`, `VLANSet` (+tests); `Packet`/`Flow` VlanID/VlanInnerID; `Device.VLANSet`.
- Repository: nullable `vlan_id`/`vlan_inner_id` on packets+flows, `devices.vlans`, `idx_flows_vlan`; all Add/Upsert/Update/Get paths; `GetFlows` maps nil filter to `IS NULL`; `LinkPacketsToFlows` matches VLAN with `IS`; `user_version = 1` + outdated-DB guard.
- Parser: `extractVLANTag` (first non-zero Dot1Q = outer, second = inner); flow key includes VLAN; device VLAN recorded in the main packet loop.
## Deviations from the design
- `DeviceManager.UpsertDevice` signature unchanged; added `RecordVLAN(address, addressType, VLANTag)` instead (less churn, DNS/SSDP post-processing has no VLAN context and must not claim "untagged").
- Fixed a pre-existing bug: parser packet ids started at 0, so `UpsertPackets` overwrote packet 1 with packet 2 (first packet of every capture lost; flow packet_refs off by one). Now starts at 1.
## Tech debt noticed
Fixed afterwards (commit "fix: ..."): `AddPackets` now stores `protocol`; `GetDevice` scans NULL columns safely; `UpdatePacket` writes `flow_id` and VLAN; 0x9100 outer QinQ ethertype is decoded as Dot1Q; `internal/dns` mock gained `LinkPacketsToFlows`; `cmd/importer` test fixtures/expectations follow the model and CLI output.
Still open:
- 5 `iec62443` tests fail on HEAD without this work: pattern-analyzer/classifier heuristics disagree with test expectations (needs a product decision on which side is right).
- Devices in the DNS/SSDP post-processing path are not given a VLAN.
