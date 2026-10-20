# SDE: vlan-data (built)
Commit: feat: store VLAN tags on packets, flows and devices.
- `lib/model`: `VLANTag`, `VLANSet` (+tests); `Packet`/`Flow` VlanID/VlanInnerID; `Device.VLANSet`.
- Repository: nullable `vlan_id`/`vlan_inner_id` on packets+flows, `devices.vlans`, `idx_flows_vlan`; all Add/Upsert/Update/Get paths; `GetFlows` maps nil filter to `IS NULL`; `LinkPacketsToFlows` matches VLAN with `IS`; `user_version = 1` + outdated-DB guard.
- Parser: `extractVLANTag` (first non-zero Dot1Q = outer, second = inner); flow key includes VLAN; device VLAN recorded in the main packet loop.
## Deviations from the design
- `DeviceManager.UpsertDevice` signature unchanged; added `RecordVLAN(address, addressType, VLANTag)` instead (less churn, DNS/SSDP post-processing has no VLAN context and must not claim "untagged").
- Fixed a pre-existing bug: parser packet ids started at 0, so `UpsertPackets` overwrote packet 1 with packet 2 (first packet of every capture lost; flow packet_refs off by one). Now starts at 1.
## Tech debt noticed (not fixed)
- `AddPackets` does not store the `protocol` column.
- `GetDevice` fails on NULL `protocol_list` for devices written by `UpsertDevices`.
- `UpdatePacket` does not update VLAN (or flow) columns; unused by the parser.
- `cmd/importer` and `internal/dns` tests do not build (mockRepo lacks LinkPacketsToFlows); 5 `iec62443` tests fail. All identical on HEAD before this work.
- Devices in the DNS/SSDP post-processing path are not given a VLAN.
