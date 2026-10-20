# QA: vlan-data
Tests added: model (VLANSet/Token), repository (round trips incl. NULL, flow split + merge per VLAN, link-by-VLAN, user_version, outdated-DB guard), managers (flow key per VLAN, reverse direction, one device with VLAN set), parser (extractVLANTag: untagged/single/QinQ/VID 0/VID 1; end-to-end pcap -> sqlite for packets, flows, devices; untagged-only capture).
Result: `go test ./internal/parser ./internal/repository ./lib/...` pass. Remaining failures (cmd/importer, internal/dns build; 5 iec62443 tests) are identical on HEAD without this change.
Bug found while testing: first packet of every capture was lost (fixed).
Follow-up fixes: regression tests for AddPackets protocol, GetDevice NULLs, UpdatePacket VLAN/flow, 0x9100 QinQ. `go test ./...` is green except 5 pre-existing `iec62443` tests.
Not covered: real-world captures with VLAN tags.
