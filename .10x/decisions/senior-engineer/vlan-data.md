# Senior Engineer: vlan-data approach
Files: lib/model/packet.go, lib/model/vlan_set.go, internal/repository/sqlite_repository.go, internal/parser/{flow_manager,device_manager,gopacket_parser}.go, internal/testutil/mock_{flow,device}_manager.go. Tricky: gopacket QinQ decoding (0x88a8), packet->flow linking, all UpsertDevice callers in parser.
