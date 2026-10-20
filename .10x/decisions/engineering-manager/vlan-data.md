# EM: vlan-data task breakdown
1. Model: VLAN fields on Packet/Flow, `VLANSet` type + tests.
2. Repository: schema columns, upsert/select, user_version + guard, tests.
3. Managers: FlowManager/DeviceManager signatures and logic, mocks, tests.
4. Parser: extract Dot1Q, wire through; synthesized-pcap integration tests.
5. Docs: docs/db_schema.md; full `go test ./...`, vet.
