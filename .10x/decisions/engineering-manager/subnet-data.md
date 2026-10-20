# EM: subnet-data
Tasks (each <= half day, in order):
1. Model: lib/model Subnet + canonical CIDR helper, tests.
2. Repository: subnets table in createTables, UpsertSubnets/GetSubnets, interface, mock, docs/db_schema.md, tests (NULL vlan, widen seen, IS NULL filter).
3. SubnetManager (interface, default impl, mock) with unit tests.
4. DHCPv4 extractor (mask, offer, router validation) + wiring in parser + tests.
5. RA extractor + wiring (replace TODO at ICMPv6 block) + tests.
6. DHCPv6 IA_PD extractor + wiring + tests.
7. Write at end of ParseFile; end-to-end parser test with VLANs; full go test/vet.
