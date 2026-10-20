# SDE: subnet-data (built)
Tasks 1-7 of decisions/engineering-manager/subnet-data.md, test first.
- `lib/model/subnet.go`: `Subnet`, source constants, `CanonicalCIDR`, `Validate` (canonical CIDR + known source).
- Repository: `subnets` table, NULL-safe unique index `COALESCE(vlan_id,-1)`, `UpsertSubnets` (one transaction, select-then-insert/update so first/last seen widen as times), `GetSubnets` (nil filter = `IS NULL`, filter keys whitelisted). Interface, `testutil.MockRepository`, `internal/dns` test mock updated.
- Parser: `SubnetManager` (key cidr+outer VLAN+source, copies the VLAN int), pure extractors in `subnet_evidence.go` (`dhcpv4SubnetEvidence`, `routerAdvertisementPrefixes`, `dhcpv6DelegatedPrefixes`), wired at the DHCPv4 reply, DHCPv6 and ICMPv6 blocks; one batched `UpsertSubnets` before protocol stats at the end of `ParseFile`.
- Tests: model, repository, manager, extractor tables (including malformed input), and end-to-end synthesized pcap (`gopacket_parser_subnet_test.go`).
## Deviations from the design
- No `SubnetManager` mock in testutil (nothing mocks it; YAGNI).
- DHCPv4 option parsing is a second pass over the options in the extractor, not folded into the existing `dhcpv4_server_info` loop (keeps the extractor pure and testable).
- DHCPv6 Advertise is not evidence; only Reply is.
## Tech debt
- `docs/db_schema.md` diagram (mermaid-like class list) was not extended with `subnets`; the prose section was.
- The 5 failing `internal/iec62443` tests predate this work (unchanged).
- DHCPv6 relay-wrapped messages (Relay-Reply) are not unwrapped, so prefixes only seen inside relay messages are missed.
