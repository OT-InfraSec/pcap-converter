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
## Follow-up after review (phase 5), all done
- DHCPv6 Relay-Reply messages are unwrapped (depth <= 8).
- `docs/db_schema.md` class diagram now lists `subnets`.
- `subnets.kind` (`on-link` | `delegated`) added per ADR-003; `Observe` takes a kind; kind is part of the key.
- `SubnetManager` capped at 100,000 distinct subnets (warning logged once).
## Tech debt
- The 5 failing `internal/iec62443` tests predate this work (unchanged, needs a product decision).
- Only the outermost relay message's inner Reply is considered; relay-forward messages are intentionally not evidence.
