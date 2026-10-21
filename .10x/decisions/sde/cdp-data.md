# SDE: cdp-data (built)
Tasks 1-6 of decisions/engineering-manager/cdp-data.md, tests alongside.
- `lib/model/cdp.go`: `CDPNeighbor`, `VLANFromWire` (0 or > 4094 -> nil), `ComputeFingerprint` (SHA-256 over length-prefixed advertised values, not identity or timestamps), `Validate` (MAC set, VLANs 1..4094, fingerprint matches). `SubnetKindAdvertised` added to `subnet.go` and `Subnet.Validate`.
- Repository: `cdp_neighbors` table, NULL-safe unique index `(tenant_id, src_mac, port_id, COALESCE(vlan_id,-1), fingerprint)`, `UpsertCDPNeighbors` / `GetCDPNeighbors` (same pattern as subnets, filter keys whitelisted). Interface, `testutil.MockRepository`, `internal/dns` test mock, `docs/db_schema.md` (diagram + prose) updated.
- Parser: `CDPManager` (`cdp_manager.go`, key = MAC + port ID + outer VLAN + fingerprint, copies input, cap 100,000, widens known rows past the cap). Pure extractors in `cdp_evidence.go`: `cdpNeighborFromInfo`, `cdpPrefixes`, `sanitizeCDPString`, `cdpCapabilityTokens`, `cdpAddressList`. Wired right after the Ethernet block; one batched `UpsertCDPNeighbors` at the end of `ParseFile`; prefixes go to `subnetManager` as `cdp`/`advertised`.
- Tests: model, repository (NULLs, widen, changed value, port/VLAN key, tenant isolation, invalid input, filter whitelist), manager, extractor tables, fuzz (`FuzzCDPEvidence`, 20 s clean), end to end with hand-built 802.3/LLC/SNAP CDP frames (untagged, tagged, QinQ, anonymous, truncated, hostile).
## Deviations from the design
- **Tagged CDP needed a fallback.** gopacket does not decode LLC behind an 802.1Q tag whose type field is a length, so tagged CDP frames produced no info layer. `cdpInfoFromPacket` decodes the tag's payload itself (only when it starts with LLC/SNAP 00000c/2000) with gopacket's recovery enabled. Without it `vlan_id` would always be NULL.
- `CDPNeighbor` stores `Capabilities`, `Addresses`, `MgmtAddresses` as comma-joined strings, as in the table (no split/join in the repository).
- `Validate` also checks the fingerprint, so the repository rejects rows whose values were altered after sealing.
- Prefix length bounds are 1..32 for IPv4 (a /32 is kept; RA allows /128 the same way). DHCPv4 still rejects /32 as before.
- Frames with a decode error (`packet.ErrorLayer() != nil`) are skipped.
## Tech debt / findings
- Crash on hostile untagged CDP: found in phase 4, fixed in phase 5 by re-enabling decode recovery (see reviews/2026-10-21-cdp-security-review.md).
- The 5 failing `internal/iec62443` tests predate this work.
- CDP over IPv6 addresses depends on gopacket's `decodeAddresses`; only IPv4 and IPv6 address entries are read.
