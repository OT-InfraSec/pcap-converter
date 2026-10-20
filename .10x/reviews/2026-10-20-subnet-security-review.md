# Security review: subnet-data (cycle 2)

Date: 2026-10-20. Scope: new code that parses untrusted packet bytes or builds SQL.

## Verdict: no open findings
| # | Area | Finding | Status |
|---|---|---|---|
| 1 | DHCPv4 option parsing | Lengths checked before use (mask exactly 4 bytes, router tail < 4 bytes ignored); mask validated contiguous, /1../31; offered address must be non-zero IPv4 | OK, table tests + fuzz |
| 2 | RA Prefix Information | Option size >= 30 bytes required, prefix length 1..128, link-local skipped; gopacket already rejects options with zero or overlong length | OK, table tests + fuzz |
| 3 | DHCPv6 IA_PD | Header and every sub-option length bounds-checked (a sub-option claiming more bytes than present stops the loop), prefix length 1..128 | OK, table tests + fuzz |
| 4 | DHCPv6 relay recursion | Nested Relay-Reply could recurse without bound; depth limited to 8 (RFC 8415), inner decode errors dropped | Fixed, tested |
| 5 | Memory exhaustion | A crafted capture could create millions of distinct prefixes and grow the in-memory map and database | Fixed: cap of 100,000 distinct subnets, warning logged once |
| 6 | SQL | All values are bound parameters. Filter keys are concatenated into SQL, so `GetSubnets` whitelists `cidr`, `vlan_id`, `source`, `kind` and rejects anything else (tested with an injection-style key) | OK |
| 7 | Data integrity | `UpsertSubnets` validates CIDR canonical form, kind and source before writing and runs in one transaction | OK |
| 8 | Panics | No panics in about 9M fuzz executions across the three decoders; extractors return no evidence instead of errors | OK |
| 9 | Evidence trust | Spoofed RA or DHCP replies in a capture create subnet rows. This is inherent to passive analysis; provenance is kept in `source` and `kind` | Accepted, documented |
| 10 | Secrets / auth | None involved; no network or file I/O added | n/a |

## Notes for the visualizer
Treat `delegated` rows as not necessarily on-link, and do not present any row as proof that a network exists beyond "evidence was observed".
