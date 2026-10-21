# QA report: cdp-data (cycle 3)

Date: 2026-10-21. Scope: `cdp_neighbors` table, `CDPManager`, CDP extractors, tagged-CDP fallback, `advertised` subnets, parser wiring.

## Result: pass
`go test ./...` green except the 5 `internal/iec62443` tests that fail without this work (unchanged). `go vet` clean. `go test -race` clean on parser, repository and model.

## What was verified
| Area | Tests |
|---|---|
| Model | fingerprint stable, changes with every advertised value, ignores identity and times, length-prefix ambiguity; `Validate` (MAC, VLAN ranges, fingerprint mismatch); `VLANFromWire` 0 / 1 / 4094 / 4095 / 65535; `advertised` kind valid |
| Extractors | full frame, VLAN bounds (native and management), capability tokens (all flags, either bridge flag), anonymous frames skipped, address list (malformed length dropped, v4-in-v6 unmapped, canonical IPv6), string sanitizing (control characters, invalid UTF-8, 255-byte cut on a character boundary), prefixes (bounds, loopback, link-local, multicast, unspecified, non-contiguous mask, malformed address) |
| CDPManager | repeat collapses and widens, key parts (native VLAN change, port ID, tagged vs untagged, MAC), input copied, invalid ignored, 100k cap still widens known rows, Clear |
| Repository | round trip with NULL VLAN / native / management, `IS NULL` filters, widening across zones, changed value = new row, port and VLAN in key, tenant isolation, tampered fingerprint and missing MAC rejected, unknown filter keys rejected |
| End to end (hand-built 802.3/LLC/SNAP frames) | untagged, repeat widens range, VLAN 30 tagged, changed native VLAN, second interface, 4095 stored as NULL, QinQ uses outer tag, anonymous / truncated / hostile frames, capture without CDP gives no rows, `cdp`/`advertised` subnets per frame VLAN |
| Fuzz | `FuzzCDPEvidence` 20 s (about 2.4M executions): no panic, strings bounded and clean, prefixes valid, neighbor passes `Validate` |

Coverage: parser 59.9%, repository 47.6%, model 58.5% of the whole packages (new files are covered by the tables above).

## Bugs and gaps found (all fixed)
1. **Tagged CDP was never decoded** (gopacket stops at an 802.1Q tag holding a length): `vlan_id` would always have been NULL. Fixed by `cdpInfoFromPacket` (phase 4).
2. **Untagged hostile CDP aborted the whole import** (prefix length above 32: nil dereference; address length beyond the TLV: slice bounds). Pre-existing `SkipDecodeRecovery = true`. Fixed by re-enabling recovery; regression test `TestIntegration_HostileUntaggedCDPDoesNotAbortImport`. Measured cost on 50,000 frames: none.

## Residual risks and notes
- Spoofed CDP is accepted as evidence (provenance stays in the table and in `source`).
- A hostile capture can still create up to 100,000 neighbor rows before the cap; each is bounded to roughly 2 KB of strings plus addresses.
- Frames that gopacket cannot decode are skipped silently; a real device with unusual TLVs may be missed (not observed).
- No test against a real-world CDP capture; frames are synthesized to the CDP TLV layout. A real capture should be tried once.
- Visualizer must pick the row with the latest `last_seen` per interface and handle a prefix appearing from several sources.
