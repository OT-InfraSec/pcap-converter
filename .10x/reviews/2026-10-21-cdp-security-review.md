# Security review: cdp-data (cycle 3)

Date: 2026-10-21. Scope: parsing of untrusted CDP frames, storage, SQL, resource use.

## Result: pass after one fix
| # | Finding | Severity | Status |
|---|---|---|---|
| 1 | One untagged CDP frame crashed the importer: gopacket's CDP decoder panics on a prefix length above 32 (nil dereference) or an address length beyond its TLV (slice bounds), and `ParseFile` ran with `SkipDecodeRecovery = true`. Anyone who can place a frame in a capture could abort an import (denial of service). Other gopacket decoders with unchecked slicing had the same exposure. | High | Fixed: recovery re-enabled in `ParseFile`; regression test with both frames; no measurable cost |
| 2 | Hostile strings (NUL, control characters, invalid UTF-8, very long values) could reach the database and the visualizer | Medium | Mitigated: `sanitizeCDPString` strips them and cuts at 255 bytes; fuzzed |
| 3 | Unbounded growth from frames that vary one value each | Medium | Mitigated: 100,000-row cap with one warning; known rows still widen |
| 4 | SQL injection through filter keys | Low | Mitigated: key whitelist, values bound as parameters, test with an injection string |
| 5 | Tampered or inconsistent rows | Low | `Validate` requires the fingerprint to match the values and VLANs in 1..4094 |
| 6 | Spoofed CDP produces false neighbors, native VLANs and `advertised` prefixes | Info | Accepted (passive analysis); provenance kept, `advertised` does not claim on-link |

## Checked and fine
- Extractors never index into raw bytes; they read gopacket's decoded fields only.
- The tagged-CDP fallback decodes with `gopacket.Default` (recovery on, copies data) and only for payloads starting with the Cisco LLC/SNAP header.
- Tenant ID is part of every key and query; isolation tested.
- No secrets, network access or file writes added.

## Open
- Other protocol layers in `lib/layers` were not audited; finding 1's fix covers their panics, but a skipped frame there loses its data silently.
