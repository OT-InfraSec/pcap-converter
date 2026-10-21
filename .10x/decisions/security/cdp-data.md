# Security: cdp-data
Review: reviews/2026-10-21-cdp-security-review.md. Result: pass after fix.
- High: hostile CDP frame aborted the import. Fixed by re-enabling gopacket decode recovery in `ParseFile` (was `SkipDecodeRecovery = true`); regression-tested; measured no cost.
- Strings sanitized and bounded, row cap 100,000, filter whitelist, fingerprint validated.
- Accepted: spoofed CDP is evidence at face value; `advertised` kind does not over-claim.
