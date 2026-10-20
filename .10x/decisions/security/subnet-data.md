# Security: subnet-data
No open findings. See reviews/2026-10-20-subnet-security-review.md. Untrusted-byte decoders are bounds-checked and fuzzed; relay recursion limited to 8; subnet count capped at 100k; SQL filter keys whitelisted and values bound. Accepted risk: spoofed evidence in a capture produces rows (provenance kept in `source`/`kind`).
