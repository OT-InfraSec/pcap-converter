# Architect: subnet-data
See ADR-002 and specs/2026-10-20-subnet-data-design.md. Flow: parser extractors -> SubnetManager (in memory) -> UpsertSubnets at end of ParseFile. Failure modes: malformed options dropped with debug log; no evidence = no row.

Amended by ADR-003: `kind` column (on-link | delegated) part of the row key; DHCPv6 relay-wrapped Replies unwrapped.
