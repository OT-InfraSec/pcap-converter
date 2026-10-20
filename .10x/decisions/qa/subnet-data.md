# QA: subnet-data
Pass. See reviews/2026-10-20-subnet-qa-report.md. Table tests for all extractors including malformed input, manager, repository, synthesized-pcap end-to-end (VLAN, relay), 3 fuzz targets (about 9M execs). Found and fixed: relay unwrapping, schema diagram, delegated vs on-link (ADR-003), unbounded map (cap 100k). Known unrelated failures: 5 `iec62443` tests.
