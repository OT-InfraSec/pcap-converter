# EM: cdp-data
Tasks (each <= half day, in order):
1. Model: CDPNeighbor, SubnetKindAdvertised (+ Validate), fingerprint helper, tests.
2. Repository: cdp_neighbors table + unique index, UpsertCDPNeighbors/GetCDPNeighbors, interface, mocks (testutil, internal/dns), docs/db_schema.md (diagram + prose), tests.
3. CDPManager (key, widen, cap) + tests.
4. Extractors (neighbor + prefixes), sanitization, tests + fuzz.
5. Parser wiring (CDP info layer -> manager and subnetManager) + end-to-end tests with synthesized CDP frames.
6. Full go test/vet, state files.
