# Architect: cdp-data
See ADR-004 and specs/2026-10-20-cdp-data-design.md. Flow: parser reads LayerTypeCiscoDiscoveryInfo -> pure extractors -> CDPManager (in memory, capped) -> UpsertCDPNeighbors + Observe(prefix, cdp, advertised) at end of ParseFile. Identity via value fingerprint.
