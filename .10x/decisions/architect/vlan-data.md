# Architect: vlan-data
See ADR-001 and specs/2026-10-20-vlan-data-design.md. Flow: parser (Dot1Q layers) -> FlowManager/DeviceManager (VLAN param) -> repository (nullable columns, devices.vlans). Failure mode: malformed tag -> treated as untagged, debug log.
