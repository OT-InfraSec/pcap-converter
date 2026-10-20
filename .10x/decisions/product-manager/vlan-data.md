# PM: vlan-data
- Scope: R1, R2, R3, R5 (see specs/2026-10-20-vlan-data-requirements.md). Subnets (R4) and CDP deferred.
- Success: visualizer can tell tagged vs untagged captures; flows split per VLAN; devices list VLAN set; old DBs detectable via user_version.
- Confirmed by user: VID 0 -> NULL; device VLAN token format `untagged,100,100.200`; outdated-DB guard kept.
