# Cycle 1 design: VLAN data (R1, R2, R3, R5)

Requirements: [vlan-data-requirements](2026-10-20-vlan-data-requirements.md). Status: **draft, awaiting user review**.
Constraint: breaking schema changes are allowed, no migrations, databases are regenerated.

## Approach
Carry VLAN as first-class data through the existing pipeline (parser -> managers -> repository) with the smallest change per layer. No new tables.

| Layer | Change |
|---|---|
| `lib/model` | `Packet` and `Flow` get `VlanID *int` and `VlanInnerID *int` (nil = untagged / no QinQ). `Device` gets `VLANSet` (new type, mirrors `MACAddressSet`). |
| Parser | Read `layers.Dot1Q` layers per packet: first = outer, second (QinQ) = inner. Pass VLAN to flow manager, device manager and the packet record. |
| `FlowManager` | `UpdateFlow` takes the VLAN pair; the flow key becomes `src:dst:protocol:vlan:inner`. Same traffic in two VLANs gives two flows. |
| `DeviceManager` | `UpsertDevice` takes the VLAN pair and adds it to the device's `VLANSet`. A device is never split or collapsed by VLAN (one row per IP, as today). |
| Repository | New nullable columns `packets.vlan_id`, `packets.vlan_inner_id`, `flows.vlan_id`, `flows.vlan_inner_id`, and `devices.vlans TEXT`. Upsert/select code and `docs/db_schema.md` updated. |

## Details and decisions
1. **NULL for untagged (R1/R2).** Never store 1 for untagged. Inner ID is NULL unless QinQ is present.
2. **VLAN ID 0 (priority-tagged frame)** is treated as untagged (NULL), since it carries no VLAN membership. *Assumption, please confirm.*
3. **Device VLAN set encoding (R3).** Comma-joined text like `mac_addresses`, sorted for stable output. Tokens: `untagged`, `100` (outer only), `100.200` (outer.inner). Example: `untagged,100,100.200`. This string format is the contract with the visualizer. *Please confirm it works for the visualizer.*
4. **Flow key.** The current key is `src:dst:protocol` (ports are not part of it), so adding VLAN to it is the minimal change. The canonicalizer (`lib/helper/flow_canonicalizer.go`) is not affected; VLAN is added after canonicalization.
5. **Packet to flow linking** (recent commit 629e6d2) must keep working with the longer key. Verify during implementation.
6. **Schema marker (R5).** `createTables` sets `PRAGMA user_version = 1`. Small guard: if an existing database has `user_version = 0` but already contains a `packets` table, `NewSQLiteRepository` returns a clear "outdated schema, delete and re-import" error. Without it an old database would be marked v1 while lacking the columns.
7. **Interface churn.** `FlowManager`, `DeviceManager`, `internal/testutil` mocks and their tests change signatures. Acceptable (breaking changes allowed).
8. **Indexes.** Add `idx_flows_vlan(vlan_id, vlan_inner_id)` only; skip packet/device indexes (YAGNI).

## Error handling
Parsing never fails on VLAN content. A malformed or truncated tag falls back to untagged for that packet and logs at debug level.

## Testing
- Synthesized packets (gopacket serialization): untagged, single 802.1Q, QinQ (0x88a8), VID 0.
- Parser integration: the same 5-tuple in VLAN 10 and 20 produces two flows; one IP seen in VLANs 10 and 20 plus untagged yields one device with `untagged,10,20`.
- Repository tests: new columns round-trip including NULL; `user_version == 1`; guard error on an old-schema database.
- Manager unit tests updated for new signatures; existing integration tests stay green.

## Out of scope
Subnets (cycle 2), CDP/NativeVLAN and the "map untagged traffic to a VLAN" feature (cycle 3), any data migration.
