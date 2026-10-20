# DBA: vlan-data
- Columns: `packets.vlan_id`, `packets.vlan_inner_id`, `flows.vlan_id`, `flows.vlan_inner_id` INTEGER NULL; `devices.vlans` TEXT (sorted comma-joined tokens).
- Index: `idx_flows_vlan(vlan_id, vlan_inner_id)`. No packet/device index (YAGNI).
- No migration: `createTables` edited in place; `PRAGMA user_version = 1`; version 0 + existing `packets` table is rejected.
- NULL semantics: always compare with `IS` / `IS NULL` (SQLite `=` never matches NULL).
