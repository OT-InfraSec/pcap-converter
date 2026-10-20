# DBA: cdp-data
- Table `cdp_neighbors` (see docs/db_schema.md): `tenant_id, src_mac, port_id, vlan_id (NULL = untagged), device_id, platform, software_version, sys_name, capabilities, addresses, mgmt_addresses, native_vlan, management_vlan (NULL = unset), fingerprint, first_seen, last_seen`.
- Unique index `idx_cdp_neighbors_key (tenant_id, src_mac, port_id, COALESCE(vlan_id,-1), fingerprint)`; COALESCE because NULLs never collide in a UNIQUE index. Upsert looks up with `vlan_id IS ?`.
- Text columns are NOT NULL with empty string for "not advertised"; VLAN columns are nullable. Times are RFC3339Nano text, compared as parsed times when widening.
- No secondary index: the visualizer reads per tenant and filters on a handful of rows; add one on `(tenant_id, src_mac)` if that changes. No `user_version` bump; schema is regenerated.
