classDiagram
direction BT
class devices {
   varchar(255) tenant_id
   varchar(255) address
   varchar(50) address_type
   varchar(50) address_sub_type
   varchar(50) address_scope
   text mac_addresses
   text additional_data
   text protocol_list
   text dns_names
   varchar(255) hostname
   varchar(100) device_type
   varchar(255) vendor
   varchar(255) os
   timestamp first_seen
   timestamp last_seen
   boolean is_router
   boolean is_only_destination
   boolean is_external
   numeric(5,4) confidence
   text description
   text vlans
   integer id
}
class flows {
   varchar(255) tenant_id
   inet src_ip
   inet dst_ip
   integer src_port
   integer dst_port
   varchar(20) protocol
   integer packet_count_out
   bigint byte_count_out
   integer packet_count_in
   bigint byte_count_in
   timestamp first_seen
   timestamp last_seen
   integer duration
   integer id
   integer vlan_id
   integer vlan_inner_id
}
class kv_store {
   text key
   text value
   timestamp created_at
   timestamp updated_at
}
class packets {
   varchar(255) tenant_id
   integer flow_id
   timestamp timestamp
   inet src_ip
   inet dst_ip
   integer src_port
   integer dst_port
   varchar(20) protocol
   integer length
   varchar(50) flags
   varchar(255) payload_hash
   integer ttl
   varchar(255) capture_file
   integer vlan_id
   integer vlan_inner_id
   integer id
}
class schema_migrations {
   timestamp applied_at
   varchar(255) version
}
class sessions {
   varchar(255) tenant_id
   integer user_id
   varchar(255) username
   varchar(100) role
   timestamp created_at
   timestamp expires_at
   inet ip_address
   text user_agent
   boolean is_anonymous
   boolean is_upgraded
   varchar(255) id
}
class tenants {
   varchar(255) name
   varchar(255) domain
   boolean is_active
   timestamp created_at
   timestamp updated_at
   jsonb settings
   varchar(255) id
}
class users {
   varchar(255) tenant_id
   varchar(255) username
   varchar(255) password_hash
   varchar(255) email
   varchar(100) role
   timestamp created_at
   timestamp last_login
   boolean is_active
   integer id
}

devices  -->  tenants : tenant_id:id
flows  -->  tenants : tenant_id:id
packets  -->  flows : flow_id:id
packets  -->  tenants : tenant_id:id
sessions  -->  tenants : tenant_id:id
sessions  -->  users : user_id:id
users  -->  tenants : tenant_id:id
class services {
   varchar(255) tenant_id
   inet ip
   integer port
   timestamp first_seen
   timestamp last_seen
   varchar(50) protocol
   integer element_id
}
class subnets {
   varchar(255) tenant_id
   varchar(64) cidr
   integer vlan_id
   varchar(16) source
   varchar(16) kind
   timestamp first_seen
   timestamp last_seen
   integer id
}
class cdp_neighbors {
   varchar(255) tenant_id
   varchar(17) src_mac
   varchar(255) port_id
   integer vlan_id
   varchar(255) device_id
   varchar(255) platform
   varchar(255) software_version
   varchar(255) sys_name
   varchar(255) capabilities
   text addresses
   text mgmt_addresses
   integer native_vlan
   integer management_vlan
   char(64) fingerprint
   timestamp first_seen
   timestamp last_seen
   integer id
}
class dns_queries {
   varchar(255) tenant_id
   integer querying_device_id
   integer answering_device_id
   varchar(255) query_name
   varchar(50) query_type
   text query_result
   timestamp timestamp
   integer id
}
class ssdp_queries {
   varchar(255) tenant_id
   integer querying_device_id
   varchar(50) query_type
   varchar(255) st
   varchar(255) user_agent
   integer id
}
class industrial_devices {
   varchar(255) tenant_id
   varchar(255) device_address
   varchar(50) device_type
   varchar(50) role
   numeric(5,4) confidence
   text protocols
   integer security_level
   varchar(255) vendor
   varchar(255) product_name
   varchar(255) serial_number
   varchar(255) firmware_version
   timestamp last_seen
   timestamp created_at
   timestamp updated_at
   integer id
}
class protocol_usage_stats {
   varchar(255) tenant_id
   varchar(255) device_address
   varchar(50) protocol
   bigint packet_count
   bigint byte_count
   timestamp first_seen
   timestamp last_seen
   varchar(50) communication_role
   text ports_used
   integer id
}
class communication_patterns {
   varchar(255) tenant_id
   varchar(255) source_device_address
   varchar(255) destination_device_address
   varchar(50) protocol
   bigint frequency_ms
   bigint data_volume
   integer flow_count
   numeric(10,6) deviation_frequency
   numeric(10,6) deviation_data_volume
   varchar(50) pattern_type
   varchar(50) criticality
   timestamp created_at
   integer id
}

services  -->  tenants : tenant_id:id
subnets  -->  tenants : tenant_id:id
cdp_neighbors  -->  tenants : tenant_id:id
dns_queries  -->  tenants : tenant_id:id
dns_queries  -->  devices : querying_device_id:id
dns_queries  -->  devices : answering_device_id:id
ssdp_queries  -->  tenants : tenant_id:id
ssdp_queries  -->  devices : querying_device_id:id
industrial_devices  -->  tenants : tenant_id:id
protocol_usage_stats  -->  tenants : tenant_id:id
communication_patterns  -->  tenants : tenant_id:id

## VLAN columns and schema version

- `packets.vlan_id` / `packets.vlan_inner_id` and `flows.vlan_id` / `flows.vlan_inner_id`: outer 802.1Q VLAN ID and, for QinQ, the inner ID. **NULL means untagged** (never stored as 1). A priority-only tag (VID 0) counts as untagged.
- The VLAN pair is part of the flow key: the same 5-tuple in two VLANs is two `flows` rows.
- `devices.vlans`: sorted, comma-joined set of the VLANs the device was seen in, with the tokens `untagged`, `<outer>` (e.g. `100`) and `<outer>.<inner>` for QinQ (e.g. `100.200`). Example: `untagged,10,10.200`. A device seen in several VLANs stays one row.
- `PRAGMA user_version = 1` marks databases that contain this data. An older database (user_version 0 with existing tables) is rejected on open with a "delete the database and re-import" error; there are no migrations.

## Subnets

`subnets` holds one row per prefix observed per VLAN and evidence source: `tenant_id`, `cidr` (canonical masked prefix, e.g. `10.0.1.0/24`, `2001:db8:1::/64`), `vlan_id`, `source`, `kind`, `first_seen`, `last_seen`.

- `vlan_id` is the outer 802.1Q tag; **NULL means untagged** (same convention as above). The same prefix in two VLANs is two rows; the QinQ inner tag is not part of the identity.
- `source` and `kind` are part of the key, so a prefix seen via two mechanisms, or as both on-link and delegated, is two rows. Written values: `dhcp` (DHCPv4 and DHCPv6), `ra` (ICMPv6 Router Advertisement) and `cdp` (CDP IP Prefix TLV). Reserved, not written yet: `eigrp`, `ospf`, `inferred`.
- DHCPv4: client's offered address masked with option 1, only when a router (option 3) lies inside the prefix. RA: on-link (L flag) Prefix Information options, link-local excluded. DHCPv6: IA_PD prefixes from Replies, including Replies wrapped in (nested) Relay-Reply messages.
- `kind`: `on-link` (DHCPv4, RA), `delegated` (DHCPv6 IA_PD) or `advertised` (CDP: the neighbor claims to be connected to the prefix, e.g. a router listing the networks of its other interfaces; it is not proof the prefix is on-link in the capture VLAN). **A delegated prefix is handed to a router for downstream use and need not be on-link in the VLAN where it was seen**; the visualizer should not draw it as that VLAN's subnet without saying so.
- Uniqueness is `(tenant_id, cidr, COALESCE(vlan_id, -1), source, kind)`; re-imports widen `first_seen`/`last_seen`.
- Device membership is not stored: assign device IPs by longest-prefix match within the device's VLAN.
- No `user_version` bump (stays 1).

## CDP neighbors

`cdp_neighbors` holds one row per CDP advertisement of an interface, per VLAN and per set of advertised values. Frames are read from CDP info decoded by gopacket (SNAP 0x2000); no IP header exists, so the source MAC comes from Ethernet.

- Identity: `(tenant_id, src_mac, port_id, COALESCE(vlan_id, -1), fingerprint)`. A switch sends from a different MAC/port ID per port. `vlan_id` is the outer tag of the frame; **NULL means untagged**.
- `fingerprint` is the SHA-256 hex of all advertised values (device ID, platform, software version, sys name, capabilities, addresses, management addresses, native and management VLAN), not of timestamps. The same advertisement repeated only widens `first_seen`/`last_seen`; a changed value (e.g. native VLAN reconfigured) is a second row with its own range. **The visualizer should use the row with the latest `last_seen`.**
- `native_vlan`, `management_vlan`: NULL when not advertised, 0 or above 4094. The management VLAN comes from the optional cluster-management TLV and is usually unset.
- `capabilities`: sorted, comma-joined tokens `bridge`, `host`, `igmp`, `phone`, `remote-managed`, `repeater`, `router`, `switch` (empty if none). `addresses` and `mgmt_addresses`: comma-joined IPs in advertised order. The visualizer joins devices through these address lists; `devices` is not changed.
- Strings are truncated to 255 bytes and stripped of control characters. At most 100,000 distinct rows are stored per import (a warning is logged).
- CDP IP prefixes are also written to `subnets` with `source = cdp`, `kind = advertised`, VLAN of the frame.
- No `user_version` bump (stays 1).
