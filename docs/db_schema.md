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
   bytea payload
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
dns_queries  -->  tenants : tenant_id:id
dns_queries  -->  devices : querying_device_id:id
dns_queries  -->  devices : answering_device_id:id
ssdp_queries  -->  tenants : tenant_id:id
ssdp_queries  -->  devices : querying_device_id:id
industrial_devices  -->  tenants : tenant_id:id
protocol_usage_stats  -->  tenants : tenant_id:id
communication_patterns  -->  tenants : tenant_id:id
