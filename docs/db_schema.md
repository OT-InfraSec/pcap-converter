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
   integer packet_count
   bigint byte_count
   timestamp first_seen
   timestamp last_seen
   numeric(10,6) duration
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
