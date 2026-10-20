# Security: vlan-data
- Untrusted input: VLAN IDs come from pcap bytes as uint16; stored as integers via parameterized SQL (no string-built SQL with VLAN values; filter keys in GetFlows remain internal constants).
- Tokens in `devices.vlans` are generated from integers, not packet strings.
- No new auth surface, secrets or network exposure. Outdated-DB guard only reads PRAGMA/sqlite_master.
- Risk: none identified. Pre-existing: `GetFlows`/`GetDevices` concatenate filter keys into SQL (callers must not pass user-controlled keys).
