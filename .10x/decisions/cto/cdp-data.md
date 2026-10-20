# CTO: cdp-data
Build on gopacket's existing CDP decoder; no new library. Scope: VLANs + identity + prefixes (user choice) since the layer already provides everything. Cost: one new table the visualizer must join.
