# SRE: vlan-data
No service or SLO impact. Runtime cost: one extra set insert per IP packet and a longer flow key string. Failure signal: opening an old DB returns "database schema is outdated ... re-import". 
