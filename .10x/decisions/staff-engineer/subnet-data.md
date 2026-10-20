# Staff Engineer: subnet-data
Mirror FlowManager/DeviceManager (interface + Default impl + testutil mock). Use net/netip for canonical CIDR. Grep every repository Add/Upsert/Get path when adding the table. Extractors are pure functions over option bytes so they are unit-testable; bounds-check all lengths.
