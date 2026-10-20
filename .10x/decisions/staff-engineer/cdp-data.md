# Staff Engineer: cdp-data
Mirror SubnetManager/DefaultSubnetManager and the subnet repository file layout (own file, whitelisted filter keys, explicit NULL handling via IS ?). Extractors are pure over *layers.CiscoDiscoveryInfo; sanitize strings; reuse model.CanonicalCIDR and the cycle 2 prefix bounds.
