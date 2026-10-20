package parser

import (
	"fmt"
	"net/netip"
	"sort"
	"time"

	model "github.com/InfraSecConsult/pcap-importer-go/lib/model"
)

// SubnetManager collects subnet evidence in memory during parsing. Writing is
// deferred to the end of ParseFile to avoid concurrent SQLite writes.
type SubnetManager interface {
	// Observe records evidence for a prefix seen in the VLAN's outer tag.
	Observe(prefix netip.Prefix, vlan model.VLANTag, source string, timestamp time.Time)

	// GetAllSubnets returns all collected subnets in a stable order.
	GetAllSubnets() []*model.Subnet

	// Clear removes all collected subnets.
	Clear()
}

// DefaultSubnetManager implements SubnetManager.
type DefaultSubnetManager struct {
	subnets  map[string]*model.Subnet
	tenantID string
}

// NewDefaultSubnetManager creates a new subnet manager.
func NewDefaultSubnetManager(tenantID string) *DefaultSubnetManager {
	return &DefaultSubnetManager{subnets: make(map[string]*model.Subnet), tenantID: tenantID}
}

// Observe records evidence. The key is prefix + outer VLAN + source: the inner
// QinQ tag is not part of a subnet's identity, and each source stays visible.
func (sm *DefaultSubnetManager) Observe(prefix netip.Prefix, vlan model.VLANTag, source string, timestamp time.Time) {
	if !prefix.IsValid() {
		return
	}
	cidr := model.CanonicalCIDR(prefix)
	key := fmt.Sprintf("%s|%s|%s", cidr, vlanKeyPart(vlan.Outer), source)

	if existing, ok := sm.subnets[key]; ok {
		if timestamp.Before(existing.FirstSeen) {
			existing.FirstSeen = timestamp
		}
		if timestamp.After(existing.LastSeen) {
			existing.LastSeen = timestamp
		}
		return
	}

	var outer *int
	if vlan.Outer != nil {
		v := *vlan.Outer // copy: callers reuse their tag
		outer = &v
	}
	sm.subnets[key] = &model.Subnet{
		TenantID:  sm.tenantID,
		CIDR:      cidr,
		VlanID:    outer,
		Source:    source,
		FirstSeen: timestamp,
		LastSeen:  timestamp,
	}
}

func vlanKeyPart(outer *int) string {
	if outer == nil {
		return "untagged"
	}
	return fmt.Sprint(*outer)
}

// GetAllSubnets returns all collected subnets sorted by key for stable output.
func (sm *DefaultSubnetManager) GetAllSubnets() []*model.Subnet {
	keys := make([]string, 0, len(sm.subnets))
	for k := range sm.subnets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]*model.Subnet, 0, len(keys))
	for _, k := range keys {
		out = append(out, sm.subnets[k])
	}
	return out
}

// Clear removes all collected subnets.
func (sm *DefaultSubnetManager) Clear() {
	sm.subnets = make(map[string]*model.Subnet)
}
