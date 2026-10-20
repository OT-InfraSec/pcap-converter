package parser

import (
	"fmt"
	"sort"
	"time"

	model "github.com/InfraSecConsult/pcap-importer-go/lib/model"
	"github.com/rs/zerolog/log"
)

// maxCDPNeighbors bounds memory: a hostile capture can vary one advertised value
// per frame and create a distinct row each time. Real networks have far fewer.
const maxCDPNeighbors = 100000

// CDPManager collects CDP neighbors in memory during parsing. Writing is deferred
// to the end of ParseFile to avoid concurrent SQLite writes.
type CDPManager interface {
	// Observe records an advertisement. The neighbor's tenant, fingerprint and time range
	// are set by the manager; the caller fills the identity and advertised fields.
	Observe(neighbor *model.CDPNeighbor, timestamp time.Time)

	// GetAllNeighbors returns all collected neighbors in a stable order.
	GetAllNeighbors() []*model.CDPNeighbor

	// Clear removes all collected neighbors.
	Clear()
}

// DefaultCDPManager implements CDPManager.
type DefaultCDPManager struct {
	neighbors map[string]*model.CDPNeighbor
	tenantID  string
	capped    bool // true once the limit was hit and logged
}

// NewDefaultCDPManager creates a new CDP manager.
func NewDefaultCDPManager(tenantID string) *DefaultCDPManager {
	return &DefaultCDPManager{neighbors: make(map[string]*model.CDPNeighbor), tenantID: tenantID}
}

// Observe stores a copy of the neighbor. The key matches the table's unique index:
// interface (MAC + port ID), outer VLAN and the fingerprint of the advertised values.
func (cm *DefaultCDPManager) Observe(neighbor *model.CDPNeighbor, timestamp time.Time) {
	if neighbor == nil || neighbor.SrcMAC == "" {
		return
	}
	n := *neighbor // copy: callers reuse their struct
	n.TenantID = cm.tenantID
	n.Fingerprint = n.ComputeFingerprint()
	n.ID = 0
	// a pointer shared with the caller must not change under us
	n.VlanID = copyIntPtr(neighbor.VlanID)
	n.NativeVLAN = copyIntPtr(neighbor.NativeVLAN)
	n.ManagementVLAN = copyIntPtr(neighbor.ManagementVLAN)

	key := fmt.Sprintf("%s|%s|%s|%s", n.SrcMAC, n.PortID, vlanKeyPart(n.VlanID), n.Fingerprint)

	if existing, ok := cm.neighbors[key]; ok {
		if timestamp.Before(existing.FirstSeen) {
			existing.FirstSeen = timestamp
		}
		if timestamp.After(existing.LastSeen) {
			existing.LastSeen = timestamp
		}
		return
	}

	if len(cm.neighbors) >= maxCDPNeighbors {
		if !cm.capped {
			cm.capped = true
			log.Warn().Int("limit", maxCDPNeighbors).Msg("CDP neighbor limit reached, ignoring further new neighbors")
		}
		return
	}

	n.FirstSeen, n.LastSeen = timestamp, timestamp
	cm.neighbors[key] = &n
}

func copyIntPtr(p *int) *int {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

// GetAllNeighbors returns all collected neighbors sorted by key for stable output.
func (cm *DefaultCDPManager) GetAllNeighbors() []*model.CDPNeighbor {
	keys := make([]string, 0, len(cm.neighbors))
	for k := range cm.neighbors {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]*model.CDPNeighbor, 0, len(keys))
	for _, k := range keys {
		out = append(out, cm.neighbors[k])
	}
	return out
}

// Clear removes all collected neighbors.
func (cm *DefaultCDPManager) Clear() {
	cm.neighbors = make(map[string]*model.CDPNeighbor)
	cm.capped = false
}
