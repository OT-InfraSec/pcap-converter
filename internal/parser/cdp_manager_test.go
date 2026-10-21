package parser

import (
	"fmt"
	"testing"
	"time"

	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func cdpN(mac, port string, vlan, native *int) *model.CDPNeighbor {
	return &model.CDPNeighbor{SrcMAC: mac, PortID: port, VlanID: vlan, NativeVLAN: native, DeviceID: "sw"}
}

func TestCDPManager_RepeatCollapsesAndWidens(t *testing.T) {
	cm := NewDefaultCDPManager("t1")
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	n := cdpN("m1", "p1", nil, nil)

	cm.Observe(n, base)
	cm.Observe(n, base.Add(time.Hour))
	cm.Observe(n, base.Add(-time.Hour))

	all := cm.GetAllNeighbors()
	require.Len(t, all, 1)
	assert.Equal(t, "t1", all[0].TenantID)
	assert.NotEmpty(t, all[0].Fingerprint)
	assert.NoError(t, all[0].Validate())
	assert.True(t, all[0].FirstSeen.Equal(base.Add(-time.Hour)))
	assert.True(t, all[0].LastSeen.Equal(base.Add(time.Hour)))
}

func TestCDPManager_KeyParts(t *testing.T) {
	cm := NewDefaultCDPManager("t1")
	now := time.Now()
	v10, n10, n20 := 10, 10, 20

	cm.Observe(cdpN("m1", "p1", nil, &n10), now)
	cm.Observe(cdpN("m1", "p1", nil, &n20), now)  // native VLAN reconfigured
	cm.Observe(cdpN("m1", "p2", nil, &n10), now)  // other port ID, same MAC
	cm.Observe(cdpN("m1", "p1", &v10, &n10), now) // seen tagged
	cm.Observe(cdpN("m2", "p1", nil, &n10), now)  // other MAC

	assert.Len(t, cm.GetAllNeighbors(), 5)
}

func TestCDPManager_CopiesInput(t *testing.T) {
	cm := NewDefaultCDPManager("t1")
	v := 10
	n := cdpN("m1", "p1", &v, nil)
	cm.Observe(n, time.Now())
	v = 99
	n.DeviceID = "changed"
	got := cm.GetAllNeighbors()[0]
	assert.Equal(t, 10, *got.VlanID)
	assert.Equal(t, "sw", got.DeviceID)
}

func TestCDPManager_IgnoresInvalid(t *testing.T) {
	cm := NewDefaultCDPManager("t1")
	cm.Observe(nil, time.Now())
	cm.Observe(&model.CDPNeighbor{}, time.Now())
	assert.Empty(t, cm.GetAllNeighbors())
}

func TestCDPManager_CapStopsNewButWidensKnown(t *testing.T) {
	cm := NewDefaultCDPManager("t1")
	base := time.Now()
	for i := 0; i < maxCDPNeighbors; i++ {
		n := cdpN("m", "p", nil, nil)
		n.DeviceID = fmt.Sprint("d", i)
		cm.Observe(n, base)
	}
	require.Len(t, cm.GetAllNeighbors(), maxCDPNeighbors)

	extra := cdpN("m", "p", nil, nil)
	extra.DeviceID = "extra"
	cm.Observe(extra, base)
	assert.Len(t, cm.GetAllNeighbors(), maxCDPNeighbors)

	known := cdpN("m", "p", nil, nil)
	known.DeviceID = "d0"
	cm.Observe(known, base.Add(time.Hour))
	found := false
	for _, n := range cm.GetAllNeighbors() {
		if n.DeviceID == known.DeviceID {
			found = true
			assert.True(t, n.LastSeen.Equal(base.Add(time.Hour)))
		}
	}
	assert.True(t, found)

	cm.Clear()
	assert.Empty(t, cm.GetAllNeighbors())
}
