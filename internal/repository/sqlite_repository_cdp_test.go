package repository

import (
	"testing"
	"time"

	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func cdpAt(tenant, mac, port string, vlan, native *int, device string, first, last time.Time) *model.CDPNeighbor {
	n := &model.CDPNeighbor{
		TenantID: tenant, SrcMAC: mac, PortID: port, VlanID: vlan, DeviceID: device, NativeVLAN: native,
		Capabilities: "router,switch", Addresses: "10.0.0.1,2001:db8::1", FirstSeen: first, LastSeen: last,
	}
	n.Fingerprint = n.ComputeFingerprint()
	return n
}

func TestSQLiteRepository_CDPRoundTripAndNulls(t *testing.T) {
	repo := newVLANTestRepo(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	full := cdpAt("t1", "aa:aa:aa:aa:aa:01", "Gi1/0/1", vlanPtr(10), vlanPtr(20), "sw1", now, now)
	full.ManagementVLAN, full.SoftwareVersion, full.MgmtAddresses = vlanPtr(99), "IOS 15", "10.0.0.2"
	full.Fingerprint = full.ComputeFingerprint()

	require.NoError(t, repo.UpsertCDPNeighbors([]*model.CDPNeighbor{
		full,
		cdpAt("t1", "aa:aa:aa:aa:aa:02", "Gi1/0/2", nil, nil, "sw2", now, now),
	}))

	all, err := repo.GetCDPNeighbors("t1", nil)
	require.NoError(t, err)
	require.Len(t, all, 2)
	assert.Equal(t, full.Fingerprint, all[0].Fingerprint)
	require.NotNil(t, all[0].VlanID)
	assert.Equal(t, 10, *all[0].VlanID)
	assert.Equal(t, 20, *all[0].NativeVLAN)
	assert.Equal(t, 99, *all[0].ManagementVLAN)
	assert.Equal(t, "IOS 15", all[0].SoftwareVersion)
	assert.Equal(t, "router,switch", all[0].Capabilities)
	assert.Equal(t, "10.0.0.2", all[0].MgmtAddresses)
	assert.True(t, all[0].FirstSeen.Equal(now))

	assert.Nil(t, all[1].VlanID, "untagged must be NULL")
	assert.Nil(t, all[1].NativeVLAN)
	assert.Nil(t, all[1].ManagementVLAN)

	untagged, err := repo.GetCDPNeighbors("t1", map[string]interface{}{"vlan_id": nil})
	require.NoError(t, err)
	require.Len(t, untagged, 1)
	assert.Equal(t, "sw2", untagged[0].DeviceID)

	noNative, err := repo.GetCDPNeighbors("t1", map[string]interface{}{"native_vlan": nil})
	require.NoError(t, err)
	assert.Len(t, noNative, 1)

	byMAC, err := repo.GetCDPNeighbors("t1", map[string]interface{}{"src_mac": "aa:aa:aa:aa:aa:01"})
	require.NoError(t, err)
	assert.Len(t, byMAC, 1)
}

func TestSQLiteRepository_CDPUpsertWidensAndChangedValueIsNewRow(t *testing.T) {
	repo := newVLANTestRepo(t)
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	require.NoError(t, repo.UpsertCDPNeighbors([]*model.CDPNeighbor{
		cdpAt("t1", "m1", "p1", nil, vlanPtr(10), "sw", base, base),
	}))
	// re-import: same advertisement earlier and later, in another zone; for untagged too (NULL key)
	require.NoError(t, repo.UpsertCDPNeighbors([]*model.CDPNeighbor{
		cdpAt("t1", "m1", "p1", nil, vlanPtr(10), "sw", base.Add(-time.Hour).In(time.FixedZone("x", 3600)), base.Add(time.Hour)),
	}))
	// reconfigured native VLAN
	require.NoError(t, repo.UpsertCDPNeighbors([]*model.CDPNeighbor{
		cdpAt("t1", "m1", "p1", nil, vlanPtr(30), "sw", base.Add(2*time.Hour), base.Add(2*time.Hour)),
	}))

	all, err := repo.GetCDPNeighbors("t1", nil)
	require.NoError(t, err)
	require.Len(t, all, 2)
	assert.Equal(t, 10, *all[0].NativeVLAN)
	assert.True(t, all[0].FirstSeen.Equal(base.Add(-time.Hour)))
	assert.True(t, all[0].LastSeen.Equal(base.Add(time.Hour)))
	assert.Equal(t, 30, *all[1].NativeVLAN)
}

func TestSQLiteRepository_CDPPortAndVLANAreKey(t *testing.T) {
	repo := newVLANTestRepo(t)
	now := time.Now()
	require.NoError(t, repo.UpsertCDPNeighbors([]*model.CDPNeighbor{
		cdpAt("t1", "m1", "p1", nil, nil, "sw", now, now),
		cdpAt("t1", "m1", "p2", nil, nil, "sw", now, now),
		cdpAt("t1", "m1", "p1", vlanPtr(10), nil, "sw", now, now),
	}))
	all, err := repo.GetCDPNeighbors("t1", nil)
	require.NoError(t, err)
	assert.Len(t, all, 3)
}

func TestSQLiteRepository_CDPTenantIsolation(t *testing.T) {
	repo := newVLANTestRepo(t)
	now := time.Now()
	require.NoError(t, repo.UpsertCDPNeighbors([]*model.CDPNeighbor{
		cdpAt("t1", "m1", "p1", nil, nil, "sw", now, now),
		cdpAt("t2", "m1", "p1", nil, nil, "sw", now, now),
	}))
	for _, tenant := range []string{"t1", "t2"} {
		got, err := repo.GetCDPNeighbors(tenant, nil)
		require.NoError(t, err)
		assert.Len(t, got, 1)
	}
}

func TestSQLiteRepository_CDPRejectsInvalidAndUnknownFilter(t *testing.T) {
	repo := newVLANTestRepo(t)
	now := time.Now()
	bad := cdpAt("t1", "m1", "p1", nil, nil, "sw", now, now)
	bad.DeviceID = "tampered"
	assert.Error(t, repo.UpsertCDPNeighbors([]*model.CDPNeighbor{bad}), "fingerprint mismatch")
	assert.Error(t, repo.UpsertCDPNeighbors([]*model.CDPNeighbor{{TenantID: "t1"}}), "no MAC")

	_, err := repo.GetCDPNeighbors("t1", map[string]interface{}{"1=1; DROP TABLE cdp_neighbors; --": "x"})
	assert.Error(t, err)
}
