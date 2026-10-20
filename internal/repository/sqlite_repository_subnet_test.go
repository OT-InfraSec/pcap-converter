package repository

import (
	"testing"
	"time"

	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func subnetAt(cidr string, vlan *int, source string, first, last time.Time) *model.Subnet {
	return &model.Subnet{TenantID: "t1", CIDR: cidr, VlanID: vlan, Source: source, FirstSeen: first, LastSeen: last}
}

func TestSQLiteRepository_SubnetRoundTripAndNullVLAN(t *testing.T) {
	repo := newVLANTestRepo(t)
	now := time.Now().UTC().Truncate(time.Millisecond)

	require.NoError(t, repo.UpsertSubnets([]*model.Subnet{
		subnetAt("10.0.1.0/24", nil, model.SubnetSourceDHCP, now, now),
		subnetAt("10.0.1.0/24", vlanPtr(10), model.SubnetSourceDHCP, now, now),
		subnetAt("10.0.1.0/24", vlanPtr(20), model.SubnetSourceDHCP, now, now),
		subnetAt("2001:db8:1::/64", nil, model.SubnetSourceRA, now, now),
	}))

	all, err := repo.GetSubnets("t1", nil)
	require.NoError(t, err)
	require.Len(t, all, 4, "same prefix in untagged, VLAN 10 and VLAN 20 is three rows")

	untagged, err := repo.GetSubnets("t1", map[string]interface{}{"vlan_id": nil})
	require.NoError(t, err)
	require.Len(t, untagged, 2)
	for _, s := range untagged {
		assert.Nil(t, s.VlanID)
	}

	v10, err := repo.GetSubnets("t1", map[string]interface{}{"vlan_id": 10})
	require.NoError(t, err)
	require.Len(t, v10, 1)
	assert.Equal(t, 10, *v10[0].VlanID)
	assert.Equal(t, "10.0.1.0/24", v10[0].CIDR)
	assert.True(t, now.Equal(v10[0].FirstSeen))

	other, err := repo.GetSubnets("other-tenant", nil)
	require.NoError(t, err)
	assert.Empty(t, other)
}

func TestSQLiteRepository_UpsertSubnetsWidensTimeRange(t *testing.T) {
	repo := newVLANTestRepo(t)
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	for _, s := range []*model.Subnet{
		subnetAt("10.0.1.0/24", nil, model.SubnetSourceDHCP, base, base),
		subnetAt("10.0.1.0/24", nil, model.SubnetSourceDHCP, base.Add(time.Hour), base.Add(time.Hour)),
		subnetAt("10.0.1.0/24", nil, model.SubnetSourceDHCP, base.Add(-time.Hour), base.Add(-time.Hour)),
	} {
		require.NoError(t, repo.UpsertSubnets([]*model.Subnet{s}))
	}

	got, err := repo.GetSubnets("t1", nil)
	require.NoError(t, err)
	require.Len(t, got, 1, "NULL vlan_id must not defeat the uniqueness key")
	assert.True(t, got[0].FirstSeen.Equal(base.Add(-time.Hour)))
	assert.True(t, got[0].LastSeen.Equal(base.Add(time.Hour)))
}

func TestSQLiteRepository_SubnetSourceIsPartOfKey(t *testing.T) {
	repo := newVLANTestRepo(t)
	now := time.Now()
	require.NoError(t, repo.UpsertSubnets([]*model.Subnet{
		subnetAt("2001:db8:1::/64", nil, model.SubnetSourceRA, now, now),
		subnetAt("2001:db8:1::/64", nil, model.SubnetSourceDHCP, now, now),
	}))
	got, err := repo.GetSubnets("t1", nil)
	require.NoError(t, err)
	assert.Len(t, got, 2)
}

func TestSQLiteRepository_UpsertSubnetsRejectsInvalid(t *testing.T) {
	repo := newVLANTestRepo(t)
	now := time.Now()
	err := repo.UpsertSubnets([]*model.Subnet{subnetAt("10.0.1.5/24", nil, model.SubnetSourceDHCP, now, now)})
	assert.Error(t, err)
}

func TestSQLiteRepository_SubnetsKeepSchemaVersion(t *testing.T) {
	assert.Equal(t, 1, schemaVersion, "cycle 2 must not bump user_version")
}
