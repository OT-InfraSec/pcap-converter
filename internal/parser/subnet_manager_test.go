package parser

import (
	"net/netip"
	"testing"
	"time"

	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSubnetManager_ObserveCollapsesAndWidens(t *testing.T) {
	sm := NewDefaultSubnetManager("t1")
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	p := netip.MustParsePrefix("10.0.1.77/24") // host bits must be masked

	sm.Observe(p, model.VLANTag{}, model.SubnetSourceDHCP, base)
	sm.Observe(p, model.VLANTag{}, model.SubnetSourceDHCP, base.Add(time.Hour))
	sm.Observe(p, model.VLANTag{}, model.SubnetSourceDHCP, base.Add(-time.Hour))

	all := sm.GetAllSubnets()
	require.Len(t, all, 1)
	assert.Equal(t, "10.0.1.0/24", all[0].CIDR)
	assert.Equal(t, "t1", all[0].TenantID)
	assert.Nil(t, all[0].VlanID)
	assert.True(t, all[0].FirstSeen.Equal(base.Add(-time.Hour)))
	assert.True(t, all[0].LastSeen.Equal(base.Add(time.Hour)))
}

func TestSubnetManager_KeyIsPrefixVLANSource(t *testing.T) {
	sm := NewDefaultSubnetManager("t1")
	now := time.Now()
	p := netip.MustParsePrefix("10.0.1.0/24")
	v10, v20 := 10, 20
	inner := 5

	sm.Observe(p, model.VLANTag{}, model.SubnetSourceDHCP, now)
	sm.Observe(p, model.VLANTag{Outer: &v10}, model.SubnetSourceDHCP, now)
	sm.Observe(p, model.VLANTag{Outer: &v20}, model.SubnetSourceDHCP, now)
	sm.Observe(p, model.VLANTag{Outer: &v20, Inner: &inner}, model.SubnetSourceDHCP, now) // inner tag is not identity
	sm.Observe(p, model.VLANTag{Outer: &v20}, model.SubnetSourceRA, now)

	assert.Len(t, sm.GetAllSubnets(), 4)
}

func TestSubnetManager_DoesNotAliasCallerVLAN(t *testing.T) {
	sm := NewDefaultSubnetManager("t1")
	v := 10
	sm.Observe(netip.MustParsePrefix("10.0.1.0/24"), model.VLANTag{Outer: &v}, model.SubnetSourceDHCP, time.Now())
	v = 99
	assert.Equal(t, 10, *sm.GetAllSubnets()[0].VlanID)
}

func TestSubnetManager_ClearAndInvalidPrefix(t *testing.T) {
	sm := NewDefaultSubnetManager("t1")
	sm.Observe(netip.Prefix{}, model.VLANTag{}, model.SubnetSourceDHCP, time.Now())
	assert.Empty(t, sm.GetAllSubnets(), "invalid prefix is ignored")

	sm.Observe(netip.MustParsePrefix("10.0.1.0/24"), model.VLANTag{}, model.SubnetSourceDHCP, time.Now())
	sm.Clear()
	assert.Empty(t, sm.GetAllSubnets())
}
