package model

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCanonicalCIDR(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		want   string
	}{
		{"ipv4 host bits masked", "10.0.1.77/24", "10.0.1.0/24"},
		{"ipv6 compressed lowercase", "2001:DB8:1:0::5/64", "2001:db8:1::/64"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, CanonicalCIDR(netip.MustParsePrefix(tt.prefix)))
		})
	}
}

func TestSubnetValidate(t *testing.T) {
	now := time.Now()
	valid := Subnet{CIDR: "10.0.1.0/24", Source: SubnetSourceDHCP, FirstSeen: now, LastSeen: now}
	require.NoError(t, valid.Validate())

	bad := valid
	bad.CIDR = "not-a-cidr"
	assert.Error(t, bad.Validate())

	bad = valid
	bad.CIDR = "10.0.1.5/24" // not canonical
	assert.Error(t, bad.Validate())

	bad = valid
	bad.Source = "bogus"
	assert.Error(t, bad.Validate())

	for _, s := range []string{SubnetSourceDHCP, SubnetSourceCDP, SubnetSourceEIGRP, SubnetSourceOSPF, SubnetSourceRA, SubnetSourceInferred} {
		ok := valid
		ok.Source = s
		assert.NoError(t, ok.Validate(), s)
	}
}
