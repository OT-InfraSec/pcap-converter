package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVLANFromWire(t *testing.T) {
	assert.Nil(t, VLANFromWire(0))
	assert.Nil(t, VLANFromWire(4095))
	assert.Nil(t, VLANFromWire(65535))
	require.NotNil(t, VLANFromWire(1))
	assert.Equal(t, 4094, *VLANFromWire(4094))
}

func sealed(n *CDPNeighbor) *CDPNeighbor {
	n.Fingerprint = n.ComputeFingerprint()
	return n
}

func TestCDPNeighborFingerprint(t *testing.T) {
	base := CDPNeighbor{SrcMAC: "aa:bb:cc:dd:ee:ff", DeviceID: "sw1", Addresses: "10.0.0.1", NativeVLAN: intPtr(10)}
	same := base
	assert.Equal(t, base.ComputeFingerprint(), same.ComputeFingerprint())

	// identity and timestamps are not advertised values
	other := base
	other.SrcMAC, other.PortID = "00:00:00:00:00:01", "Gi1/0/2"
	assert.Equal(t, base.ComputeFingerprint(), other.ComputeFingerprint())

	changed := base
	changed.NativeVLAN = intPtr(20)
	assert.NotEqual(t, base.ComputeFingerprint(), changed.ComputeFingerprint())

	unset := base
	unset.NativeVLAN = nil
	assert.NotEqual(t, base.ComputeFingerprint(), unset.ComputeFingerprint())

	// length prefix: moving a byte between fields changes the hash
	a := CDPNeighbor{DeviceID: "ab", Platform: "c"}
	b := CDPNeighbor{DeviceID: "a", Platform: "bc"}
	assert.NotEqual(t, a.ComputeFingerprint(), b.ComputeFingerprint())
}

func TestCDPNeighborValidate(t *testing.T) {
	ok := sealed(&CDPNeighbor{SrcMAC: "aa:bb:cc:dd:ee:ff", NativeVLAN: intPtr(1)})
	assert.NoError(t, ok.Validate())

	assert.Error(t, sealed(&CDPNeighbor{}).Validate(), "missing MAC")
	assert.Error(t, sealed(&CDPNeighbor{SrcMAC: "m", NativeVLAN: intPtr(0)}).Validate())
	assert.Error(t, sealed(&CDPNeighbor{SrcMAC: "m", ManagementVLAN: intPtr(4095)}).Validate())
	assert.Error(t, sealed(&CDPNeighbor{SrcMAC: "m", VlanID: intPtr(5000)}).Validate())
	assert.Error(t, (&CDPNeighbor{SrcMAC: "m", DeviceID: "x", Fingerprint: "bogus"}).Validate())
}

func TestSubnetKindAdvertisedValid(t *testing.T) {
	s := Subnet{CIDR: "10.0.0.0/24", Source: SubnetSourceCDP, Kind: SubnetKindAdvertised}
	assert.NoError(t, s.Validate())
}
