package parser

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecordProtocolUsage_AggregatesPerDeviceAndProtocol(t *testing.T) {
	p := &GopacketParser{
		TenantID:           "t1",
		industrialParser:   NewIndustrialProtocolParser(),
		protocolUsageStats: make(map[string]*model.ProtocolUsageStats),
	}
	base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 1000; i++ {
		info := IndustrialProtocolInfo{Protocol: "enip", Port: 44818, Direction: "outbound", Timestamp: base.Add(time.Duration(i) * time.Second)}
		p.recordProtocolUsage("10.0.0.1", info, false)
		info.Direction = "inbound"
		p.recordProtocolUsage("10.0.0.2", info, true)
	}
	assert.Len(t, p.protocolUsageStats, 2, "one record per device and protocol, not per packet")

	out := p.protocolUsageStats["10.0.0.1\x00enip"]
	require.NotNil(t, out)
	assert.Equal(t, int64(1000), out.PacketCountOut)
	assert.Equal(t, base, out.FirstSeen)
	assert.Equal(t, base.Add(999*time.Second), out.LastSeen)
	assert.Equal(t, "t1", out.TenantID)
	assert.Equal(t, []uint16{44818}, out.PortsUsed)
	assert.NoError(t, out.Validate())

	// a device that was client and server ends up "both"
	p.recordProtocolUsage("10.0.0.1", IndustrialProtocolInfo{Protocol: "enip", Port: 44818, Direction: "inbound", Timestamp: base}, true)
	assert.Equal(t, "both", out.CommunicationRole)
}

func TestDeviceManager_IndustrialInfoDoesNotAliasPacketMaps(t *testing.T) {
	dm := NewDefaultDeviceManager("t", 0)
	dm.UpsertDevice("10.0.0.5", "IP", time.Now(), "IPv4", "", "", false)
	first := IndustrialProtocolInfo{Protocol: "x", DeviceIdentity: map[string]interface{}{"a": 1}}
	dm.UpdateDeviceWithIndustrialInfo("10.0.0.5", first, false)
	dm.UpdateDeviceWithIndustrialInfo("10.0.0.5", IndustrialProtocolInfo{Protocol: "x", DeviceIdentity: map[string]interface{}{"b": 2}}, false)

	assert.Len(t, first.DeviceIdentity, 1, "merging later packets must not change the first packet's data")

	var data map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(dm.GetAllDevices()[0].AdditionalData), &data))
	identity := data["industrial_protocols"].(map[string]interface{})["x"].(map[string]interface{})["device_identity"].(map[string]interface{})
	assert.Len(t, identity, 2)
}

func TestAssociateDNSNames_NoRewriteWhenKnown(t *testing.T) {
	dm := NewDefaultDeviceManager("t", 0)
	dev := dm.UpsertDevice("10.0.0.7", "IP", time.Now(), "IPv4", "", `{"dnsNames":["a.local",7]}`, false)
	p := &GopacketParser{deviceManager: dm}

	require.NoError(t, p.associateDNSNames("10.0.0.7", "a.local"))
	assert.JSONEq(t, `{"dnsNames":["a.local",7]}`, dev.AdditionalData, "known name leaves the data untouched")

	require.NoError(t, p.AssociateDNSNameToIP("10.0.0.7", "b.local"))
	assert.JSONEq(t, `{"dnsNames":["a.local","b.local"]}`, dev.AdditionalData)

	assert.Error(t, p.associateDNSNames("10.9.9.9", "x"))
}
