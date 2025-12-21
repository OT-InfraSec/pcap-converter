package parser

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	model "github.com/InfraSecConsult/pcap-importer-go/lib/model"
)

func TestDefaultDeviceManager_UpsertDevice_NewDevice(t *testing.T) {
	dm := NewDefaultDeviceManager("test-tenant", 0)

	address := "192.168.1.100"
	addressType := "IP"
	timestamp := time.Now()
	addressSubType := "IPv4-Private"
	macAddress := "00:11:22:33:44:55"
	additionalData := ""
	isDestination := false

	device := dm.UpsertDevice(address, addressType, timestamp, addressSubType, macAddress, additionalData, isDestination)

	require.NotNil(t, device)
	assert.Equal(t, "test-tenant", device.TenantID)
	assert.Equal(t, address, device.Address)
	assert.Equal(t, addressType, device.AddressType)
	assert.Equal(t, addressSubType, device.AddressSubType)
	assert.Equal(t, timestamp, device.FirstSeen)
	assert.Equal(t, timestamp, device.LastSeen)
	assert.False(t, device.IsOnlyDestination)
	assert.True(t, device.MACAddressSet.Contains(macAddress))
	assert.Equal(t, 1, device.MACAddressSet.Size())
}

func TestDefaultDeviceManager_UpsertDevice_UpdateExisting(t *testing.T) {
	dm := NewDefaultDeviceManager("test-tenant", 0)

	address := "10.0.0.50"
	addressType := "IP"
	firstTime := time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC)
	secondTime := firstTime.Add(5 * time.Minute)
	mac1 := "00:11:22:33:44:55"
	mac2 := "aa:bb:cc:dd:ee:ff"

	// Create initial device
	device1 := dm.UpsertDevice(address, addressType, firstTime, "IPv4-Private", mac1, "", false)
	require.NotNil(t, device1)
	assert.Equal(t, firstTime, device1.FirstSeen)
	assert.Equal(t, firstTime, device1.LastSeen)
	assert.Equal(t, 1, device1.MACAddressSet.Size())

	// Update same device with new MAC and later timestamp
	device2 := dm.UpsertDevice(address, addressType, secondTime, "IPv4-Private", mac2, "", false)

	// Should be the same object
	assert.Equal(t, device1, device2)
	assert.Equal(t, firstTime, device2.FirstSeen, "FirstSeen should not change")
	assert.Equal(t, secondTime, device2.LastSeen, "LastSeen should be updated")
	assert.Equal(t, 2, device2.MACAddressSet.Size(), "Should have 2 MAC addresses")
	assert.True(t, device2.MACAddressSet.Contains(mac1))
	assert.True(t, device2.MACAddressSet.Contains(mac2))
}

func TestDefaultDeviceManager_UpsertDevice_AdditionalDataMerge(t *testing.T) {
	dm := NewDefaultDeviceManager("test-tenant", 0)

	address := "192.168.1.10"
	timestamp := time.Now()

	// First insert with additional data
	data1 := map[string]interface{}{"key1": "value1", "key2": "value2"}
	data1JSON, _ := json.Marshal(data1)
	device := dm.UpsertDevice(address, "IP", timestamp, "IPv4-Private", "", string(data1JSON), false)

	var actualData1 map[string]interface{}
	err := json.Unmarshal([]byte(device.AdditionalData), &actualData1)
	require.NoError(t, err)
	assert.Equal(t, "value1", actualData1["key1"])
	assert.Equal(t, "value2", actualData1["key2"])

	// Update with new additional data - should merge
	data2 := map[string]interface{}{"key2": "updated", "key3": "value3"}
	data2JSON, _ := json.Marshal(data2)
	dm.UpsertDevice(address, "IP", timestamp.Add(1*time.Second), "IPv4-Private", "", string(data2JSON), false)

	var actualData2 map[string]interface{}
	err = json.Unmarshal([]byte(device.AdditionalData), &actualData2)
	require.NoError(t, err)
	assert.Equal(t, "value1", actualData2["key1"], "Original key1 should remain")
	assert.Equal(t, "updated", actualData2["key2"], "key2 should be updated")
	assert.Equal(t, "value3", actualData2["key3"], "New key3 should be added")
}

func TestDefaultDeviceManager_UpsertDevice_IsOnlyDestination(t *testing.T) {
	dm := NewDefaultDeviceManager("test-tenant", 0)

	address := "192.168.1.200"
	timestamp := time.Now()

	// First seen as destination only
	device := dm.UpsertDevice(address, "IP", timestamp, "IPv4-Private", "", "", true)
	assert.True(t, device.IsOnlyDestination, "Should be marked as destination-only")

	// Later seen as source
	dm.UpsertDevice(address, "IP", timestamp.Add(1*time.Second), "IPv4-Private", "", "", false)
	assert.False(t, device.IsOnlyDestination, "Should no longer be destination-only")

	// Even if seen as destination again, should remain false
	dm.UpsertDevice(address, "IP", timestamp.Add(2*time.Second), "IPv4-Private", "", "", true)
	assert.False(t, device.IsOnlyDestination, "Should still not be destination-only")
}

func TestDefaultDeviceManager_GetDevice(t *testing.T) {
	dm := NewDefaultDeviceManager("test-tenant", 0)

	// Create a device
	address := "10.0.0.100"
	device := dm.UpsertDevice(address, "IP", time.Now(), "IPv4-Private", "00:11:22:33:44:55", "", false)
	require.NotNil(t, device)

	// Retrieve it
	retrieved := dm.GetDevice(address, "IP")
	assert.Equal(t, device, retrieved, "Should retrieve the same device")

	// Try to get non-existent device
	nonExistent := dm.GetDevice("1.2.3.4", "IP")
	assert.Nil(t, nonExistent, "Should return nil for non-existent device")

	// Wrong address type
	wrongType := dm.GetDevice(address, "MAC")
	assert.Nil(t, wrongType, "Should return nil for wrong address type")
}

func TestDefaultDeviceManager_GetAllDevices(t *testing.T) {
	dm := NewDefaultDeviceManager("test-tenant", 0)

	// Initially empty
	devices := dm.GetAllDevices()
	assert.Empty(t, devices)

	// Add devices
	dm.UpsertDevice("192.168.1.1", "IP", time.Now(), "IPv4-Private", "", "", false)
	dm.UpsertDevice("192.168.1.2", "IP", time.Now(), "IPv4-Private", "", "", false)
	dm.UpsertDevice("00:11:22:33:44:55", "MAC", time.Now(), "", "", "", false)

	devices = dm.GetAllDevices()
	assert.Len(t, devices, 3, "Should have 3 devices")
}

func TestDefaultDeviceManager_Clear(t *testing.T) {
	dm := NewDefaultDeviceManager("test-tenant", 0)

	// Add devices
	dm.UpsertDevice("192.168.1.1", "IP", time.Now(), "IPv4-Private", "", "", false)
	dm.UpsertDevice("192.168.1.2", "IP", time.Now(), "IPv4-Private", "", "", false)

	devices := dm.GetAllDevices()
	assert.Len(t, devices, 2)

	// Clear
	dm.Clear()

	devices = dm.GetAllDevices()
	assert.Empty(t, devices, "Should have no devices after clear")

	// Verify retrieval also returns nil
	device := dm.GetDevice("192.168.1.1", "IP")
	assert.Nil(t, device)
}

func TestDefaultDeviceManager_UpdateDeviceWithIndustrialInfo(t *testing.T) {
	dm := NewDefaultDeviceManager("test-tenant", 0)

	deviceIP := "10.0.0.50"
	timestamp := time.Now()

	// Create device first
	device := dm.UpsertDevice(deviceIP, "IP", timestamp, "IPv4-Private", "", "", false)
	require.NotNil(t, device)

	// Add industrial protocol info
	protocolInfo := model.IndustrialProtocolInfo{
		Protocol:    "EtherNet/IP",
		Port:        44818,
		Direction:   "request",
		ServiceType: "List Identity",
		Confidence:  0.95,
		Timestamp:   timestamp,
		DeviceIdentity: map[string]interface{}{
			"vendor":       "Rockwell Automation",
			"product_name": "CompactLogix",
		},
	}

	dm.UpdateDeviceWithIndustrialInfo(deviceIP, protocolInfo, false)

	// Verify industrial info was added
	var additionalData map[string]interface{}
	err := json.Unmarshal([]byte(device.AdditionalData), &additionalData)
	require.NoError(t, err)

	industrialProtocols, ok := additionalData["industrial_protocols"].(map[string]interface{})
	require.True(t, ok, "Should have industrial_protocols key")

	ethernetIP, ok := industrialProtocols["EtherNet/IP"].(map[string]interface{})
	require.True(t, ok, "Should have EtherNet/IP protocol")

	assert.Equal(t, "EtherNet/IP", ethernetIP["protocol"])
	assert.Equal(t, float64(44818), ethernetIP["port"])
	assert.Equal(t, "request", ethernetIP["direction"])
	assert.Equal(t, 0.95, ethernetIP["confidence"])
}

func TestDefaultDeviceManager_UpdateDeviceWithIndustrialInfo_MultipleProtocols(t *testing.T) {
	dm := NewDefaultDeviceManager("test-tenant", 0)

	deviceIP := "10.0.0.60"
	timestamp := time.Now()

	// Create device
	dm.UpsertDevice(deviceIP, "IP", timestamp, "IPv4-Private", "", "", false)

	// Add first protocol
	protocol1 := model.IndustrialProtocolInfo{
		Protocol:   "EtherNet/IP",
		Port:       44818,
		Confidence: 0.9,
		Timestamp:  timestamp,
	}
	dm.UpdateDeviceWithIndustrialInfo(deviceIP, protocol1, false)

	// Add second protocol
	protocol2 := model.IndustrialProtocolInfo{
		Protocol:   "Modbus",
		Port:       502,
		Confidence: 0.85,
		Timestamp:  timestamp.Add(1 * time.Second),
	}
	dm.UpdateDeviceWithIndustrialInfo(deviceIP, protocol2, false)

	// Verify both protocols are stored
	device := dm.GetDevice(deviceIP, "IP")
	var additionalData map[string]interface{}
	err := json.Unmarshal([]byte(device.AdditionalData), &additionalData)
	require.NoError(t, err)

	industrialProtocols := additionalData["industrial_protocols"].(map[string]interface{})
	assert.Contains(t, industrialProtocols, "EtherNet/IP")
	assert.Contains(t, industrialProtocols, "Modbus")
}

func TestDefaultDeviceManager_UpdateDeviceWithIndustrialInfo_MergeDeviceIdentity(t *testing.T) {
	dm := NewDefaultDeviceManager("test-tenant", 0)

	deviceIP := "10.0.0.70"
	timestamp := time.Now()

	// Create device
	dm.UpsertDevice(deviceIP, "IP", timestamp, "IPv4-Private", "", "", false)

	// Add protocol with partial device identity
	protocol1 := model.IndustrialProtocolInfo{
		Protocol:   "OPC UA",
		Port:       4840,
		Confidence: 0.9,
		Timestamp:  timestamp,
		DeviceIdentity: map[string]interface{}{
			"vendor": "Siemens",
		},
	}
	dm.UpdateDeviceWithIndustrialInfo(deviceIP, protocol1, false)

	// Update with more device identity info
	protocol2 := model.IndustrialProtocolInfo{
		Protocol:   "OPC UA",
		Port:       4840,
		Confidence: 0.95,
		Timestamp:  timestamp.Add(1 * time.Second),
		DeviceIdentity: map[string]interface{}{
			"product_name": "S7-1500",
			"serial":       "ABC123",
		},
	}
	dm.UpdateDeviceWithIndustrialInfo(deviceIP, protocol2, false)

	// Verify device identity was merged
	device := dm.GetDevice(deviceIP, "IP")
	var additionalData map[string]interface{}
	err := json.Unmarshal([]byte(device.AdditionalData), &additionalData)
	require.NoError(t, err)

	industrialProtocols := additionalData["industrial_protocols"].(map[string]interface{})
	opcua := industrialProtocols["OPC UA"].(map[string]interface{})
	deviceIdentity := opcua["device_identity"].(map[string]interface{})

	assert.Equal(t, "Siemens", deviceIdentity["vendor"])
	assert.Equal(t, "S7-1500", deviceIdentity["product_name"])
	assert.Equal(t, "ABC123", deviceIdentity["serial"])
}

func TestDefaultDeviceManager_UpdateDeviceWithIndustrialInfo_NonExistentDevice(t *testing.T) {
	dm := NewDefaultDeviceManager("test-tenant", 0)

	// Try to update non-existent device - should not panic
	protocolInfo := model.IndustrialProtocolInfo{
		Protocol:   "Modbus",
		Port:       502,
		Confidence: 0.8,
		Timestamp:  time.Now(),
	}

	// Should not panic, just do nothing
	dm.UpdateDeviceWithIndustrialInfo("1.2.3.4", protocolInfo, false)

	// Verify device wasn't created
	device := dm.GetDevice("1.2.3.4", "IP")
	assert.Nil(t, device, "Device should not be auto-created")
}

func TestDefaultDeviceManager_DeviceCounter(t *testing.T) {
	dm := NewDefaultDeviceManager("test-tenant", 0)

	// Create devices and verify ID assignment
	device1 := dm.UpsertDevice("10.0.0.1", "IP", time.Now(), "IPv4-Private", "", "", false)
	assert.Equal(t, int64(0), device1.ID, "First device should have ID 0")

	device2 := dm.UpsertDevice("10.0.0.2", "IP", time.Now(), "IPv4-Private", "", "", false)
	assert.Equal(t, int64(1), device2.ID, "Second device should have ID 1")

	device3 := dm.UpsertDevice("10.0.0.3", "IP", time.Now(), "IPv4-Private", "", "", false)
	assert.Equal(t, int64(2), device3.ID, "Third device should have ID 2")

	// Update existing device - ID should not change
	dm.UpsertDevice("10.0.0.1", "IP", time.Now().Add(1*time.Second), "IPv4-Private", "", "", false)
	assert.Equal(t, int64(0), device1.ID, "Device ID should not change on update")
}

func TestDefaultDeviceManager_MultipleAddressTypes(t *testing.T) {
	dm := NewDefaultDeviceManager("test-tenant", 0)

	// Same address but different types should be different devices
	ipDevice := dm.UpsertDevice("192.168.1.1", "IP", time.Now(), "IPv4-Private", "", "", false)
	macDevice := dm.UpsertDevice("192.168.1.1", "MAC", time.Now(), "", "", "", false)

	assert.NotEqual(t, ipDevice, macDevice, "Different address types should create different devices")
	assert.Equal(t, int64(0), ipDevice.ID)
	assert.Equal(t, int64(1), macDevice.ID)

	devices := dm.GetAllDevices()
	assert.Len(t, devices, 2)
}
