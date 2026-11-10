package parser

import (
	"encoding/json"
	"maps"
	"time"

	helper "github.com/InfraSecConsult/pcap-importer-go/lib/helper"
	model "github.com/InfraSecConsult/pcap-importer-go/lib/model"
)

// DeviceManager handles device discovery, tracking, and MAC correlation
type DeviceManager interface {
	// UpsertDevice updates or creates a device
	UpsertDevice(address, addressType string, timestamp time.Time, addressSubType, macAddress, additionalData string, isDestination bool) *model.Device

	// RecordVLAN adds the VLAN a device was seen in; unknown devices are ignored
	RecordVLAN(address, addressType string, vlan model.VLANTag)

	// GetDevice retrieves a device by address and type
	GetDevice(address, addressType string) *model.Device

	// GetAllDevices returns all tracked devices
	GetAllDevices() []*model.Device

	// UpdateDeviceWithIndustrialInfo updates a device with industrial protocol information
	UpdateDeviceWithIndustrialInfo(deviceIP string, protocolInfo model.IndustrialProtocolInfo, isDestination bool)

	// GetDeviceCounter returns the current device counter value
	GetDeviceCounter() int64

	// Clear removes all devices from tracking
	Clear()
}

// DefaultDeviceManager implements DeviceManager
type DefaultDeviceManager struct {
	devices map[string]*model.Device
	// industrial holds each device's "industrial_protocols" additional-data entry
	// as a live map. Updating it per packet is a map write; the device's JSON is
	// rebuilt only when someone reads the device (see materialize), not once per
	// packet.
	industrial    map[string]map[string]interface{}
	dirty         map[string]struct{} // device keys whose AdditionalData lags behind industrial
	deviceCounter int64
	tenantID      string
}

// NewDefaultDeviceManager creates a new device manager
func NewDefaultDeviceManager(tenantID string, initialCounter int64) *DefaultDeviceManager {
	return &DefaultDeviceManager{
		devices:       make(map[string]*model.Device),
		industrial:    make(map[string]map[string]interface{}),
		dirty:         make(map[string]struct{}),
		deviceCounter: initialCounter,
		tenantID:      tenantID,
	}
}

// UpsertDevice updates or creates a device
func (dm *DefaultDeviceManager) UpsertDevice(address, addressType string, timestamp time.Time,
	addressSubType, macAddress, additionalData string, isDestination bool) *model.Device {

	devKey := addressType + ":" + address
	dev, exists := dm.devices[devKey]

	if !exists {
		// Create new device
		macAddressSet := model.NewMACAddressSet()
		if macAddress != "" {
			macAddressSet.Add(macAddress)
		}

		dev = &model.Device{
			ID:                dm.deviceCounter,
			TenantID:          dm.tenantID,
			Address:           address,
			AddressType:       addressType,
			FirstSeen:         timestamp,
			LastSeen:          timestamp,
			AddressSubType:    addressSubType,
			AddressScope:      helper.GetAddressScopeCombined(address, macAddressSet),
			MACAddressSet:     macAddressSet,
			AdditionalData:    additionalData,
			IsOnlyDestination: isDestination,
			VLANSet:           model.NewVLANSet(),
		}
		dm.devices[devKey] = dev
		dm.deviceCounter++
	} else {
		// Update existing device
		if macAddress != "" {
			dev.MACAddressSet.Add(macAddress)
		}

		if additionalData != "" {
			dm.materialize(devKey)
			// Merge additional data if it exists
			if dev.AdditionalData != "" {
				// Parse existing additional data
				var existingData map[string]interface{}
				if err := json.Unmarshal([]byte(dev.AdditionalData), &existingData); err == nil {
					// Parse new additional data
					var newData map[string]interface{}
					if err := json.Unmarshal([]byte(additionalData), &newData); err == nil {
						// Merge new data into existing data
						for k, v := range newData {
							existingData[k] = v
						}
						// Convert back to JSON string
						if merged, err := json.Marshal(existingData); err == nil {
							dev.AdditionalData = string(merged)
						}
					}
				}
			} else {
				dev.AdditionalData = additionalData
			}
		}

		if dev.IsOnlyDestination && !isDestination {
			dev.IsOnlyDestination = false
		}

		if timestamp.Before(dev.FirstSeen) {
			dev.FirstSeen = timestamp
		}
		if timestamp.After(dev.LastSeen) {
			dev.LastSeen = timestamp
		}

		dm.devices[devKey] = dev
	}

	return dev
}

// RecordVLAN adds the frame's VLAN to the device's VLAN set. A device seen in
// several VLANs keeps one row; the set records each VLAN (and "untagged").
func (dm *DefaultDeviceManager) RecordVLAN(address, addressType string, vlan model.VLANTag) {
	dev, exists := dm.devices[addressType+":"+address]
	if !exists {
		return
	}
	if dev.VLANSet == nil {
		dev.VLANSet = model.NewVLANSet()
	}
	dev.VLANSet.AddTag(vlan)
}

// GetDevice retrieves a device by address and type
func (dm *DefaultDeviceManager) GetDevice(address, addressType string) *model.Device {
	devKey := addressType + ":" + address
	dm.materialize(devKey)
	return dm.devices[devKey]
}

// materialize writes a device's live industrial-protocol data into its
// AdditionalData JSON. Callers that read AdditionalData get it through
// GetDevice or GetAllDevices, which call this.
func (dm *DefaultDeviceManager) materialize(devKey string) {
	if _, ok := dm.dirty[devKey]; !ok {
		return
	}
	delete(dm.dirty, devKey)
	device := dm.devices[devKey]
	if device == nil {
		return
	}
	additionalData := make(map[string]interface{})
	if device.AdditionalData != "" {
		if err := json.Unmarshal([]byte(device.AdditionalData), &additionalData); err != nil || additionalData == nil {
			additionalData = make(map[string]interface{})
		}
	}
	additionalData["industrial_protocols"] = dm.industrial[devKey]
	if jsonData, err := json.Marshal(additionalData); err == nil {
		device.AdditionalData = string(jsonData)
	}
}

// GetAllDevices returns all tracked devices
func (dm *DefaultDeviceManager) GetAllDevices() []*model.Device {
	for key := range dm.dirty {
		dm.materialize(key)
	}
	devices := make([]*model.Device, 0, len(dm.devices))
	for _, device := range dm.devices {
		devices = append(devices, device)
	}
	return devices
}

// UpdateDeviceWithIndustrialInfo updates a device with industrial protocol information
func (dm *DefaultDeviceManager) UpdateDeviceWithIndustrialInfo(deviceIP string, protocolInfo model.IndustrialProtocolInfo, isDestination bool) {
	deviceKey := "IP:" + deviceIP
	device, exists := dm.devices[deviceKey]
	if !exists {
		// Device doesn't exist yet, it will be created by UpsertDevice
		return
	}

	industrialProtocols, ok := dm.industrial[deviceKey]
	if !ok {
		// First update for this device: pick up what an earlier run stored.
		industrialProtocols = make(map[string]interface{})
		if device.AdditionalData != "" {
			var stored map[string]interface{}
			if json.Unmarshal([]byte(device.AdditionalData), &stored) == nil {
				if m, ok := stored["industrial_protocols"].(map[string]interface{}); ok {
					industrialProtocols = m
				}
			}
		}
		dm.industrial[deviceKey] = industrialProtocols
	}

	protocolKey := protocolInfo.Protocol
	existingProtoMap, _ := industrialProtocols[protocolKey].(map[string]interface{})
	if existingProtoMap == nil {
		// New protocol data. The info's maps are copied: they also belong to the
		// packet record and must not change when later packets merge into this.
		protocolData := map[string]interface{}{
			"protocol":         protocolInfo.Protocol,
			"port":             protocolInfo.Port,
			"direction":        protocolInfo.Direction,
			"service_type":     protocolInfo.ServiceType,
			"message_type":     protocolInfo.MessageType,
			"is_real_time":     protocolInfo.IsRealTimeData,
			"is_discovery":     protocolInfo.IsDiscovery,
			"is_configuration": protocolInfo.IsConfiguration,
			"confidence":       protocolInfo.Confidence,
			"last_seen":        protocolInfo.Timestamp,
			"is_destination":   isDestination,
		}
		if protocolInfo.DeviceIdentity != nil {
			protocolData["device_identity"] = maps.Clone(protocolInfo.DeviceIdentity)
		}
		if protocolInfo.SecurityInfo != nil {
			protocolData["security_info"] = maps.Clone(protocolInfo.SecurityInfo)
		}
		if protocolInfo.AdditionalData != nil {
			protocolData["additional_data"] = maps.Clone(protocolInfo.AdditionalData)
		}
		industrialProtocols[protocolKey] = protocolData
	} else {
		// Merge with existing protocol data (multiple packets of the same protocol)
		existingProtoMap["last_seen"] = protocolInfo.Timestamp

		// Update confidence if higher
		if existingConf, ok := existingProtoMap["confidence"].(float64); ok {
			if protocolInfo.Confidence > existingConf {
				existingProtoMap["confidence"] = protocolInfo.Confidence
			}
		}

		mergeInto := func(key string, src map[string]interface{}) {
			if src == nil {
				return
			}
			if existing, ok := existingProtoMap[key].(map[string]interface{}); ok {
				maps.Copy(existing, src)
			} else {
				existingProtoMap[key] = maps.Clone(src)
			}
		}
		mergeInto("device_identity", protocolInfo.DeviceIdentity)
		mergeInto("security_info", protocolInfo.SecurityInfo)
		mergeInto("additional_data", protocolInfo.AdditionalData)
	}

	dm.dirty[deviceKey] = struct{}{}
}

// GetDeviceCounter returns the current device counter value
func (dm *DefaultDeviceManager) GetDeviceCounter() int64 {
	return dm.deviceCounter
}

// Clear removes all devices from tracking
func (dm *DefaultDeviceManager) Clear() {
	dm.devices = make(map[string]*model.Device)
	dm.industrial = make(map[string]map[string]interface{})
	dm.dirty = make(map[string]struct{})
}
