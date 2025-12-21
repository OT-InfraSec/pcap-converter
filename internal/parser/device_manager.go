package parser

import (
	"encoding/json"
	"time"

	helper "github.com/InfraSecConsult/pcap-importer-go/lib/helper"
	model "github.com/InfraSecConsult/pcap-importer-go/lib/model"
)

// DeviceManager handles device discovery, tracking, and MAC correlation
type DeviceManager interface {
	// UpsertDevice updates or creates a device
	UpsertDevice(address, addressType string, timestamp time.Time, addressSubType, macAddress, additionalData string, isDestination bool) *model.Device

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
	devices       map[string]*model.Device
	deviceCounter int64
	tenantID      string
}

// NewDefaultDeviceManager creates a new device manager
func NewDefaultDeviceManager(tenantID string, initialCounter int64) *DefaultDeviceManager {
	return &DefaultDeviceManager{
		devices:       make(map[string]*model.Device),
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
		}
		dm.devices[devKey] = dev
		dm.deviceCounter++
	} else {
		// Update existing device
		if macAddress != "" {
			dev.MACAddressSet.Add(macAddress)
		}

		if additionalData != "" {
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

// GetDevice retrieves a device by address and type
func (dm *DefaultDeviceManager) GetDevice(address, addressType string) *model.Device {
	devKey := addressType + ":" + address
	return dm.devices[devKey]
}

// GetAllDevices returns all tracked devices
func (dm *DefaultDeviceManager) GetAllDevices() []*model.Device {
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

	// Create or update additional data with industrial protocol information
	var additionalData map[string]interface{}
	if device.AdditionalData != "" {
		json.Unmarshal([]byte(device.AdditionalData), &additionalData)
	} else {
		additionalData = make(map[string]interface{})
	}

	// Add industrial protocol information
	if additionalData["industrial_protocols"] == nil {
		additionalData["industrial_protocols"] = make(map[string]interface{})
	}

	industrialProtocols := additionalData["industrial_protocols"].(map[string]interface{})

	// Store protocol-specific information with enhanced data
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

	// Add device identity information if available
	if protocolInfo.DeviceIdentity != nil {
		protocolData["device_identity"] = protocolInfo.DeviceIdentity
	}

	// Add security information if available
	if protocolInfo.SecurityInfo != nil {
		protocolData["security_info"] = protocolInfo.SecurityInfo
	}

	// Add additional protocol-specific data
	if protocolInfo.AdditionalData != nil {
		protocolData["additional_data"] = protocolInfo.AdditionalData
	}

	// Update or merge protocol data (handle multiple packets of same protocol)
	protocolKey := protocolInfo.Protocol
	if existingProto, exists := industrialProtocols[protocolKey]; exists {
		// Merge with existing protocol data
		existingProtoMap := existingProto.(map[string]interface{})

		// Update timestamps to latest
		existingProtoMap["last_seen"] = protocolInfo.Timestamp

		// Update confidence if higher
		if existingConf, ok := existingProtoMap["confidence"].(float64); ok {
			if float64(protocolInfo.Confidence) > existingConf {
				existingProtoMap["confidence"] = protocolInfo.Confidence
			}
		}

		// Merge device identity if provided
		if protocolInfo.DeviceIdentity != nil {
			if existingIdentity, ok := existingProtoMap["device_identity"].(map[string]interface{}); ok {
				for k, v := range protocolInfo.DeviceIdentity {
					existingIdentity[k] = v
				}
			} else {
				existingProtoMap["device_identity"] = protocolInfo.DeviceIdentity
			}
		}

		// Merge security info if provided
		if protocolInfo.SecurityInfo != nil {
			if existingSecurity, ok := existingProtoMap["security_info"].(map[string]interface{}); ok {
				for k, v := range protocolInfo.SecurityInfo {
					existingSecurity[k] = v
				}
			} else {
				existingProtoMap["security_info"] = protocolInfo.SecurityInfo
			}
		}

		// Merge additional data if provided
		if protocolInfo.AdditionalData != nil {
			if existingAdditional, ok := existingProtoMap["additional_data"].(map[string]interface{}); ok {
				for k, v := range protocolInfo.AdditionalData {
					existingAdditional[k] = v
				}
			} else {
				existingProtoMap["additional_data"] = protocolInfo.AdditionalData
			}
		}
	} else {
		// New protocol data
		industrialProtocols[protocolKey] = protocolData
	}

	// Update device additional data
	if jsonData, err := json.Marshal(additionalData); err == nil {
		device.AdditionalData = string(jsonData)
		dm.devices[deviceKey] = device
	}
}

// GetDeviceCounter returns the current device counter value
func (dm *DefaultDeviceManager) GetDeviceCounter() int64 {
	return dm.deviceCounter
}

// Clear removes all devices from tracking
func (dm *DefaultDeviceManager) Clear() {
	dm.devices = make(map[string]*model.Device)
}
