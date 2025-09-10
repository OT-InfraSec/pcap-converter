package model

import (
	"errors"
	"time"
)

// IndustrialDeviceType represents the type of industrial device
type IndustrialDeviceType string

const (
	DeviceTypePLC            IndustrialDeviceType = "PLC"
	DeviceTypeHMI            IndustrialDeviceType = "HMI"
	DeviceTypeSCADA          IndustrialDeviceType = "SCADA"
	DeviceTypeHistorian      IndustrialDeviceType = "Historian"
	DeviceTypeEngWorkstation IndustrialDeviceType = "EngineeringWorkstation"
	DeviceTypeIODevice       IndustrialDeviceType = "IODevice"
	DeviceTypeSensor         IndustrialDeviceType = "Sensor"
	DeviceTypeActuator       IndustrialDeviceType = "Actuator"
	DeviceTypeUnknown        IndustrialDeviceType = "Unknown"
)

// IndustrialDeviceRole represents the role of an industrial device in the network
type IndustrialDeviceRole string

const (
	RoleController    IndustrialDeviceRole = "Controller"
	RoleOperator      IndustrialDeviceRole = "Operator"
	RoleEngineer      IndustrialDeviceRole = "Engineer"
	RoleDataCollector IndustrialDeviceRole = "DataCollector"
	RoleFieldDevice   IndustrialDeviceRole = "FieldDevice"
)

// SecurityLevel represents IEC 62443 security levels
type SecurityLevel int

const (
	SecurityLevelUnknown SecurityLevel = 0
	SecurityLevel1       SecurityLevel = 1
	SecurityLevel2       SecurityLevel = 2
	SecurityLevel3       SecurityLevel = 3
	SecurityLevel4       SecurityLevel = 4
)

// IndustrialDeviceInfo represents industrial-specific device information
type IndustrialDeviceInfo struct {
	DeviceAddress   string               `json:"device_address"`
	DeviceType      IndustrialDeviceType `json:"device_type"`
	Role            IndustrialDeviceRole `json:"role"`
	Confidence      float64              `json:"confidence"`
	Protocols       []string             `json:"protocols"`
	SecurityLevel   SecurityLevel        `json:"security_level"`
	Vendor          string               `json:"vendor"`
	ProductName     string               `json:"product_name"`
	SerialNumber    string               `json:"serial_number"`
	FirmwareVersion string               `json:"firmware_version"`
	LastSeen        time.Time            `json:"last_seen"`
	CreatedAt       time.Time            `json:"created_at"`
	UpdatedAt       time.Time            `json:"updated_at"`
}

// ProtocolUsageStats represents protocol usage statistics for a device
type ProtocolUsageStats struct {
	DeviceID          string    `json:"device_id"`
	Protocol          string    `json:"protocol"`
	PacketCount       int64     `json:"packet_count"`
	ByteCount         int64     `json:"byte_count"`
	FirstSeen         time.Time `json:"first_seen"`
	LastSeen          time.Time `json:"last_seen"`
	CommunicationRole string    `json:"communication_role"` // "client", "server", "both"
	PortsUsed         []uint16  `json:"ports_used"`
}

// CommunicationPattern represents communication patterns between devices
type CommunicationPattern struct {
	SourceDevice      string        `json:"source_device"`
	DestinationDevice string        `json:"destination_device"`
	Protocol          string        `json:"protocol"`
	Frequency         time.Duration `json:"frequency"`
	DataVolume        int64         `json:"data_volume"`
	PatternType       string        `json:"pattern_type"` // "periodic", "event-driven", "continuous"
	Criticality       string        `json:"criticality"`  // "low", "medium", "high", "critical"
}

// Validate validates the IndustrialDeviceInfo struct
func (idi *IndustrialDeviceInfo) Validate() error {
	if idi.DeviceAddress == "" {
		return errors.New("device address must not be empty")
	}
	if idi.DeviceType == "" {
		return errors.New("device type must not be empty")
	}
	if !isValidIndustrialDeviceType(idi.DeviceType) {
		return errors.New("invalid device type")
	}
	if idi.Role == "" {
		return errors.New("role must not be empty")
	}
	if !isValidIndustrialDeviceRole(idi.Role) {
		return errors.New("invalid device role")
	}
	if idi.Confidence < 0.0 || idi.Confidence > 1.0 {
		return errors.New("confidence must be between 0.0 and 1.0")
	}
	if !isValidSecurityLevel(idi.SecurityLevel) {
		return errors.New("invalid security level")
	}
	if idi.LastSeen.IsZero() {
		return errors.New("last seen time must not be zero")
	}
	if idi.CreatedAt.IsZero() {
		return errors.New("created at time must not be zero")
	}
	if idi.UpdatedAt.IsZero() {
		return errors.New("updated at time must not be zero")
	}
	if idi.UpdatedAt.Before(idi.CreatedAt) {
		return errors.New("updated at time must not be before created at time")
	}
	return nil
}

// Validate validates the ProtocolUsageStats struct
func (pus *ProtocolUsageStats) Validate() error {
	if pus.DeviceID == "" {
		return errors.New("device ID must not be empty")
	}
	if pus.Protocol == "" {
		return errors.New("protocol must not be empty")
	}
	if pus.PacketCount < 0 {
		return errors.New("packet count must not be negative")
	}
	if pus.ByteCount < 0 {
		return errors.New("byte count must not be negative")
	}
	if pus.FirstSeen.IsZero() {
		return errors.New("first seen time must not be zero")
	}
	if pus.LastSeen.IsZero() {
		return errors.New("last seen time must not be zero")
	}
	if pus.LastSeen.Before(pus.FirstSeen) {
		return errors.New("last seen time must not be before first seen time")
	}
	if pus.CommunicationRole == "" {
		return errors.New("communication role must not be empty")
	}
	if !isValidCommunicationRole(pus.CommunicationRole) {
		return errors.New("invalid communication role")
	}
	return nil
}

// Validate validates the CommunicationPattern struct
func (cp *CommunicationPattern) Validate() error {
	if cp.SourceDevice == "" {
		return errors.New("source device must not be empty")
	}
	if cp.DestinationDevice == "" {
		return errors.New("destination device must not be empty")
	}
	if cp.SourceDevice == cp.DestinationDevice {
		return errors.New("source and destination devices must be different")
	}
	if cp.Protocol == "" {
		return errors.New("protocol must not be empty")
	}
	if cp.Frequency < 0 {
		return errors.New("frequency must not be negative")
	}
	if cp.DataVolume < 0 {
		return errors.New("data volume must not be negative")
	}
	if cp.PatternType == "" {
		return errors.New("pattern type must not be empty")
	}
	if !isValidPatternType(cp.PatternType) {
		return errors.New("invalid pattern type")
	}
	if cp.Criticality == "" {
		return errors.New("criticality must not be empty")
	}
	if !isValidCriticality(cp.Criticality) {
		return errors.New("invalid criticality level")
	}
	return nil
}

// Helper validation functions
func isValidIndustrialDeviceType(deviceType IndustrialDeviceType) bool {
	switch deviceType {
	case DeviceTypePLC, DeviceTypeHMI, DeviceTypeSCADA, DeviceTypeHistorian,
		DeviceTypeEngWorkstation, DeviceTypeIODevice, DeviceTypeSensor,
		DeviceTypeActuator, DeviceTypeUnknown:
		return true
	default:
		return false
	}
}

func isValidIndustrialDeviceRole(role IndustrialDeviceRole) bool {
	switch role {
	case RoleController, RoleOperator, RoleEngineer, RoleDataCollector, RoleFieldDevice:
		return true
	default:
		return false
	}
}

func isValidSecurityLevel(level SecurityLevel) bool {
	return level >= SecurityLevelUnknown && level <= SecurityLevel4
}

func isValidCommunicationRole(role string) bool {
	switch role {
	case "client", "server", "both":
		return true
	default:
		return false
	}
}

func isValidPatternType(patternType string) bool {
	switch patternType {
	case "periodic", "event-driven", "continuous":
		return true
	default:
		return false
	}
}

func isValidCriticality(criticality string) bool {
	switch criticality {
	case "low", "medium", "high", "critical":
		return true
	default:
		return false
	}
}
