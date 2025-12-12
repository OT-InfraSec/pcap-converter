package model

import (
	"testing"
	"time"
)

func TestIndustrialDeviceInfoValidation(t *testing.T) {
	now := time.Now()
	later := now.Add(time.Hour)

	tests := []struct {
		name    string
		device  IndustrialDeviceInfo
		wantErr bool
	}{
		{
			name: "happy path - valid PLC device",
			device: IndustrialDeviceInfo{
				DeviceAddress:   "device-001",
				DeviceType:      DeviceTypePLC,
				Role:            RoleController,
				Confidence:      0.95,
				Protocols:       []string{"EtherNet/IP", "Modbus"},
				SecurityLevel:   SecurityLevel2,
				Vendor:          "Rockwell Automation",
				ProductName:     "CompactLogix 5370",
				SerialNumber:    "12345678",
				FirmwareVersion: "v1.2.3",
				LastSeen:        later,
				CreatedAt:       now,
				UpdatedAt:       later,
			},
			wantErr: false,
		},
		{
			name: "happy path - valid HMI device",
			device: IndustrialDeviceInfo{
				DeviceAddress: "device-002",
				DeviceType:    DeviceTypeHMI,
				Role:          RoleOperator,
				Confidence:    0.85,
				Protocols:     []string{"OPC UA"},
				SecurityLevel: SecurityLevel1,
				LastSeen:      later,
				CreatedAt:     now,
				UpdatedAt:     later,
			},
			wantErr: false,
		},
		{
			name: "happy path - minimum confidence",
			device: IndustrialDeviceInfo{
				DeviceAddress: "device-003",
				DeviceType:    DeviceTypeUnknown,
				Role:          RoleFieldDevice,
				Confidence:    0.0,
				SecurityLevel: SecurityLevelUnknown,
				LastSeen:      later,
				CreatedAt:     now,
				UpdatedAt:     later,
			},
			wantErr: false,
		},
		{
			name: "happy path - maximum confidence",
			device: IndustrialDeviceInfo{
				DeviceAddress: "device-004",
				DeviceType:    DeviceTypeSCADA,
				Role:          RoleDataCollector,
				Confidence:    1.0,
				SecurityLevel: SecurityLevel4,
				LastSeen:      later,
				CreatedAt:     now,
				UpdatedAt:     later,
			},
			wantErr: false,
		},
		{
			name: "bad path - empty device address",
			device: IndustrialDeviceInfo{
				DeviceAddress: "",
				DeviceType:    DeviceTypePLC,
				Role:          RoleController,
				Confidence:    0.95,
				SecurityLevel: SecurityLevel2,
				LastSeen:      later,
				CreatedAt:     now,
				UpdatedAt:     later,
			},
			wantErr: true,
		},
		{
			name: "bad path - empty device type",
			device: IndustrialDeviceInfo{
				DeviceAddress: "device-005",
				DeviceType:    "",
				Role:          RoleController,
				Confidence:    0.95,
				SecurityLevel: SecurityLevel2,
				LastSeen:      later,
				CreatedAt:     now,
				UpdatedAt:     later,
			},
			wantErr: true,
		},
		{
			name: "bad path - invalid device type",
			device: IndustrialDeviceInfo{
				DeviceAddress: "device-006",
				DeviceType:    "InvalidType",
				Role:          RoleController,
				Confidence:    0.95,
				SecurityLevel: SecurityLevel2,
				LastSeen:      later,
				CreatedAt:     now,
				UpdatedAt:     later,
			},
			wantErr: true,
		},
		{
			name: "bad path - empty role",
			device: IndustrialDeviceInfo{
				DeviceAddress: "device-007",
				DeviceType:    DeviceTypePLC,
				Role:          "",
				Confidence:    0.95,
				SecurityLevel: SecurityLevel2,
				LastSeen:      later,
				CreatedAt:     now,
				UpdatedAt:     later,
			},
			wantErr: true,
		},
		{
			name: "bad path - invalid role",
			device: IndustrialDeviceInfo{
				DeviceAddress: "device-008",
				DeviceType:    DeviceTypePLC,
				Role:          "InvalidRole",
				Confidence:    0.95,
				SecurityLevel: SecurityLevel2,
				LastSeen:      later,
				CreatedAt:     now,
				UpdatedAt:     later,
			},
			wantErr: true,
		},
		{
			name: "bad path - confidence below 0",
			device: IndustrialDeviceInfo{
				DeviceAddress: "device-009",
				DeviceType:    DeviceTypePLC,
				Role:          RoleController,
				Confidence:    -0.1,
				SecurityLevel: SecurityLevel2,
				LastSeen:      later,
				CreatedAt:     now,
				UpdatedAt:     later,
			},
			wantErr: true,
		},
		{
			name: "bad path - confidence above 1",
			device: IndustrialDeviceInfo{
				DeviceAddress: "device-010",
				DeviceType:    DeviceTypePLC,
				Role:          RoleController,
				Confidence:    1.1,
				SecurityLevel: SecurityLevel2,
				LastSeen:      later,
				CreatedAt:     now,
				UpdatedAt:     later,
			},
			wantErr: true,
		},
		{
			name: "bad path - invalid security level",
			device: IndustrialDeviceInfo{
				DeviceAddress: "device-011",
				DeviceType:    DeviceTypePLC,
				Role:          RoleController,
				Confidence:    0.95,
				SecurityLevel: SecurityLevel(5),
				LastSeen:      later,
				CreatedAt:     now,
				UpdatedAt:     later,
			},
			wantErr: true,
		},
		{
			name: "bad path - zero last seen time",
			device: IndustrialDeviceInfo{
				DeviceAddress: "device-012",
				DeviceType:    DeviceTypePLC,
				Role:          RoleController,
				Confidence:    0.95,
				SecurityLevel: SecurityLevel2,
				LastSeen:      time.Time{},
				CreatedAt:     now,
				UpdatedAt:     later,
			},
			wantErr: true,
		},
		{
			name: "bad path - zero created at time",
			device: IndustrialDeviceInfo{
				DeviceAddress: "device-013",
				DeviceType:    DeviceTypePLC,
				Role:          RoleController,
				Confidence:    0.95,
				SecurityLevel: SecurityLevel2,
				LastSeen:      later,
				CreatedAt:     time.Time{},
				UpdatedAt:     later,
			},
			wantErr: true,
		},
		{
			name: "bad path - zero updated at time",
			device: IndustrialDeviceInfo{
				DeviceAddress: "device-014",
				DeviceType:    DeviceTypePLC,
				Role:          RoleController,
				Confidence:    0.95,
				SecurityLevel: SecurityLevel2,
				LastSeen:      later,
				CreatedAt:     now,
				UpdatedAt:     time.Time{},
			},
			wantErr: true,
		},
		{
			name: "bad path - updated at before created at",
			device: IndustrialDeviceInfo{
				DeviceAddress: "device-015",
				DeviceType:    DeviceTypePLC,
				Role:          RoleController,
				Confidence:    0.95,
				SecurityLevel: SecurityLevel2,
				LastSeen:      later,
				CreatedAt:     later,
				UpdatedAt:     now,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.device.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("IndustrialDeviceInfo.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestProtocolUsageStatsValidation(t *testing.T) {
	now := time.Now()
	later := now.Add(time.Hour)

	tests := []struct {
		name    string
		stats   ProtocolUsageStats
		wantErr bool
	}{
		{
			name: "happy path - valid EtherNet/IP stats",
			stats: ProtocolUsageStats{
				DeviceID:          "device-001",
				Protocol:          "EtherNet/IP",
				PacketCountOut: 1000,
				ByteCountOut: 50000,
				FirstSeen:         now,
				LastSeen:          later,
				CommunicationRole: "client",
				PortsUsed:         []uint16{44818, 2222},
			},
			wantErr: false,
		},
		{
			name: "happy path - valid OPC UA server stats",
			stats: ProtocolUsageStats{
				DeviceID:          "device-002",
				Protocol:          "OPC UA",
				PacketCountOut: 500,
				ByteCountOut: 25000,
				FirstSeen:         now,
				LastSeen:          later,
				CommunicationRole: "server",
				PortsUsed:         []uint16{4840},
			},
			wantErr: false,
		},
		{
			name: "happy path - both client and server",
			stats: ProtocolUsageStats{
				DeviceID:          "device-003",
				Protocol:          "Modbus",
				PacketCountOut: 200,
				ByteCountOut: 10000,
				FirstSeen:         now,
				LastSeen:          later,
				CommunicationRole: "both",
				PortsUsed:         []uint16{502},
			},
			wantErr: false,
		},
		{
			name: "happy path - zero counts",
			stats: ProtocolUsageStats{
				DeviceID:          "device-004",
				Protocol:          "DNP3",
				PacketCountOut: 0,
				ByteCountOut: 0,
				FirstSeen:         now,
				LastSeen:          now,
				CommunicationRole: "client",
				PortsUsed:         []uint16{},
			},
			wantErr: false,
		},
		{
			name: "bad path - empty device ID",
			stats: ProtocolUsageStats{
				DeviceID:          "",
				Protocol:          "EtherNet/IP",
				PacketCountOut: 1000,
				ByteCountOut: 50000,
				FirstSeen:         now,
				LastSeen:          later,
				CommunicationRole: "client",
			},
			wantErr: true,
		},
		{
			name: "bad path - empty protocol",
			stats: ProtocolUsageStats{
				DeviceID:          "device-005",
				Protocol:          "",
				PacketCountOut: 1000,
				ByteCountOut: 50000,
				FirstSeen:         now,
				LastSeen:          later,
				CommunicationRole: "client",
			},
			wantErr: true,
		},
		{
			name: "bad path - negative packet count",
			stats: ProtocolUsageStats{
				DeviceID:          "device-006",
				Protocol:          "EtherNet/IP",
				PacketCountOut: -1,
				ByteCountOut: 50000,
				FirstSeen:         now,
				LastSeen:          later,
				CommunicationRole: "client",
			},
			wantErr: true,
		},
		{
			name: "bad path - negative byte count",
			stats: ProtocolUsageStats{
				DeviceID:          "device-007",
				Protocol:          "EtherNet/IP",
				PacketCountOut: 1000,
				ByteCountOut: -1,
				FirstSeen:         now,
				LastSeen:          later,
				CommunicationRole: "client",
			},
			wantErr: true,
		},
		{
			name: "bad path - zero first seen time",
			stats: ProtocolUsageStats{
				DeviceID:          "device-008",
				Protocol:          "EtherNet/IP",
				PacketCountOut: 1000,
				ByteCountOut: 50000,
				FirstSeen:         time.Time{},
				LastSeen:          later,
				CommunicationRole: "client",
			},
			wantErr: true,
		},
		{
			name: "bad path - zero last seen time",
			stats: ProtocolUsageStats{
				DeviceID:          "device-009",
				Protocol:          "EtherNet/IP",
				PacketCountOut: 1000,
				ByteCountOut: 50000,
				FirstSeen:         now,
				LastSeen:          time.Time{},
				CommunicationRole: "client",
			},
			wantErr: true,
		},
		{
			name: "bad path - last seen before first seen",
			stats: ProtocolUsageStats{
				DeviceID:          "device-010",
				Protocol:          "EtherNet/IP",
				PacketCountOut: 1000,
				ByteCountOut: 50000,
				FirstSeen:         later,
				LastSeen:          now,
				CommunicationRole: "client",
			},
			wantErr: true,
		},
		{
			name: "bad path - empty communication role",
			stats: ProtocolUsageStats{
				DeviceID:          "device-011",
				Protocol:          "EtherNet/IP",
				PacketCountOut: 1000,
				ByteCountOut: 50000,
				FirstSeen:         now,
				LastSeen:          later,
				CommunicationRole: "",
			},
			wantErr: true,
		},
		{
			name: "bad path - invalid communication role",
			stats: ProtocolUsageStats{
				DeviceID:          "device-012",
				Protocol:          "EtherNet/IP",
				PacketCountOut: 1000,
				ByteCountOut: 50000,
				FirstSeen:         now,
				LastSeen:          later,
				CommunicationRole: "invalid",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.stats.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("ProtocolUsageStats.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCommunicationPatternValidation(t *testing.T) {
	tests := []struct {
		name    string
		pattern CommunicationPattern
		wantErr bool
	}{
		{
			name: "happy path - periodic EtherNet/IP communication",
			pattern: CommunicationPattern{
				SourceDevice:      "plc-001",
				DestinationDevice: "hmi-001",
				Protocol:          "EtherNet/IP",
				Frequency:         time.Second * 10,
				DataVolume:        1024,
				PatternType:       "periodic",
				Criticality:       "high",
			},
			wantErr: false,
		},
		{
			name: "happy path - event-driven OPC UA communication",
			pattern: CommunicationPattern{
				SourceDevice:      "scada-001",
				DestinationDevice: "historian-001",
				Protocol:          "OPC UA",
				Frequency:         0,
				DataVolume:        2048,
				PatternType:       "event-driven",
				Criticality:       "medium",
			},
			wantErr: false,
		},
		{
			name: "happy path - continuous Modbus communication",
			pattern: CommunicationPattern{
				SourceDevice:      "controller-001",
				DestinationDevice: "sensor-001",
				Protocol:          "Modbus",
				Frequency:         time.Millisecond * 100,
				DataVolume:        512,
				PatternType:       "continuous",
				Criticality:       "critical",
			},
			wantErr: false,
		},
		{
			name: "happy path - low criticality communication",
			pattern: CommunicationPattern{
				SourceDevice:      "workstation-001",
				DestinationDevice: "plc-001",
				Protocol:          "HTTP",
				Frequency:         time.Minute * 5,
				DataVolume:        100,
				PatternType:       "periodic",
				Criticality:       "low",
			},
			wantErr: false,
		},
		{
			name: "bad path - empty source device",
			pattern: CommunicationPattern{
				SourceDevice:      "",
				DestinationDevice: "hmi-001",
				Protocol:          "EtherNet/IP",
				Frequency:         time.Second * 10,
				DataVolume:        1024,
				PatternType:       "periodic",
				Criticality:       "high",
			},
			wantErr: true,
		},
		{
			name: "bad path - empty destination device",
			pattern: CommunicationPattern{
				SourceDevice:      "plc-001",
				DestinationDevice: "",
				Protocol:          "EtherNet/IP",
				Frequency:         time.Second * 10,
				DataVolume:        1024,
				PatternType:       "periodic",
				Criticality:       "high",
			},
			wantErr: true,
		},
		{
			name: "bad path - same source and destination",
			pattern: CommunicationPattern{
				SourceDevice:      "plc-001",
				DestinationDevice: "plc-001",
				Protocol:          "EtherNet/IP",
				Frequency:         time.Second * 10,
				DataVolume:        1024,
				PatternType:       "periodic",
				Criticality:       "high",
			},
			wantErr: true,
		},
		{
			name: "bad path - empty protocol",
			pattern: CommunicationPattern{
				SourceDevice:      "plc-001",
				DestinationDevice: "hmi-001",
				Protocol:          "",
				Frequency:         time.Second * 10,
				DataVolume:        1024,
				PatternType:       "periodic",
				Criticality:       "high",
			},
			wantErr: true,
		},
		{
			name: "bad path - negative frequency",
			pattern: CommunicationPattern{
				SourceDevice:      "plc-001",
				DestinationDevice: "hmi-001",
				Protocol:          "EtherNet/IP",
				Frequency:         time.Second * -1,
				DataVolume:        1024,
				PatternType:       "periodic",
				Criticality:       "high",
			},
			wantErr: true,
		},
		{
			name: "bad path - negative data volume",
			pattern: CommunicationPattern{
				SourceDevice:      "plc-001",
				DestinationDevice: "hmi-001",
				Protocol:          "EtherNet/IP",
				Frequency:         time.Second * 10,
				DataVolume:        -1,
				PatternType:       "periodic",
				Criticality:       "high",
			},
			wantErr: true,
		},
		{
			name: "bad path - empty pattern type",
			pattern: CommunicationPattern{
				SourceDevice:      "plc-001",
				DestinationDevice: "hmi-001",
				Protocol:          "EtherNet/IP",
				Frequency:         time.Second * 10,
				DataVolume:        1024,
				PatternType:       "",
				Criticality:       "high",
			},
			wantErr: true,
		},
		{
			name: "bad path - invalid pattern type",
			pattern: CommunicationPattern{
				SourceDevice:      "plc-001",
				DestinationDevice: "hmi-001",
				Protocol:          "EtherNet/IP",
				Frequency:         time.Second * 10,
				DataVolume:        1024,
				PatternType:       "invalid",
				Criticality:       "high",
			},
			wantErr: true,
		},
		{
			name: "bad path - empty criticality",
			pattern: CommunicationPattern{
				SourceDevice:      "plc-001",
				DestinationDevice: "hmi-001",
				Protocol:          "EtherNet/IP",
				Frequency:         time.Second * 10,
				DataVolume:        1024,
				PatternType:       "periodic",
				Criticality:       "",
			},
			wantErr: true,
		},
		{
			name: "bad path - invalid criticality",
			pattern: CommunicationPattern{
				SourceDevice:      "plc-001",
				DestinationDevice: "hmi-001",
				Protocol:          "EtherNet/IP",
				Frequency:         time.Second * 10,
				DataVolume:        1024,
				PatternType:       "periodic",
				Criticality:       "invalid",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.pattern.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("CommunicationPattern.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIndustrialDeviceTypeValidation(t *testing.T) {
	tests := []struct {
		name       string
		deviceType IndustrialDeviceType
		want       bool
	}{
		{"valid PLC", DeviceTypePLC, true},
		{"valid HMI", DeviceTypeHMI, true},
		{"valid SCADA", DeviceTypeSCADA, true},
		{"valid Historian", DeviceTypeHistorian, true},
		{"valid Engineering Workstation", DeviceTypeEngWorkstation, true},
		{"valid IO Device", DeviceTypeIODevice, true},
		{"valid Sensor", DeviceTypeSensor, true},
		{"valid Actuator", DeviceTypeActuator, true},
		{"valid Unknown", DeviceTypeUnknown, true},
		{"invalid type", IndustrialDeviceType("InvalidType"), false},
		{"empty type", IndustrialDeviceType(""), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidIndustrialDeviceType(tt.deviceType)
			if got != tt.want {
				t.Errorf("isValidIndustrialDeviceType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIndustrialDeviceRoleValidation(t *testing.T) {
	tests := []struct {
		name string
		role IndustrialDeviceRole
		want bool
	}{
		{"valid Controller", RoleController, true},
		{"valid Operator", RoleOperator, true},
		{"valid Engineer", RoleEngineer, true},
		{"valid Data Collector", RoleDataCollector, true},
		{"valid Field Device", RoleFieldDevice, true},
		{"invalid role", IndustrialDeviceRole("InvalidRole"), false},
		{"empty role", IndustrialDeviceRole(""), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidIndustrialDeviceRole(tt.role)
			if got != tt.want {
				t.Errorf("isValidIndustrialDeviceRole() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSecurityLevelValidation(t *testing.T) {
	tests := []struct {
		name  string
		level SecurityLevel
		want  bool
	}{
		{"valid Unknown", SecurityLevelUnknown, true},
		{"valid Level 1", SecurityLevel1, true},
		{"valid Level 2", SecurityLevel2, true},
		{"valid Level 3", SecurityLevel3, true},
		{"valid Level 4", SecurityLevel4, true},
		{"invalid negative", SecurityLevel(-1), false},
		{"invalid too high", SecurityLevel(5), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidSecurityLevel(tt.level)
			if got != tt.want {
				t.Errorf("isValidSecurityLevel() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCommunicationRoleValidation(t *testing.T) {
	tests := []struct {
		name string
		role string
		want bool
	}{
		{"valid client", "client", true},
		{"valid server", "server", true},
		{"valid both", "both", true},
		{"invalid role", "invalid", false},
		{"empty role", "", false},
		{"case sensitive", "Client", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidCommunicationRole(tt.role)
			if got != tt.want {
				t.Errorf("isValidCommunicationRole() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPatternTypeValidation(t *testing.T) {
	tests := []struct {
		name        string
		patternType string
		want        bool
	}{
		{"valid periodic", "periodic", true},
		{"valid event-driven", "event-driven", true},
		{"valid continuous", "continuous", true},
		{"invalid type", "invalid", false},
		{"empty type", "", false},
		{"case sensitive", "Periodic", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidPatternType(tt.patternType)
			if got != tt.want {
				t.Errorf("isValidPatternType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCriticalityValidation(t *testing.T) {
	tests := []struct {
		name        string
		criticality string
		want        bool
	}{
		{"valid low", "low", true},
		{"valid medium", "medium", true},
		{"valid high", "high", true},
		{"valid critical", "critical", true},
		{"invalid level", "invalid", false},
		{"empty level", "", false},
		{"case sensitive", "Low", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidCriticality(tt.criticality)
			if got != tt.want {
				t.Errorf("isValidCriticality() = %v, want %v", got, tt.want)
			}
		})
	}
}
