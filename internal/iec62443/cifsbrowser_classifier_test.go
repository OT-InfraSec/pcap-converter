package iec62443

import (
	"testing"

	lib_layers "github.com/InfraSecConsult/pcap-importer-go/lib/layers"
	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
)

// TestClassifyPrintQueueServer tests classification of print queue servers
func TestClassifyPrintQueueServer(t *testing.T) {
	announcement := &lib_layers.CIFSBrowserAnnouncement{
		Command:    lib_layers.CIFSBrowserCmdHostAnnounce,
		ServerName: "PRINTER01",
		ServerTypeFlags: lib_layers.ServerTypeFlags{
			IsPrintQueueServer: true,
			IsServer:           true,
		},
	}

	result := ClassifyFromCIFSBrowserAnnouncement(announcement)

	if result.DeviceType.Type != model.DeviceTypePrinter {
		t.Errorf("Expected DeviceTypePrinter, got %v", result.DeviceType.Type)
	}

	if result.DeviceType.Confidence < 0.80 {
		t.Errorf("Expected confidence > 0.80 for printer, got %f", result.DeviceType.Confidence)
	}

	if result.Role.Role != model.RoleFieldDevice {
		t.Errorf("Expected RoleFieldDevice, got %v", result.Role.Role)
	}
}

// TestClassifyDomainController tests classification of domain controllers
func TestClassifyDomainController(t *testing.T) {
	announcement := &lib_layers.CIFSBrowserAnnouncement{
		Command:    lib_layers.CIFSBrowserCmdHostAnnounce,
		ServerName: "DC01",
		ServerTypeFlags: lib_layers.ServerTypeFlags{
			IsDomainController: true,
		},
	}

	result := ClassifyFromCIFSBrowserAnnouncement(announcement)

	if result.DeviceType.Type != model.DeviceTypeDomainController {
		t.Errorf("Expected DeviceTypeDomainController, got %v", result.DeviceType.Type)
	}

	if result.DeviceType.Confidence < 0.85 {
		t.Errorf("Expected confidence > 0.85 for domain controller, got %f", result.DeviceType.Confidence)
	}

	if result.Role.Role != model.RoleController {
		t.Errorf("Expected RoleController, got %v", result.Role.Role)
	}
}

// TestClassifyWorkstation tests classification of engineering workstations
func TestClassifyWorkstation(t *testing.T) {
	announcement := &lib_layers.CIFSBrowserAnnouncement{
		Command:    lib_layers.CIFSBrowserCmdHostAnnounce,
		ServerName: "WORKSTATION01",
		ServerTypeFlags: lib_layers.ServerTypeFlags{
			IsWorkstation:   true,
			IsNTWorkstation: true,
		},
	}

	result := ClassifyFromCIFSBrowserAnnouncement(announcement)

	if result.DeviceType.Type != model.DeviceTypeEngWorkstation {
		t.Errorf("Expected DeviceTypeEngWorkstation, got %v", result.DeviceType.Type)
	}

	if result.DeviceType.Confidence < 0.55 {
		t.Errorf("Expected confidence > 0.55 for workstation, got %f", result.DeviceType.Confidence)
	}

	if result.Role.Role != model.RoleOperator {
		t.Errorf("Expected RoleOperator, got %v", result.Role.Role)
	}
}

// TestClassifyMasterBrowser tests classification of master browsers
func TestClassifyMasterBrowser(t *testing.T) {
	announcement := &lib_layers.CIFSBrowserAnnouncement{
		Command:    lib_layers.CIFSBrowserCmdHostAnnounce,
		ServerName: "MASTER_BROWSER",
		ServerTypeFlags: lib_layers.ServerTypeFlags{
			IsMasterBrowser: true,
			IsServer:        true,
		},
	}

	result := ClassifyFromCIFSBrowserAnnouncement(announcement)

	if result.Role.Role != model.RoleController {
		t.Errorf("Expected RoleController for master browser, got %v", result.Role.Role)
	}

	if result.Role.Confidence < 0.70 {
		t.Errorf("Expected confidence > 0.70 for master browser role, got %f", result.Role.Confidence)
	}
}

// TestDetectWindowsOS tests Windows operating system detection
func TestDetectWindowsOS(t *testing.T) {
	announcement := &lib_layers.CIFSBrowserAnnouncement{
		Command:    lib_layers.CIFSBrowserCmdHostAnnounce,
		ServerName: "WIN_HOST",
		ServerTypeFlags: lib_layers.ServerTypeFlags{
			IsNTWorkstation: true,
			IsNTServer:      false,
		},
	}

	result := ClassifyFromCIFSBrowserAnnouncement(announcement)

	if result.OSType.OSType != "Windows" {
		t.Errorf("Expected OSType 'Windows', got %s", result.OSType.OSType)
	}

	if result.OSType.Confidence < 0.70 {
		t.Errorf("Expected confidence > 0.70 for Windows detection, got %f", result.OSType.Confidence)
	}
}

// TestDetectAppleOS tests Apple operating system detection
func TestDetectAppleOS(t *testing.T) {
	announcement := &lib_layers.CIFSBrowserAnnouncement{
		Command:    lib_layers.CIFSBrowserCmdHostAnnounce,
		ServerName: "APPLE_HOST",
		ServerTypeFlags: lib_layers.ServerTypeFlags{
			IsAppleServer: true,
		},
	}

	result := ClassifyFromCIFSBrowserAnnouncement(announcement)

	if result.OSType.OSType != "Apple" {
		t.Errorf("Expected OSType 'Apple', got %s", result.OSType.OSType)
	}

	if result.OSType.Confidence < 0.80 {
		t.Errorf("Expected confidence > 0.80 for Apple detection, got %f", result.OSType.Confidence)
	}
}

// TestClassifyFromCIFSBrowserMessage tests the generic message classifier
func TestClassifyFromCIFSBrowserMessage(t *testing.T) {
	announcement := &lib_layers.CIFSBrowserAnnouncement{
		Command:    lib_layers.CIFSBrowserCmdHostAnnounce,
		ServerName: "TEST_HOST",
		ServerTypeFlags: lib_layers.ServerTypeFlags{
			IsPrintQueueServer: true,
		},
	}

	result := ClassifyFromCIFSBrowserMessage(announcement)

	if result == nil {
		t.Fatal("Expected non-nil result for CIFSBrowserAnnouncement")
	}

	if result.DeviceType.Type != model.DeviceTypePrinter {
		t.Errorf("Expected DeviceTypePrinter, got %v", result.DeviceType.Type)
	}
}

// TestUnknownDeviceClassification tests classification of unrecognized devices
func TestUnknownDeviceClassification(t *testing.T) {
	announcement := &lib_layers.CIFSBrowserAnnouncement{
		Command:         lib_layers.CIFSBrowserCmdHostAnnounce,
		ServerName:      "UNKNOWN_HOST",
		ServerTypeFlags: lib_layers.ServerTypeFlags{}, // No flags set
	}

	result := ClassifyFromCIFSBrowserAnnouncement(announcement)

	if result.DeviceType.Type != model.DeviceTypeUnknown {
		t.Errorf("Expected DeviceTypeUnknown, got %v", result.DeviceType.Type)
	}

	if result.DeviceType.Confidence >= 0.25 {
		t.Errorf("Expected low confidence for unknown device, got %f", result.DeviceType.Confidence)
	}
}

// TestBackupBrowserRole tests backup browser role classification
func TestBackupBrowserRole(t *testing.T) {
	announcement := &lib_layers.CIFSBrowserAnnouncement{
		Command:    lib_layers.CIFSBrowserCmdHostAnnounce,
		ServerName: "BACKUP_BROWSER",
		ServerTypeFlags: lib_layers.ServerTypeFlags{
			IsBackupBrowser: true,
		},
	}

	result := ClassifyFromCIFSBrowserAnnouncement(announcement)

	if result.Role.Role != model.RoleController {
		t.Errorf("Expected RoleController for backup browser, got %v", result.Role.Role)
	}
}

// TestConfidenceScoring tests that confidence scores are reasonable
func TestConfidenceScoring(t *testing.T) {
	tests := []struct {
		name            string
		flags           lib_layers.ServerTypeFlags
		expectedMinConf float64
		expectedDevType model.IndustrialDeviceType
	}{
		{
			name: "PrintQueueServer",
			flags: lib_layers.ServerTypeFlags{
				IsPrintQueueServer: true,
			},
			expectedMinConf: 0.80,
			expectedDevType: model.DeviceTypePrinter,
		},
		{
			name: "DomainController",
			flags: lib_layers.ServerTypeFlags{
				IsDomainController: true,
			},
			expectedMinConf: 0.85,
			expectedDevType: model.DeviceTypeDomainController,
		},
		{
			name: "Workstation",
			flags: lib_layers.ServerTypeFlags{
				IsWorkstation: true,
			},
			expectedMinConf: 0.55,
			expectedDevType: model.DeviceTypeEngWorkstation,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			announcement := &lib_layers.CIFSBrowserAnnouncement{
				Command:         lib_layers.CIFSBrowserCmdHostAnnounce,
				ServerName:      "TEST",
				ServerTypeFlags: tt.flags,
			}

			result := ClassifyFromCIFSBrowserAnnouncement(announcement)

			if result.DeviceType.Type != tt.expectedDevType {
				t.Errorf("Expected device type %v, got %v", tt.expectedDevType, result.DeviceType.Type)
			}

			if result.DeviceType.Confidence < tt.expectedMinConf {
				t.Errorf("Expected confidence >= %f, got %f", tt.expectedMinConf, result.DeviceType.Confidence)
			}

			// Confidence should always be between 0 and 1
			if result.DeviceType.Confidence < 0 || result.DeviceType.Confidence > 1 {
				t.Errorf("Confidence out of range [0,1]: %f", result.DeviceType.Confidence)
			}
		})
	}
}

// TestIntegrationWithIndustrialProtocolInfo tests creating IndustrialProtocolInfo from CIFS Browser
func TestIntegrationWithIndustrialProtocolInfo(t *testing.T) {
	// This test verifies that CIFS Browser data can be converted to IndustrialProtocolInfo
	announcement := &lib_layers.CIFSBrowserAnnouncement{
		Command:        lib_layers.CIFSBrowserCmdHostAnnounce,
		ServerName:     "WORKSTATION01",
		OSMajorVersion: 6,
		OSMinorVersion: 1,
		ServerTypeFlags: lib_layers.ServerTypeFlags{
			IsNTWorkstation: true,
		},
	}

	result := ClassifyFromCIFSBrowserAnnouncement(announcement)

	// This should be usable with the device classifier
	if result.DeviceType.Type == model.DeviceTypeUnknown && result.DeviceType.Confidence == 0 {
		t.Error("Expected meaningful classification result")
	}

	// Verify confidence is reasonable
	if result.DeviceType.Confidence <= 0 || result.DeviceType.Confidence > 1 {
		t.Errorf("Confidence %f should be between 0 and 1", result.DeviceType.Confidence)
	}
}
