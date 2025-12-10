package iec62443

import (
	lib_layers "github.com/InfraSecConsult/pcap-importer-go/lib/layers"
	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
)

// CIFSBrowserClassificationResult represents device classification based on CIFS Browser analysis
type CIFSBrowserClassificationResult struct {
	DeviceType IndustrialDeviceTypeWithConfidence
	Role       IndustrialDeviceRoleWithConfidence
	OSType     OSTypeWithConfidence
}

// IndustrialDeviceTypeWithConfidence represents a device type with confidence score
type IndustrialDeviceTypeWithConfidence struct {
	Type       model.IndustrialDeviceType
	Confidence float64
}

// IndustrialDeviceRoleWithConfidence represents a device role with confidence score
type IndustrialDeviceRoleWithConfidence struct {
	Role       model.IndustrialDeviceRole
	Confidence float64
}

// OSTypeWithConfidence represents operating system type with confidence
type OSTypeWithConfidence struct {
	OSType     string  // "Windows", "Apple", "Unknown"
	Confidence float64
}

// ClassifyFromCIFSBrowserAnnouncement classifies a device based on Host Announce message
func ClassifyFromCIFSBrowserAnnouncement(announcement *lib_layers.CIFSBrowserAnnouncement) CIFSBrowserClassificationResult {
	result := CIFSBrowserClassificationResult{
		DeviceType: IndustrialDeviceTypeWithConfidence{
			Type:       model.DeviceTypeUnknown,
			Confidence: 0.0,
		},
		Role: IndustrialDeviceRoleWithConfidence{
			Role:       model.RoleFieldDevice,
			Confidence: 0.0,
		},
		OSType: OSTypeWithConfidence{
			OSType:     "Unknown",
			Confidence: 0.0,
		},
	}

	// Analyze server type flags for device type
	result.DeviceType = classifyDeviceTypeFromServerFlags(announcement.ServerTypeFlags)

	// Analyze server type flags for role
	result.Role = classifyRoleFromServerFlags(announcement.ServerTypeFlags)

	// Detect operating system
	result.OSType = detectOSType(announcement.ServerTypeFlags)

	return result
}

// classifyDeviceTypeFromServerFlags determines device type from server type flags
func classifyDeviceTypeFromServerFlags(flags lib_layers.ServerTypeFlags) IndustrialDeviceTypeWithConfidence {
	// High confidence: Print Queue Server
	if flags.IsPrintQueueServer {
		return IndustrialDeviceTypeWithConfidence{
			Type:       model.DeviceTypePrinter,
			Confidence: 0.85,
		}
	}

	// High confidence: Domain Controller
	if flags.IsDomainController {
		return IndustrialDeviceTypeWithConfidence{
			Type:       model.DeviceTypeDomainController,
			Confidence: 0.90,
		}
	}

	// Moderate-High confidence: Engineering Workstation if Windows
	if flags.IsWorkstation || flags.IsNTWorkstation || flags.IsWindowsForWorkgroups {
		return IndustrialDeviceTypeWithConfidence{
			Type:       model.DeviceTypeEngWorkstation,
			Confidence: 0.60,
		}
	}

	// Moderate-High confidence: Server types
	if flags.IsServer || flags.IsNTServer {
		return IndustrialDeviceTypeWithConfidence{
			Type:       model.DeviceTypeIODevice,
			Confidence: 0.55,
		}
	}

	// Default to Unknown with low confidence
	return IndustrialDeviceTypeWithConfidence{
		Type:       model.DeviceTypeUnknown,
		Confidence: 0.2,
	}
}

// classifyRoleFromServerFlags determines device role from server type flags
func classifyRoleFromServerFlags(flags lib_layers.ServerTypeFlags) IndustrialDeviceRoleWithConfidence {
	// Master or backup browser -> Controller
	if flags.IsMasterBrowser || flags.IsBackupBrowser || flags.IsDomainMasterBrowser {
		return IndustrialDeviceRoleWithConfidence{
			Role:       model.RoleController,
			Confidence: 0.75,
		}
	}

	// Domain controller -> Controller
	if flags.IsDomainController {
		return IndustrialDeviceRoleWithConfidence{
			Role:       model.RoleController,
			Confidence: 0.85,
		}
	}

	// Print queue -> Field Device
	if flags.IsPrintQueueServer {
		return IndustrialDeviceRoleWithConfidence{
			Role:       model.RoleFieldDevice,
			Confidence: 0.80,
		}
	}

	// Workstations -> Operator
	if flags.IsWorkstation || flags.IsNTWorkstation || flags.IsWindowsForWorkgroups {
		return IndustrialDeviceRoleWithConfidence{
			Role:       model.RoleOperator,
			Confidence: 0.65,
		}
	}

	// Default -> Field Device with moderate confidence
	return IndustrialDeviceRoleWithConfidence{
		Role:       model.RoleFieldDevice,
		Confidence: 0.5,
	}
}

// detectOSType detects the operating system type from server flags
func detectOSType(flags lib_layers.ServerTypeFlags) OSTypeWithConfidence {
	// Strong indicators of Windows
	if flags.IsNTWorkstation || flags.IsNTServer || flags.IsWindows95 || flags.IsWindowsForWorkgroups {
		return OSTypeWithConfidence{
			OSType:     "Windows",
			Confidence: 0.75,
		}
	}

	// Apple server detected
	if flags.IsAppleServer {
		return OSTypeWithConfidence{
			OSType:     "Apple",
			Confidence: 0.85,
		}
	}

	// Generic workstation or server (could be Windows)
	if flags.IsWorkstation || flags.IsServer {
		return OSTypeWithConfidence{
			OSType:     "Windows",
			Confidence: 0.55,
		}
	}

	// Other OS indicators
	if flags.IsNovellServer {
		return OSTypeWithConfidence{
			OSType:     "Novell",
			Confidence: 0.80,
		}
	}

	if flags.IsOSF || flags.IsVMS {
		return OSTypeWithConfidence{
			OSType:     "Unix/VMS",
			Confidence: 0.75,
		}
	}

	// Default unknown
	return OSTypeWithConfidence{
		OSType:     "Unknown",
		Confidence: 0.0,
	}
}

// ClassifyFromCIFSBrowserMessage is a helper to classify from a generic CIFS Browser message
func ClassifyFromCIFSBrowserMessage(msg interface{}) *CIFSBrowserClassificationResult {
	// Type assert to different message types
	switch v := msg.(type) {
	case *lib_layers.CIFSBrowserAnnouncement:
		result := ClassifyFromCIFSBrowserAnnouncement(v)
		return &result
	default:
		// Unknown message type, return nil
		return nil
	}
}
