package iec62443

import (
	"fmt"
	"strings"
	"time"

	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
)

// DeviceClassifierImpl implements the DeviceClassifier interface
type DeviceClassifierImpl struct {
	// Repository for device data access (injected dependency)
	repository DeviceRepository
	// Communication pattern analyzer for advanced pattern analysis
	patternAnalyzer CommunicationPatternAnalyzer
}

// DeviceRepository defines the interface for device data access needed by the classifier
type DeviceRepository interface {
	GetDevicesByType(deviceType model.IndustrialDeviceType) ([]model.Device, error)
	UpdateDevice(device *model.Device) error
}

// NewDeviceClassifier creates a new device classifier instance
func NewDeviceClassifier(repository DeviceRepository) DeviceClassifier {
	return &DeviceClassifierImpl{
		repository:      repository,
		patternAnalyzer: NewCommunicationPatternAnalyzer(),
	}
}

// ClassifyDevice analyzes a device and its communication patterns to determine its industrial type and role
func (dc *DeviceClassifierImpl) ClassifyDevice(device model.Device, protocols []IndustrialProtocolInfo, patterns []model.CommunicationPattern) IndustrialDeviceClassification {
	// Analyze protocol usage patterns
	protocolAnalysis := dc.AnalyzeProtocolUsage(protocols)

	// Analyze communication patterns
	commAnalysis := dc.AnalyzeCommunicationPatterns(patterns)

	// Determine device type based on protocol and communication analysis
	deviceType := dc.determineDeviceType(protocolAnalysis, commAnalysis)

	// Determine device role based on communication patterns
	role := dc.determineDeviceRole(protocolAnalysis, commAnalysis)

	// Calculate confidence score
	confidence := dc.CalculateConfidence(device, protocols, patterns)

	// Determine security level based on device type and role
	securityLevel := dc.determineSecurityLevel(deviceType, role, protocolAnalysis)

	// Extract protocol names
	protocolNames := make([]string, len(protocols))
	for i, p := range protocols {
		protocolNames[i] = p.Protocol
	}

	// Generate reasoning explanation
	reasoning := dc.generateReasoning(deviceType, role, protocolAnalysis, commAnalysis)

	return IndustrialDeviceClassification{
		DeviceType:    deviceType,
		Role:          role,
		Confidence:    confidence,
		Protocols:     protocolNames,
		SecurityLevel: securityLevel,
		LastUpdated:   time.Now(),
		Reasoning:     reasoning,
	}
}

// UpdateDeviceRole updates the role of a device based on new information
func (dc *DeviceClassifierImpl) UpdateDeviceRole(deviceID string, newRole model.IndustrialDeviceRole) error {
	// This would typically interact with the repository to update the device
	// For now, we'll return a placeholder implementation
	return fmt.Errorf("device role update not yet implemented for device %s", deviceID)
}

// GetDevicesByType retrieves devices of a specific industrial type
func (dc *DeviceClassifierImpl) GetDevicesByType(deviceType model.IndustrialDeviceType) ([]model.Device, error) {
	return dc.repository.GetDevicesByType(deviceType)
}

// AnalyzeProtocolUsage analyzes protocol usage patterns to infer device characteristics
func (dc *DeviceClassifierImpl) AnalyzeProtocolUsage(protocols []IndustrialProtocolInfo) ProtocolAnalysisResult {
	primaryProtocols := make([]string, 0)
	secondaryProtocols := make([]string, 0)
	deviceTypeHints := make([]model.IndustrialDeviceType, 0)
	roleHints := make([]model.IndustrialDeviceRole, 0)
	securityIndicators := make(map[string]interface{})

	// Analyze each protocol
	for _, protocol := range protocols {
		switch strings.ToUpper(protocol.Protocol) {
		case "ETHERNETIP":
			primaryProtocols = append(primaryProtocols, protocol.Protocol)
			dc.analyzeEtherNetIPProtocol(protocol, &deviceTypeHints, &roleHints, securityIndicators)
		case "OPCUA":
			primaryProtocols = append(primaryProtocols, protocol.Protocol)
			dc.analyzeOPCUAProtocol(protocol, &deviceTypeHints, &roleHints, securityIndicators)
		case "MODBUS":
			primaryProtocols = append(primaryProtocols, protocol.Protocol)
			dc.analyzeModbusProtocol(protocol, &deviceTypeHints, &roleHints, securityIndicators)
		case "CIFSBROWSER":
			secondaryProtocols = append(secondaryProtocols, protocol.Protocol)
			dc.analyzeCIFSBrowserProtocol(protocol, &deviceTypeHints, &roleHints, securityIndicators)
		case "HTTP", "HTTPS":
			secondaryProtocols = append(secondaryProtocols, protocol.Protocol)
			dc.analyzeHTTPProtocol(protocol, &deviceTypeHints, &roleHints, securityIndicators)
		default:
			secondaryProtocols = append(secondaryProtocols, protocol.Protocol)
		}
	}

	return ProtocolAnalysisResult{
		PrimaryProtocols:   primaryProtocols,
		SecondaryProtocols: secondaryProtocols,
		DeviceTypeHints:    deviceTypeHints,
		RoleHints:          roleHints,
		SecurityIndicators: securityIndicators,
	}
}

// AnalyzeCommunicationPatterns analyzes communication patterns for producer-consumer and client-server relationships
func (dc *DeviceClassifierImpl) AnalyzeCommunicationPatterns(patterns []model.CommunicationPattern) CommunicationAnalysisResult {
	if len(patterns) == 0 {
		return CommunicationAnalysisResult{
			RelationshipType:  "unknown",
			CommunicationRole: "unknown",
			DataFlowDirection: "unknown",
			CriticalityLevel:  "low",
		}
	}

	// Analyze pattern types and frequencies
	periodicCount := 0
	eventDrivenCount := 0
	continuousCount := 0

	inboundCount := 0
	outboundCount := 0
	bidirectionalCount := 0

	highCriticalityCount := 0
	mediumCriticalityCount := 0

	deviceTypeHints := make([]model.IndustrialDeviceType, 0)
	roleHints := make([]model.IndustrialDeviceRole, 0)

	for _, pattern := range patterns {
		// Count pattern types
		switch pattern.PatternType {
		case "periodic":
			periodicCount++
		case "event-driven":
			eventDrivenCount++
		case "continuous":
			continuousCount++
		}

		// Analyze criticality
		if pattern.Criticality == "high" || pattern.Criticality == "critical" {
			highCriticalityCount++
		} else if pattern.Criticality == "medium" {
			mediumCriticalityCount++
		}

		// Analyze communication patterns for device type hints
		dc.analyzeCommunicationForDeviceHints(pattern, &deviceTypeHints, &roleHints)
	}

	// Determine relationship type
	relationshipType := dc.determineRelationshipType(periodicCount, eventDrivenCount, continuousCount)

	// Determine communication role
	communicationRole := dc.determineCommunicationRole(inboundCount, outboundCount, bidirectionalCount)

	// Determine data flow direction
	dataFlowDirection := dc.determineDataFlowDirection(patterns)

	// Determine criticality level
	criticalityLevel := dc.determineCriticalityLevel(highCriticalityCount, mediumCriticalityCount, len(patterns))

	return CommunicationAnalysisResult{
		RelationshipType:  relationshipType,
		CommunicationRole: communicationRole,
		DataFlowDirection: dataFlowDirection,
		CriticalityLevel:  criticalityLevel,
		DeviceTypeHints:   deviceTypeHints,
		RoleHints:         roleHints,
	}
}

// CalculateConfidence calculates confidence score for device classification
func (dc *DeviceClassifierImpl) CalculateConfidence(device model.Device, protocols []IndustrialProtocolInfo, patterns []model.CommunicationPattern) float64 {
	advancedScore := dc.CalculateAdvancedConfidence(device, protocols, patterns)
	return advancedScore.OverallConfidence
}

// CalculateAdvancedConfidence calculates advanced confidence score with detailed breakdown
func (dc *DeviceClassifierImpl) CalculateAdvancedConfidence(device model.Device, protocols []IndustrialProtocolInfo, patterns []model.CommunicationPattern) ConfidenceScore {
	confidenceFactors := make(map[string]float64)
	uncertaintyReasons := make([]string, 0)
	recommendedActions := make([]string, 0)
	evidenceCount := 0

	// Protocol-based confidence
	protocolConfidence := dc.calculateProtocolConfidence(protocols, confidenceFactors, &uncertaintyReasons, &recommendedActions, &evidenceCount)

	// Communication pattern confidence
	patternConfidence := dc.calculatePatternConfidence(patterns, confidenceFactors, &uncertaintyReasons, &recommendedActions, &evidenceCount)

	// Device identity confidence
	identityConfidence := dc.calculateIdentityConfidence(protocols, confidenceFactors, &uncertaintyReasons, &recommendedActions, &evidenceCount)

	// Consistency score - how well different evidence sources agree
	consistencyScore := dc.calculateConsistencyScore(protocols, patterns, confidenceFactors, &uncertaintyReasons)

	// Calculate overall confidence using weighted average
	weights := map[string]float64{
		"protocol":    0.4,
		"pattern":     0.3,
		"identity":    0.2,
		"consistency": 0.1,
	}

	overallConfidence := (protocolConfidence*weights["protocol"] +
		patternConfidence*weights["pattern"] +
		identityConfidence*weights["identity"] +
		consistencyScore*weights["consistency"])

	// Apply evidence count bonus/penalty
	evidenceBonus := dc.calculateEvidenceBonus(evidenceCount)
	overallConfidence = overallConfidence * evidenceBonus

	// Cap at 1.0
	if overallConfidence > 1.0 {
		overallConfidence = 1.0
	}

	// Add recommendations based on confidence level
	if overallConfidence < 0.5 {
		recommendedActions = append(recommendedActions, "Collect more network traffic data")
		recommendedActions = append(recommendedActions, "Verify device configuration manually")
	}
	if protocolConfidence < 0.3 {
		recommendedActions = append(recommendedActions, "Enable industrial protocol logging")
	}
	if patternConfidence < 0.3 {
		recommendedActions = append(recommendedActions, "Monitor communication patterns over longer period")
	}

	return ConfidenceScore{
		OverallConfidence:  overallConfidence,
		ProtocolConfidence: protocolConfidence,
		PatternConfidence:  patternConfidence,
		IdentityConfidence: identityConfidence,
		ConsistencyScore:   consistencyScore,
		EvidenceCount:      evidenceCount,
		ConfidenceFactors:  confidenceFactors,
		UncertaintyReasons: uncertaintyReasons,
		RecommendedActions: recommendedActions,
	}
}

// Helper methods for protocol analysis

func (dc *DeviceClassifierImpl) analyzeEtherNetIPProtocol(protocol IndustrialProtocolInfo, deviceTypeHints *[]model.IndustrialDeviceType, roleHints *[]model.IndustrialDeviceRole, securityIndicators map[string]interface{}) {
	// EtherNet/IP analysis logic
	if protocol.Direction == "outbound" || protocol.Direction == "bidirectional" {
		// Device initiating EtherNet/IP connections - likely a controller or HMI
		*deviceTypeHints = append(*deviceTypeHints, model.DeviceTypePLC, model.DeviceTypeHMI)
		*roleHints = append(*roleHints, model.RoleController, model.RoleOperator)
	}

	if protocol.Direction == "inbound" {
		// Device accepting EtherNet/IP connections - likely an I/O device or sensor
		*deviceTypeHints = append(*deviceTypeHints, model.DeviceTypeIODevice, model.DeviceTypeSensor, model.DeviceTypeActuator)
		*roleHints = append(*roleHints, model.RoleFieldDevice)
	}

	// Check for implicit messaging (real-time I/O)
	if serviceType, ok := protocol.DeviceIdentity["service_type"]; ok {
		if serviceType == "implicit" {
			*deviceTypeHints = append(*deviceTypeHints, model.DeviceTypeIODevice)
			*roleHints = append(*roleHints, model.RoleFieldDevice)
		}
	}

	securityIndicators["ethernetip_detected"] = true
}

func (dc *DeviceClassifierImpl) analyzeOPCUAProtocol(protocol IndustrialProtocolInfo, deviceTypeHints *[]model.IndustrialDeviceType, roleHints *[]model.IndustrialDeviceRole, securityIndicators map[string]interface{}) {
	// OPC UA analysis logic
	if protocol.Direction == "outbound" || protocol.Direction == "bidirectional" {
		// Device initiating OPC UA connections - likely HMI, SCADA, or engineering workstation
		*deviceTypeHints = append(*deviceTypeHints, model.DeviceTypeHMI, model.DeviceTypeSCADA, model.DeviceTypeEngWorkstation)
		*roleHints = append(*roleHints, model.RoleOperator, model.RoleEngineer)
	}

	if protocol.Direction == "inbound" {
		// Device accepting OPC UA connections - likely PLC, historian, or server
		*deviceTypeHints = append(*deviceTypeHints, model.DeviceTypePLC, model.DeviceTypeHistorian)
		*roleHints = append(*roleHints, model.RoleController, model.RoleDataCollector)
	}

	// Check security policy
	if securityPolicy, ok := protocol.SecurityInfo["security_policy"]; ok {
		securityIndicators["opcua_security_policy"] = securityPolicy
		if securityPolicy != "None" {
			securityIndicators["encrypted_communication"] = true
		}
	}

	securityIndicators["opcua_detected"] = true
}

func (dc *DeviceClassifierImpl) analyzeModbusProtocol(protocol IndustrialProtocolInfo, deviceTypeHints *[]model.IndustrialDeviceType, roleHints *[]model.IndustrialDeviceRole, securityIndicators map[string]interface{}) {
	// Modbus analysis logic
	if protocol.Direction == "outbound" || protocol.Direction == "bidirectional" {
		// Device initiating Modbus connections - likely HMI, SCADA, or controller
		*deviceTypeHints = append(*deviceTypeHints, model.DeviceTypeHMI, model.DeviceTypeSCADA, model.DeviceTypePLC)
		*roleHints = append(*roleHints, model.RoleOperator, model.RoleController)
	}

	if protocol.Direction == "inbound" {
		// Device accepting Modbus connections - likely PLC or I/O device
		*deviceTypeHints = append(*deviceTypeHints, model.DeviceTypePLC, model.DeviceTypeIODevice)
		*roleHints = append(*roleHints, model.RoleController, model.RoleFieldDevice)
	}

	securityIndicators["modbus_detected"] = true
	securityIndicators["unencrypted_communication"] = true // Modbus is typically unencrypted
}

func (dc *DeviceClassifierImpl) analyzeCIFSBrowserProtocol(protocol IndustrialProtocolInfo, deviceTypeHints *[]model.IndustrialDeviceType, roleHints *[]model.IndustrialDeviceRole, securityIndicators map[string]interface{}) {
	// CIFS Browser analysis logic
	// CIFS Browser is used for Windows network discovery and sharing
	// Extract device type hints based on server type flags detected in CIFS Browser announcements

	// Check for CIFS Browser specific information in DeviceIdentity
	if protocol.DeviceIdentity != nil {
		// Device type classification from CIFS Browser data
		if deviceType, ok := protocol.DeviceIdentity["cifs_device_type"]; ok {
			if devType, isString := deviceType.(model.IndustrialDeviceType); isString {
				*deviceTypeHints = append(*deviceTypeHints, devType)
			}
		}

		// Role classification from CIFS Browser data
		if role, ok := protocol.DeviceIdentity["cifs_role"]; ok {
			if r, isString := role.(model.IndustrialDeviceRole); isString {
				*roleHints = append(*roleHints, r)
			}
		}

		// OS detection from CIFS Browser announcements
		if osType, ok := protocol.DeviceIdentity["detected_os"]; ok {
			securityIndicators["detected_os"] = osType
		}

		if osConf, ok := protocol.DeviceIdentity["os_confidence"]; ok {
			securityIndicators["os_confidence"] = osConf
		}
	}

	// General CIFS Browser protocol handling based on direction
	if protocol.Direction == "outbound" || protocol.Direction == "bidirectional" {
		// Device initiating CIFS Browser announcements - likely workstation or server
		*deviceTypeHints = append(*deviceTypeHints, model.DeviceTypeEngWorkstation)
		*roleHints = append(*roleHints, model.RoleOperator, model.RoleFieldDevice)
	}

	if protocol.Direction == "inbound" {
		// Device responding to CIFS Browser queries - likely server or domain controller
		*deviceTypeHints = append(*deviceTypeHints, model.DeviceTypeDomainController)
		*roleHints = append(*roleHints, model.RoleController)
	}

	// Record CIFS Browser protocol detection
	securityIndicators["cifs_browser_detected"] = true
	securityIndicators["windows_network_protocol"] = true
	securityIndicators["network_discovery_detected"] = true
}

func (dc *DeviceClassifierImpl) analyzeHTTPProtocol(protocol IndustrialProtocolInfo, deviceTypeHints *[]model.IndustrialDeviceType, roleHints *[]model.IndustrialDeviceRole, securityIndicators map[string]interface{}) {
	// HTTP/HTTPS analysis for web-based industrial interfaces
	if protocol.Direction == "outbound" {
		// Device making HTTP requests - likely HMI or engineering workstation
		*deviceTypeHints = append(*deviceTypeHints, model.DeviceTypeHMI, model.DeviceTypeEngWorkstation)
		*roleHints = append(*roleHints, model.RoleOperator, model.RoleEngineer)
	}

	if protocol.Direction == "inbound" {
		// Device serving HTTP - likely web-enabled PLC or HMI
		*deviceTypeHints = append(*deviceTypeHints, model.DeviceTypePLC, model.DeviceTypeHMI)
		*roleHints = append(*roleHints, model.RoleController)
	}

	if strings.ToUpper(protocol.Protocol) == "HTTPS" {
		securityIndicators["encrypted_web_communication"] = true
	} else {
		securityIndicators["unencrypted_web_communication"] = true
	}
}

// Helper methods for communication pattern analysis

func (dc *DeviceClassifierImpl) analyzeCommunicationForDeviceHints(pattern model.CommunicationPattern, deviceTypeHints *[]model.IndustrialDeviceType, roleHints *[]model.IndustrialDeviceRole) {
	// Analyze based on pattern type and criticality
	switch pattern.PatternType {
	case "periodic":
		if pattern.Criticality == "high" || pattern.Criticality == "critical" {
			// High-frequency periodic communication suggests control systems
			*deviceTypeHints = append(*deviceTypeHints, model.DeviceTypePLC, model.DeviceTypeIODevice)
			*roleHints = append(*roleHints, model.RoleController, model.RoleFieldDevice)
		}
	case "event-driven":
		// Event-driven communication suggests HMI or SCADA systems
		*deviceTypeHints = append(*deviceTypeHints, model.DeviceTypeHMI, model.DeviceTypeSCADA)
		*roleHints = append(*roleHints, model.RoleOperator)
	case "continuous":
		// Continuous communication suggests data collection or historian systems
		*deviceTypeHints = append(*deviceTypeHints, model.DeviceTypeHistorian)
		*roleHints = append(*roleHints, model.RoleDataCollector)
	}
}

func (dc *DeviceClassifierImpl) determineRelationshipType(periodicCount, eventDrivenCount, continuousCount int) string {
	total := periodicCount + eventDrivenCount + continuousCount
	if total == 0 {
		return "unknown"
	}

	// Determine dominant pattern
	if periodicCount > eventDrivenCount && periodicCount > continuousCount {
		return "producer-consumer"
	} else if eventDrivenCount > continuousCount {
		return "client-server"
	} else if continuousCount > 0 {
		return "peer-to-peer"
	}

	return "client-server" // Default
}

func (dc *DeviceClassifierImpl) determineCommunicationRole(inboundCount, outboundCount, bidirectionalCount int) string {
	if bidirectionalCount > 0 {
		return "both"
	} else if outboundCount > inboundCount {
		return "initiator"
	} else if inboundCount > outboundCount {
		return "responder"
	}
	return "unknown"
}

func (dc *DeviceClassifierImpl) determineDataFlowDirection(patterns []model.CommunicationPattern) string {
	// Simplified logic - could be enhanced based on actual data volume analysis
	if len(patterns) == 0 {
		return "unknown"
	}

	// For now, return bidirectional as most industrial communications are bidirectional
	return "bidirectional"
}

func (dc *DeviceClassifierImpl) determineCriticalityLevel(highCriticalityCount, mediumCriticalityCount, totalCount int) string {
	if totalCount == 0 {
		return "low"
	}

	// If all patterns are high/critical, return critical
	highRatio := float64(highCriticalityCount) / float64(totalCount)
	if highRatio >= 0.7 {
		return "critical"
	} else if highRatio >= 0.4 {
		return "high"
	}

	// If we have medium criticality patterns, consider them
	mediumRatio := float64(mediumCriticalityCount) / float64(totalCount)
	if mediumRatio >= 0.5 || (highRatio > 0 && mediumRatio > 0) {
		return "medium"
	} else if mediumRatio > 0 {
		return "medium"
	}

	return "low"
}

// Helper methods for device classification

func (dc *DeviceClassifierImpl) determineDeviceType(protocolAnalysis ProtocolAnalysisResult, commAnalysis CommunicationAnalysisResult) model.IndustrialDeviceType {
	// Combine hints from protocol and communication analysis
	allHints := append(protocolAnalysis.DeviceTypeHints, commAnalysis.DeviceTypeHints...)

	if len(allHints) == 0 {
		return model.DeviceTypeUnknown
	}

	// Count occurrences of each device type hint
	typeCounts := make(map[model.IndustrialDeviceType]int)
	for _, hint := range allHints {
		typeCounts[hint]++
	}

	// Find the most common device type
	var mostCommonType model.IndustrialDeviceType
	maxCount := 0
	for deviceType, count := range typeCounts {
		if count > maxCount {
			maxCount = count
			mostCommonType = deviceType
		}
	}

	return mostCommonType
}

func (dc *DeviceClassifierImpl) determineDeviceRole(protocolAnalysis ProtocolAnalysisResult, commAnalysis CommunicationAnalysisResult) model.IndustrialDeviceRole {
	// Combine hints from protocol and communication analysis
	allHints := append(protocolAnalysis.RoleHints, commAnalysis.RoleHints...)

	if len(allHints) == 0 {
		return model.RoleFieldDevice // Default role
	}

	// Count occurrences of each role hint
	roleCounts := make(map[model.IndustrialDeviceRole]int)
	for _, hint := range allHints {
		roleCounts[hint]++
	}

	// Find the most common role
	var mostCommonRole model.IndustrialDeviceRole
	maxCount := 0
	for role, count := range roleCounts {
		if count > maxCount {
			maxCount = count
			mostCommonRole = role
		}
	}

	return mostCommonRole
}

func (dc *DeviceClassifierImpl) determineSecurityLevel(deviceType model.IndustrialDeviceType, role model.IndustrialDeviceRole, protocolAnalysis ProtocolAnalysisResult) model.SecurityLevel {
	// Determine security level based on device type, role, and security indicators
	baseLevel := model.SecurityLevel1

	// Adjust based on device type
	switch deviceType {
	case model.DeviceTypePLC:
		baseLevel = model.SecurityLevel2 // PLCs typically need higher security
	case model.DeviceTypeHMI, model.DeviceTypeSCADA:
		baseLevel = model.SecurityLevel2 // Human interfaces need protection
	case model.DeviceTypeEngWorkstation:
		baseLevel = model.SecurityLevel3 // Engineering workstations are high-value targets
	case model.DeviceTypeHistorian:
		baseLevel = model.SecurityLevel2 // Data integrity is important
	case model.DeviceTypeIODevice, model.DeviceTypeSensor, model.DeviceTypeActuator:
		baseLevel = model.SecurityLevel1 // Field devices may have lower requirements
	}

	// Adjust based on security indicators
	if encrypted, ok := protocolAnalysis.SecurityIndicators["encrypted_communication"]; ok && encrypted.(bool) {
		// Encrypted communication suggests higher security awareness
		if baseLevel < model.SecurityLevel2 {
			baseLevel = model.SecurityLevel2
		}
	}

	if unencrypted, ok := protocolAnalysis.SecurityIndicators["unencrypted_communication"]; ok && unencrypted.(bool) {
		// Unencrypted communication may indicate lower security implementation
		// But don't lower below SL1
		if baseLevel > model.SecurityLevel1 {
			baseLevel = model.SecurityLevel1
		}
	}

	return baseLevel
}

func (dc *DeviceClassifierImpl) generateReasoning(deviceType model.IndustrialDeviceType, role model.IndustrialDeviceRole, protocolAnalysis ProtocolAnalysisResult, commAnalysis CommunicationAnalysisResult) string {
	reasoning := fmt.Sprintf("Classified as %s with role %s based on: ", deviceType, role)

	reasons := make([]string, 0)

	// Add protocol-based reasoning
	if len(protocolAnalysis.PrimaryProtocols) > 0 {
		reasons = append(reasons, fmt.Sprintf("industrial protocols detected (%s)", strings.Join(protocolAnalysis.PrimaryProtocols, ", ")))
	}

	// Add communication pattern reasoning
	if commAnalysis.RelationshipType != "unknown" {
		reasons = append(reasons, fmt.Sprintf("%s communication pattern", commAnalysis.RelationshipType))
	}

	if commAnalysis.CriticalityLevel != "low" {
		reasons = append(reasons, fmt.Sprintf("%s criticality communications", commAnalysis.CriticalityLevel))
	}

	// Add security reasoning
	if encrypted, ok := protocolAnalysis.SecurityIndicators["encrypted_communication"]; ok && encrypted.(bool) {
		reasons = append(reasons, "encrypted communications detected")
	}

	if len(reasons) == 0 {
		reasons = append(reasons, "limited protocol information available")
	}

	return reasoning + strings.Join(reasons, ", ")
}

// Helper methods for advanced confidence calculation

func (dc *DeviceClassifierImpl) calculateProtocolConfidence(protocols []IndustrialProtocolInfo, factors map[string]float64, uncertaintyReasons *[]string, recommendedActions *[]string, evidenceCount *int) float64 {
	if len(protocols) == 0 {
		factors["no_protocols"] = 0.0
		*uncertaintyReasons = append(*uncertaintyReasons, "No industrial protocols detected")
		*recommendedActions = append(*recommendedActions, "Verify network traffic contains industrial protocols")
		return 0.0
	}

	confidence := 0.0
	industrialProtocolCount := 0
	hasDeviceIdentity := false
	hasSecurityInfo := false

	for _, protocol := range protocols {
		*evidenceCount++

		switch strings.ToUpper(protocol.Protocol) {
		case "ETHERNETIP":
			confidence += 0.35
			industrialProtocolCount++
			factors["ethernetip_detected"] = 0.35
		case "OPCUA":
			confidence += 0.35
			industrialProtocolCount++
			factors["opcua_detected"] = 0.35
		case "MODBUS":
			confidence += 0.30
			industrialProtocolCount++
			factors["modbus_detected"] = 0.30
		case "PROFINET":
			confidence += 0.30
			industrialProtocolCount++
			factors["profinet_detected"] = 0.30
		case "DNP3":
			confidence += 0.25
			industrialProtocolCount++
			factors["dnp3_detected"] = 0.25
		case "HTTP", "HTTPS":
			confidence += 0.10
			factors["web_protocol_detected"] = 0.10
		default:
			confidence += 0.05
			factors["other_protocol_detected"] = 0.05
		}

		// Check for device identity information
		if len(protocol.DeviceIdentity) > 0 {
			hasDeviceIdentity = true
			confidence += 0.15
			factors["device_identity_available"] = 0.15
		}

		// Check for security information
		if len(protocol.SecurityInfo) > 0 {
			hasSecurityInfo = true
			confidence += 0.10
			factors["security_info_available"] = 0.10
		}
	}

	// Add uncertainty reasons based on missing information
	if industrialProtocolCount == 0 {
		*uncertaintyReasons = append(*uncertaintyReasons, "No industrial protocols detected")
	}
	if !hasDeviceIdentity {
		*uncertaintyReasons = append(*uncertaintyReasons, "No device identity information available")
	}
	if !hasSecurityInfo {
		*uncertaintyReasons = append(*uncertaintyReasons, "No security configuration information available")
	}

	// Multiple industrial protocols increase confidence
	if industrialProtocolCount > 1 {
		confidence += 0.10
		factors["multiple_industrial_protocols"] = 0.10
	}

	// Cap at 1.0
	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

func (dc *DeviceClassifierImpl) calculatePatternConfidence(patterns []model.CommunicationPattern, factors map[string]float64, uncertaintyReasons *[]string, recommendedActions *[]string, evidenceCount *int) float64 {
	if len(patterns) == 0 {
		factors["no_patterns"] = 0.0
		*uncertaintyReasons = append(*uncertaintyReasons, "No communication patterns detected")
		*recommendedActions = append(*recommendedActions, "Monitor network traffic over longer period")
		return 0.0
	}

	confidence := 0.0
	wellDefinedPatterns := 0
	criticalPatterns := 0
	periodicPatterns := 0

	for _, pattern := range patterns {
		*evidenceCount++

		// Well-defined patterns increase confidence
		if pattern.PatternType != "unknown" && pattern.PatternType != "" {
			wellDefinedPatterns++
			confidence += 0.15
		}

		// Critical patterns suggest important industrial devices
		if pattern.Criticality == "high" || pattern.Criticality == "critical" {
			criticalPatterns++
			confidence += 0.20
		}

		// Periodic patterns are common in industrial systems
		if pattern.PatternType == "periodic" {
			periodicPatterns++
			confidence += 0.10
		}
	}

	// Set confidence factors
	if wellDefinedPatterns > 0 {
		factors["well_defined_patterns"] = float64(wellDefinedPatterns) * 0.15
	}
	if criticalPatterns > 0 {
		factors["critical_patterns"] = float64(criticalPatterns) * 0.20
	}
	if periodicPatterns > 0 {
		factors["periodic_patterns"] = float64(periodicPatterns) * 0.10
	}

	// Add uncertainty reasons
	if wellDefinedPatterns == 0 {
		*uncertaintyReasons = append(*uncertaintyReasons, "No well-defined communication patterns")
	}
	if criticalPatterns == 0 {
		*uncertaintyReasons = append(*uncertaintyReasons, "No critical communication patterns detected")
	}

	// Multiple patterns increase confidence
	if len(patterns) > 3 {
		confidence += 0.10
		factors["multiple_patterns"] = 0.10
	}

	// Cap at 1.0
	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

func (dc *DeviceClassifierImpl) calculateIdentityConfidence(protocols []IndustrialProtocolInfo, factors map[string]float64, uncertaintyReasons *[]string, recommendedActions *[]string, evidenceCount *int) float64 {
	confidence := 0.0
	hasVendorInfo := false
	hasProductInfo := false
	hasVersionInfo := false
	hasSerialNumber := false

	for _, protocol := range protocols {
		if len(protocol.DeviceIdentity) > 0 {
			*evidenceCount++

			// Check for specific identity fields
			if vendor, ok := protocol.DeviceIdentity["vendor"]; ok && vendor != "" {
				hasVendorInfo = true
				confidence += 0.25
			}
			if product, ok := protocol.DeviceIdentity["product_name"]; ok && product != "" {
				hasProductInfo = true
				confidence += 0.25
			}
			if version, ok := protocol.DeviceIdentity["firmware_version"]; ok && version != "" {
				hasVersionInfo = true
				confidence += 0.20
			}
			if serial, ok := protocol.DeviceIdentity["serial_number"]; ok && serial != "" {
				hasSerialNumber = true
				confidence += 0.30
			}
		}
	}

	// Set confidence factors
	if hasVendorInfo {
		factors["vendor_info_available"] = 0.25
	}
	if hasProductInfo {
		factors["product_info_available"] = 0.25
	}
	if hasVersionInfo {
		factors["version_info_available"] = 0.20
	}
	if hasSerialNumber {
		factors["serial_number_available"] = 0.30
	}

	// Add uncertainty reasons for missing identity information
	if !hasVendorInfo {
		*uncertaintyReasons = append(*uncertaintyReasons, "No vendor information available")
	}
	if !hasProductInfo {
		*uncertaintyReasons = append(*uncertaintyReasons, "No product information available")
	}
	if !hasVersionInfo {
		*uncertaintyReasons = append(*uncertaintyReasons, "No firmware version information available")
	}

	// Cap at 1.0
	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

func (dc *DeviceClassifierImpl) calculateConsistencyScore(protocols []IndustrialProtocolInfo, patterns []model.CommunicationPattern, factors map[string]float64, uncertaintyReasons *[]string) float64 {
	if len(protocols) == 0 && len(patterns) == 0 {
		return 0.0
	}

	consistency := 1.0 // Start with perfect consistency

	// Check for conflicting protocol evidence
	hasClientProtocols := false
	hasServerProtocols := false

	for _, protocol := range protocols {
		if protocol.Direction == "outbound" {
			hasClientProtocols = true
		}
		if protocol.Direction == "inbound" {
			hasServerProtocols = true
		}
	}

	// Devices can be both client and server, but check for unusual combinations
	if hasClientProtocols && hasServerProtocols {
		// This is actually normal for many industrial devices
		factors["bidirectional_communication"] = 0.05
	}

	// Check for consistency between protocols and patterns
	industrialProtocolCount := 0
	for _, protocol := range protocols {
		switch strings.ToUpper(protocol.Protocol) {
		case "ETHERNETIP", "OPCUA", "MODBUS", "PROFINET", "DNP3":
			industrialProtocolCount++
		}
	}

	criticalPatternCount := 0
	for _, pattern := range patterns {
		if pattern.Criticality == "high" || pattern.Criticality == "critical" {
			criticalPatternCount++
		}
	}

	// Industrial protocols should correlate with critical patterns
	if industrialProtocolCount > 0 && criticalPatternCount == 0 {
		consistency -= 0.2
		*uncertaintyReasons = append(*uncertaintyReasons, "Industrial protocols detected but no critical communication patterns")
	}

	if industrialProtocolCount == 0 && criticalPatternCount > 0 {
		consistency -= 0.1
		*uncertaintyReasons = append(*uncertaintyReasons, "Critical patterns detected but no industrial protocols")
	}

	// Ensure consistency is not negative
	if consistency < 0.0 {
		consistency = 0.0
	}

	factors["consistency_score"] = consistency
	return consistency
}

func (dc *DeviceClassifierImpl) calculateEvidenceBonus(evidenceCount int) float64 {
	// Bonus/penalty based on amount of evidence
	switch {
	case evidenceCount >= 10:
		return 1.1 // 10% bonus for lots of evidence
	case evidenceCount >= 5:
		return 1.05 // 5% bonus for good amount of evidence
	case evidenceCount >= 3:
		return 1.0 // No bonus/penalty
	case evidenceCount >= 1:
		return 0.9 // 10% penalty for limited evidence
	default:
		return 0.7 // 30% penalty for no evidence
	}
}

// ValidateClassification validates a device classification and returns validation result
func (dc *DeviceClassifierImpl) ValidateClassification(classification IndustrialDeviceClassification) ValidationResult {
	validationErrors := make([]string, 0)
	criticalErrors := make([]string, 0)
	warnings := make([]string, 0)
	validationScore := 1.0

	// Validate device type
	if !dc.isValidDeviceType(classification.DeviceType) {
		criticalErrors = append(criticalErrors, fmt.Sprintf("Invalid device type: %s", classification.DeviceType))
		validationScore -= 0.3
	}

	// Validate device role
	if !dc.isValidDeviceRole(classification.Role) {
		criticalErrors = append(criticalErrors, fmt.Sprintf("Invalid device role: %s", classification.Role))
		validationScore -= 0.3
	}

	// Validate confidence score
	if classification.Confidence < 0.0 || classification.Confidence > 1.0 {
		criticalErrors = append(criticalErrors, fmt.Sprintf("Invalid confidence score: %f (must be between 0.0 and 1.0)", classification.Confidence))
		validationScore -= 0.2
	}

	// Validate security level
	if !dc.isValidSecurityLevel(classification.SecurityLevel) {
		criticalErrors = append(criticalErrors, fmt.Sprintf("Invalid security level: %d", classification.SecurityLevel))
		validationScore -= 0.2
	}

	// Validate timestamp
	if classification.LastUpdated.IsZero() {
		validationErrors = append(validationErrors, "Last updated timestamp is zero")
		validationScore -= 0.1
	} else if classification.LastUpdated.After(time.Now().Add(time.Hour)) {
		warnings = append(warnings, "Last updated timestamp is in the future")
		validationScore -= 0.05
	}

	// Validate protocol consistency
	if len(classification.Protocols) == 0 {
		warnings = append(warnings, "No protocols specified for device classification")
		validationScore -= 0.1
	}

	// Validate device type and role consistency
	if !dc.isConsistentDeviceTypeAndRole(classification.DeviceType, classification.Role) {
		warnings = append(warnings, fmt.Sprintf("Device type %s and role %s may be inconsistent", classification.DeviceType, classification.Role))
		validationScore -= 0.1
	}

	// Validate confidence level appropriateness
	if classification.Confidence < 0.3 && classification.DeviceType != model.DeviceTypeUnknown {
		warnings = append(warnings, "Low confidence score for specific device type classification")
		validationScore -= 0.05
	}

	// Validate security level appropriateness for device type
	if !dc.isAppropriateSecurityLevel(classification.DeviceType, classification.SecurityLevel) {
		warnings = append(warnings, fmt.Sprintf("Security level %d may be inappropriate for device type %s", classification.SecurityLevel, classification.DeviceType))
		validationScore -= 0.05
	}

	// Ensure validation score is not negative
	if validationScore < 0.0 {
		validationScore = 0.0
	}

	isValid := len(criticalErrors) == 0

	return ValidationResult{
		IsValid:          isValid,
		ValidationErrors: validationErrors,
		ValidationScore:  validationScore,
		CriticalErrors:   criticalErrors,
		Warnings:         warnings,
	}
}

// GetUncertaintyIndicators returns uncertainty indicators for low-confidence classifications
func (dc *DeviceClassifierImpl) GetUncertaintyIndicators(classification IndustrialDeviceClassification) UncertaintyIndicators {
	confidenceThreshold := 0.6 // Threshold for considering classification as low confidence
	hasLowConfidence := classification.Confidence < confidenceThreshold

	uncertaintyLevel := dc.determineUncertaintyLevel(classification.Confidence)
	missingEvidence := dc.identifyMissingEvidence(classification)
	conflictingEvidence := dc.identifyConflictingEvidence(classification)
	requiresManualReview := dc.shouldRequireManualReview(classification)
	suggestedActions := dc.generateSuggestedActions(classification, missingEvidence)

	return UncertaintyIndicators{
		HasLowConfidence:     hasLowConfidence,
		ConfidenceThreshold:  confidenceThreshold,
		UncertaintyLevel:     uncertaintyLevel,
		MissingEvidence:      missingEvidence,
		ConflictingEvidence:  conflictingEvidence,
		RequiresManualReview: requiresManualReview,
		SuggestedActions:     suggestedActions,
	}
}

// Helper methods for validation

func (dc *DeviceClassifierImpl) isValidDeviceType(deviceType model.IndustrialDeviceType) bool {
	validTypes := []model.IndustrialDeviceType{
		model.DeviceTypePLC,
		model.DeviceTypeHMI,
		model.DeviceTypeSCADA,
		model.DeviceTypeHistorian,
		model.DeviceTypeEngWorkstation,
		model.DeviceTypeIODevice,
		model.DeviceTypeSensor,
		model.DeviceTypeActuator,
		model.DeviceTypeUnknown,
	}

	for _, validType := range validTypes {
		if deviceType == validType {
			return true
		}
	}
	return false
}

func (dc *DeviceClassifierImpl) isValidDeviceRole(role model.IndustrialDeviceRole) bool {
	validRoles := []model.IndustrialDeviceRole{
		model.RoleController,
		model.RoleOperator,
		model.RoleEngineer,
		model.RoleDataCollector,
		model.RoleFieldDevice,
	}

	for _, validRole := range validRoles {
		if role == validRole {
			return true
		}
	}
	return false
}

func (dc *DeviceClassifierImpl) isValidSecurityLevel(level model.SecurityLevel) bool {
	return level >= model.SecurityLevelUnknown && level <= model.SecurityLevel4
}

func (dc *DeviceClassifierImpl) isConsistentDeviceTypeAndRole(deviceType model.IndustrialDeviceType, role model.IndustrialDeviceRole) bool {
	// Define consistent combinations
	consistentCombinations := map[model.IndustrialDeviceType][]model.IndustrialDeviceRole{
		model.DeviceTypePLC:            {model.RoleController},
		model.DeviceTypeHMI:            {model.RoleOperator, model.RoleEngineer},
		model.DeviceTypeSCADA:          {model.RoleOperator, model.RoleDataCollector},
		model.DeviceTypeHistorian:      {model.RoleDataCollector},
		model.DeviceTypeEngWorkstation: {model.RoleEngineer},
		model.DeviceTypeIODevice:       {model.RoleFieldDevice},
		model.DeviceTypeSensor:         {model.RoleFieldDevice},
		model.DeviceTypeActuator:       {model.RoleFieldDevice},
		model.DeviceTypeUnknown:        {model.RoleController, model.RoleOperator, model.RoleEngineer, model.RoleDataCollector, model.RoleFieldDevice},
	}

	validRoles, exists := consistentCombinations[deviceType]
	if !exists {
		return false
	}

	for _, validRole := range validRoles {
		if role == validRole {
			return true
		}
	}
	return false
}

func (dc *DeviceClassifierImpl) isAppropriateSecurityLevel(deviceType model.IndustrialDeviceType, level model.SecurityLevel) bool {
	// Define appropriate security levels for each device type
	appropriateLevels := map[model.IndustrialDeviceType][]model.SecurityLevel{
		model.DeviceTypePLC:            {model.SecurityLevel2, model.SecurityLevel3, model.SecurityLevel4},
		model.DeviceTypeHMI:            {model.SecurityLevel1, model.SecurityLevel2, model.SecurityLevel3},
		model.DeviceTypeSCADA:          {model.SecurityLevel2, model.SecurityLevel3, model.SecurityLevel4},
		model.DeviceTypeHistorian:      {model.SecurityLevel2, model.SecurityLevel3},
		model.DeviceTypeEngWorkstation: {model.SecurityLevel3, model.SecurityLevel4},
		model.DeviceTypeIODevice:       {model.SecurityLevel1, model.SecurityLevel2},
		model.DeviceTypeSensor:         {model.SecurityLevel1, model.SecurityLevel2},
		model.DeviceTypeActuator:       {model.SecurityLevel1, model.SecurityLevel2},
		model.DeviceTypeUnknown:        {model.SecurityLevelUnknown, model.SecurityLevel1, model.SecurityLevel2, model.SecurityLevel3, model.SecurityLevel4},
	}

	validLevels, exists := appropriateLevels[deviceType]
	if !exists {
		return false
	}

	for _, validLevel := range validLevels {
		if level == validLevel {
			return true
		}
	}
	return false
}

// Helper methods for uncertainty indicators

func (dc *DeviceClassifierImpl) determineUncertaintyLevel(confidence float64) string {
	switch {
	case confidence >= 0.8:
		return "low"
	case confidence >= 0.5:
		return "medium"
	default:
		return "high"
	}
}

func (dc *DeviceClassifierImpl) identifyMissingEvidence(classification IndustrialDeviceClassification) []string {
	missing := make([]string, 0)

	// Check for missing protocol evidence
	if len(classification.Protocols) == 0 {
		missing = append(missing, "industrial_protocols")
	}

	// Check for missing industrial protocols
	hasIndustrialProtocol := false
	for _, protocol := range classification.Protocols {
		switch strings.ToUpper(protocol) {
		case "ETHERNETIP", "OPCUA", "MODBUS", "PROFINET", "DNP3":
			hasIndustrialProtocol = true
			break
		}
	}
	if !hasIndustrialProtocol {
		missing = append(missing, "industrial_protocol_evidence")
	}

	// Check for missing device identity
	if classification.DeviceType == model.DeviceTypeUnknown {
		missing = append(missing, "device_identity_information")
	}

	// Check for missing security information
	if classification.SecurityLevel == model.SecurityLevelUnknown {
		missing = append(missing, "security_configuration")
	}

	// Check for missing communication patterns
	if classification.Confidence < 0.4 {
		missing = append(missing, "communication_patterns")
	}

	return missing
}

func (dc *DeviceClassifierImpl) identifyConflictingEvidence(classification IndustrialDeviceClassification) []string {
	conflicting := make([]string, 0)

	// Check for conflicting device type and security level
	if !dc.isAppropriateSecurityLevel(classification.DeviceType, classification.SecurityLevel) {
		conflicting = append(conflicting, "device_type_security_level_mismatch")
	}

	// Check for conflicting device type and role
	if !dc.isConsistentDeviceTypeAndRole(classification.DeviceType, classification.Role) {
		conflicting = append(conflicting, "device_type_role_mismatch")
	}

	// Check for conflicting confidence and classification specificity
	if classification.Confidence < 0.3 && classification.DeviceType != model.DeviceTypeUnknown {
		conflicting = append(conflicting, "low_confidence_specific_classification")
	}

	return conflicting
}

func (dc *DeviceClassifierImpl) shouldRequireManualReview(classification IndustrialDeviceClassification) bool {
	// Require manual review for very low confidence
	if classification.Confidence < 0.3 {
		return true
	}

	// Require manual review for conflicting evidence
	conflicting := dc.identifyConflictingEvidence(classification)
	if len(conflicting) > 1 {
		return true
	}

	// Require manual review for critical devices with low confidence
	criticalDeviceTypes := []model.IndustrialDeviceType{
		model.DeviceTypePLC,
		model.DeviceTypeSCADA,
		model.DeviceTypeEngWorkstation,
	}

	for _, criticalType := range criticalDeviceTypes {
		if classification.DeviceType == criticalType && classification.Confidence < 0.6 {
			return true
		}
	}

	return false
}

func (dc *DeviceClassifierImpl) generateSuggestedActions(classification IndustrialDeviceClassification, missingEvidence []string) []string {
	actions := make([]string, 0)

	// Actions based on missing evidence
	for _, missing := range missingEvidence {
		switch missing {
		case "industrial_protocols":
			actions = append(actions, "Enable industrial protocol monitoring")
		case "industrial_protocol_evidence":
			actions = append(actions, "Verify industrial protocol configuration")
		case "device_identity_information":
			actions = append(actions, "Collect device identity information through protocol analysis")
		case "security_configuration":
			actions = append(actions, "Analyze security configuration and encryption usage")
		case "communication_patterns":
			actions = append(actions, "Monitor communication patterns over extended period")
		}
	}

	// Actions based on confidence level
	if classification.Confidence < 0.5 {
		actions = append(actions, "Collect additional network traffic data")
		actions = append(actions, "Verify device configuration manually")
	}

	// Actions based on device type
	if classification.DeviceType == model.DeviceTypeUnknown {
		actions = append(actions, "Perform active device discovery")
		actions = append(actions, "Check device documentation and configuration")
	}

	// Remove duplicates
	uniqueActions := make([]string, 0)
	seen := make(map[string]bool)
	for _, action := range actions {
		if !seen[action] {
			uniqueActions = append(uniqueActions, action)
			seen[action] = true
		}
	}

	return uniqueActions
}

// AnalyzePeriodicCommunication detects and analyzes periodic communication patterns (Requirement 5.3)
func (dc *DeviceClassifierImpl) AnalyzePeriodicCommunication(flows []model.Flow) []PeriodicPattern {
	return dc.patternAnalyzer.AnalyzePeriodicPatterns(flows)
}

// AnalyzeRequestResponsePatterns identifies request-response patterns and determines criticality (Requirement 5.4)
func (dc *DeviceClassifierImpl) AnalyzeRequestResponsePatterns(flows []model.Flow) []RequestResponsePattern {
	return dc.patternAnalyzer.AnalyzeRequestResponsePatterns(flows)
}

// UpdateClassificationFromPatternChanges updates device classifications based on pattern changes (Requirement 5.5)
func (dc *DeviceClassifierImpl) UpdateClassificationFromPatternChanges(deviceID string, oldPatterns, newPatterns []model.CommunicationPattern) (IndustrialDeviceClassification, error) {
	// Detect pattern changes
	changes := dc.patternAnalyzer.DetectPatternChanges(oldPatterns, newPatterns)

	if len(changes) == 0 {
		return IndustrialDeviceClassification{}, fmt.Errorf("no significant pattern changes detected for device %s", deviceID)
	}

	// Update classification based on pattern changes
	return dc.patternAnalyzer.UpdateDeviceClassificationFromPatterns(deviceID, changes)
}

// DetermineCommunicationCriticality calculates criticality levels based on pattern analysis
func (dc *DeviceClassifierImpl) DetermineCommunicationCriticality(patterns []model.CommunicationPattern) CriticalityAssessment {
	return dc.patternAnalyzer.DetermineCommunicationCriticality(patterns)
}

// DetectPatternChanges identifies changes in communication patterns over time
func (dc *DeviceClassifierImpl) DetectPatternChanges(oldPatterns, newPatterns []model.CommunicationPattern) []PatternChange {
	return dc.patternAnalyzer.DetectPatternChanges(oldPatterns, newPatterns)
}
