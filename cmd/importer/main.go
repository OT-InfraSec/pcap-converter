package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/InfraSecConsult/pcap-importer-go/internal/dns"
	"github.com/InfraSecConsult/pcap-importer-go/internal/parser"
	"github.com/InfraSecConsult/pcap-importer-go/internal/repository"
	"github.com/InfraSecConsult/pcap-importer-go/internal/version"
	"github.com/InfraSecConsult/pcap-importer-go/lib/model"

	"github.com/spf13/cobra"
)

// DependencyProvider allows injection for testability
// (in production, use real implementations)
type DependencyProvider struct {
	Parser       parser.PacketParser
	Repository   repository.Repository
	DNSProcessor dns.DNSProcessor
}

// newRootCmd wires up the CLI with the given dependencies
func newRootCmd(provider *DependencyProvider) *cobra.Command {
	var (
		dbPath                   string
		batchSize                int
		clearDB                  bool
		enableIndustrialAnalysis bool
		outputFormat             string
		tenantID                 string
	)

	rootCmd := &cobra.Command{
		Use:   "importer",
		Short: "PCAP Importer - Import packet capture files into a database",
	}

	importCmd := &cobra.Command{
		Use:   "import <pcap-file>",
		Short: "Import packets from a PCAP file into the database",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pcapFile := args[0]

			if clearDB {
				log.Printf("Clearing database at %s before import", dbPath)
				err := os.Remove(dbPath) // Remove the database file if it exists
				if err != nil && !os.IsNotExist(err) {
					log.Printf("Failed to clear database: %v", err)
					return err
				}
			} else {
				log.Printf("Using existing database at %s", dbPath)
			}

			// If not injected, use real implementations
			if provider.Parser == nil || provider.Repository == nil || provider.DNSProcessor == nil {
				repo, err := repository.NewSQLiteRepository(dbPath)
				if err != nil {
					return fmt.Errorf("failed to open database: %w", err)
				}
				log.Printf("Using database at %s", dbPath)
				provider.Repository = repo
				provider.Parser = parser.NewGopacketParser(pcapFile, repo, tenantID)
				// TODO: Replace with real DNS processor implementation
				provider.DNSProcessor = &dns.NoopDNSProcessor{}
			}

			startTime := time.Now()
			if err := provider.Parser.ParseFile(); err != nil {
				return err
			}
			log.Printf("Packet parsing completed, processing DNS records...")
			// FIXME: not restricting to tenantID here
			if err := provider.DNSProcessor.Process(provider.Repository); err != nil {
				return err
			}
			log.Printf("DNS processing completed")

			// Perform industrial device analysis if enabled
			if enableIndustrialAnalysis {
				log.Printf("Performing industrial device analysis...")
				if err := performIndustrialAnalysis(provider.Repository); err != nil {
					log.Printf("Industrial analysis failed: %v", err)
					// Don't fail the entire import, just log the error
				}
			}
			log.Printf("Finalizing database operations...")

			// Store the application version in the database
			appVersion := version.GetVersion()
			if err := provider.Repository.SetKeyValue("version", appVersion); err != nil {
				log.Printf("Warning: Failed to store version in database: %v", err)
				// Don't fail the import, just log the warning
			} else {
				log.Printf("Stored version %s in database", appVersion)
			}

			if err := provider.Repository.Commit(); err != nil {
				return err
			}
			if err := provider.Repository.Close(); err != nil {
				return err
			}
			duration := time.Since(startTime)
			log.Printf("Imported packets from %s in %s", pcapFile, duration)
			return nil
		},
	}
	importCmd.Flags().StringVar(&dbPath, "db-path", "database.sqlite", "Path to the SQLite database file")
	importCmd.Flags().IntVar(&batchSize, "batch-size", 1000, "Number of packets to import in each batch")
	importCmd.Flags().BoolVar(&clearDB, "clear", false, "Clear the database before importing")
	importCmd.Flags().BoolVar(&enableIndustrialAnalysis, "industrial", false, "Enable industrial protocol analysis and device classification")
	importCmd.Flags().StringVar(&tenantID, "tenant-id", "", "Tenant ID to associate with all imported data")

	// Industrial device analysis commands
	industrialCmd := &cobra.Command{
		Use:   "industrial",
		Short: "Industrial device analysis and reporting commands",
	}

	listDevicesCmd := &cobra.Command{
		Use:   "list-devices",
		Short: "List all industrial devices with their classifications",
		RunE: func(cmd *cobra.Command, args []string) error {
			return listIndustrialDevices(dbPath, outputFormat)
		},
	}
	listDevicesCmd.Flags().StringVar(&dbPath, "db-path", "database.sqlite", "Path to the SQLite database file")
	listDevicesCmd.Flags().StringVar(&outputFormat, "format", "table", "Output format: table, json, csv")

	devicesByTypeCmd := &cobra.Command{
		Use:   "devices-by-type <device-type>",
		Short: "List industrial devices by type (PLC, HMI, SCADA, etc.)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			deviceType := model.IndustrialDeviceType(args[0])
			return listIndustrialDevicesByType(dbPath, deviceType, outputFormat)
		},
	}
	devicesByTypeCmd.Flags().StringVar(&dbPath, "db-path", "database.sqlite", "Path to the SQLite database file")
	devicesByTypeCmd.Flags().StringVar(&outputFormat, "format", "table", "Output format: table, json, csv")

	protocolStatsCmd := &cobra.Command{
		Use:   "protocol-stats [device-address]",
		Short: "Show protocol usage statistics for all devices or a specific device",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var deviceAddress string
			if len(args) > 0 {
				deviceAddress = args[0]
			}
			return showProtocolStats(dbPath, deviceAddress, outputFormat)
		},
	}
	protocolStatsCmd.Flags().StringVar(&dbPath, "db-path", "database.sqlite", "Path to the SQLite database file")
	protocolStatsCmd.Flags().StringVar(&outputFormat, "format", "table", "Output format: table, json, csv")

	communicationPatternsCmd := &cobra.Command{
		Use:   "communication-patterns [device-address]",
		Short: "Show communication patterns for all devices or a specific device",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var deviceAddress string
			if len(args) > 0 {
				deviceAddress = args[0]
			}
			return showCommunicationPatterns(dbPath, deviceAddress, outputFormat)
		},
	}
	communicationPatternsCmd.Flags().StringVar(&dbPath, "db-path", "database.sqlite", "Path to the SQLite database file")
	communicationPatternsCmd.Flags().StringVar(&outputFormat, "format", "table", "Output format: table, json, csv")

	summaryCmd := &cobra.Command{
		Use:   "summary",
		Short: "Show industrial network analysis summary",
		RunE: func(cmd *cobra.Command, args []string) error {
			return showIndustrialSummary(dbPath, outputFormat)
		},
	}
	summaryCmd.Flags().StringVar(&dbPath, "db-path", "database.sqlite", "Path to the SQLite database file")
	summaryCmd.Flags().StringVar(&outputFormat, "format", "table", "Output format: table, json")

	industrialCmd.AddCommand(listDevicesCmd, devicesByTypeCmd, protocolStatsCmd, communicationPatternsCmd, summaryCmd)
	rootCmd.AddCommand(importCmd, industrialCmd)
	return rootCmd
}

// performIndustrialAnalysis performs industrial device analysis on imported data
func performIndustrialAnalysis(repo repository.Repository) error {
	log.Printf("Starting industrial device analysis...")

	// Create industrial protocol parser
	industrialParser := parser.NewIndustrialProtocolParser()

	// Get all flows to analyze for industrial protocols
	flows, err := repo.GetFlows("", make(map[string]interface{}))
	if err != nil {
		return fmt.Errorf("failed to get flows for industrial analysis: %w", err)
	}

	log.Printf("Analyzing %d flows for industrial protocols...", len(flows))

	// Process flows to extract industrial protocol information
	deviceProtocols := make(map[string][]model.IndustrialProtocolInfo)

	for _, flow := range flows {
		// Simulate packet analysis for industrial protocols
		// In a real implementation, this would analyze actual packets
		protocols := analyzeFlowForIndustrialProtocols(flow)

		// Group by source device
		if len(protocols) > 0 {
			srcAddr := flow.SrcIP.String()
			deviceProtocols[srcAddr] = append(deviceProtocols[srcAddr], protocols...)
		}
	}

	log.Printf("Found industrial protocols in %d devices", len(deviceProtocols))

	// Perform device classification and save results
	for deviceAddr, protocols := range deviceProtocols {
		// Convert flows slice for device classification
		flowsForDevice := make([]model.Flow, len(flows))
		for i, flow := range flows {
			flowsForDevice[i] = *flow
		}

		// Classify device type based on protocol usage
		deviceType := industrialParser.DetectDeviceType(protocols, flowsForDevice)

		// Create industrial device info
		deviceInfo := &model.IndustrialDeviceInfo{
			DeviceAddress: deviceAddr,
			DeviceType:    deviceType,
			Role:          determineDeviceRole(deviceType, protocols),
			Confidence:    calculateConfidence(protocols),
			Protocols:     extractProtocolNames(protocols),
			SecurityLevel: model.SecurityLevelUnknown, // Would be determined from security analysis
			LastSeen:      time.Now(),
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}

		// Save device info
		if err := repo.UpsertIndustrialDeviceInfo(deviceInfo); err != nil {
			log.Printf("Failed to save device info for %s: %v", deviceAddr, err)
			continue
		}

		// Generate and save protocol usage statistics
		stats, err := industrialParser.CollectProtocolUsageStats(deviceAddr, protocols)
		if err != nil {
			log.Printf("Failed to collect protocol stats for %s: %v", deviceAddr, err)
			continue
		}

		if err := repo.UpsertProtocolUsageStats(stats); err != nil {
			log.Printf("Failed to save protocol stats for %s: %v", deviceAddr, err)
		}

		// Save individual protocol info entries
		protocolInfos := make([]*model.IndustrialProtocolInfo, len(protocols))
		for i := range protocols {
			protocolInfos[i] = &protocols[i]
		}

		if err := repo.SaveIndustrialProtocolInfos(protocolInfos); err != nil {
			log.Printf("Failed to save protocol infos for %s: %v", deviceAddr, err)
		}
	}

	// Analyze communication patterns
	flowsForAnalysis := make([]model.Flow, len(flows))
	for i, flow := range flows {
		flowsForAnalysis[i] = *flow
	}
	patterns := industrialParser.AnalyzeCommunicationPatterns(flowsForAnalysis)

	// Convert patterns to pointer slice
	patternPtrs := make([]*model.CommunicationPattern, len(patterns))
	for i := range patterns {
		patternPtrs[i] = &patterns[i]
	}

	if err := repo.SaveCommunicationPatterns(patternPtrs); err != nil {
		log.Printf("Failed to save communication patterns: %v", err)
	}

	log.Printf("Industrial analysis completed successfully")
	return nil
}

// listIndustrialDevices lists all industrial devices with their classifications
func listIndustrialDevices(dbPath, format string) error {
	repo, err := repository.NewSQLiteRepository(dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer repo.Close()

	// Get all industrial device types
	allTypes := []model.IndustrialDeviceType{
		model.DeviceTypePLC, model.DeviceTypeHMI, model.DeviceTypeSCADA,
		model.DeviceTypeHistorian, model.DeviceTypeEngWorkstation,
		model.DeviceTypeIODevice, model.DeviceTypeSensor, model.DeviceTypeActuator,
	}

	var allDevices []*model.IndustrialDeviceInfo
	for _, deviceType := range allTypes {
		devices, err := repo.GetIndustrialDevicesByType("", deviceType)
		if err != nil {
			continue // Skip errors for missing data
		}
		allDevices = append(allDevices, devices...)
	}

	return formatIndustrialDevices(allDevices, format)
}

// listIndustrialDevicesByType lists industrial devices by specific type
func listIndustrialDevicesByType(dbPath string, deviceType model.IndustrialDeviceType, format string) error {
	// Validate device type
	validTypes := []model.IndustrialDeviceType{
		model.DeviceTypePLC, model.DeviceTypeHMI, model.DeviceTypeSCADA,
		model.DeviceTypeHistorian, model.DeviceTypeEngWorkstation,
		model.DeviceTypeIODevice, model.DeviceTypeSensor, model.DeviceTypeActuator,
		model.DeviceTypeUnknown,
	}

	isValid := false
	for _, validType := range validTypes {
		if deviceType == validType {
			isValid = true
			break
		}
	}

	if !isValid {
		return fmt.Errorf("invalid device type: %s. Valid types are: PLC, HMI, SCADA, Historian, EngineeringWorkstation, IODevice, Sensor, Actuator, Unknown", deviceType)
	}

	repo, err := repository.NewSQLiteRepository(dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer repo.Close()

	devices, err := repo.GetIndustrialDevicesByType("", deviceType)
	if err != nil {
		return fmt.Errorf("failed to get devices by type: %w", err)
	}

	return formatIndustrialDevices(devices, format)
}

// showProtocolStats shows protocol usage statistics
func showProtocolStats(dbPath, deviceAddress, format string) error {
	repo, err := repository.NewSQLiteRepository(dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer repo.Close()

	var stats []*model.ProtocolUsageStats
	if deviceAddress != "" {
		stats, err = repo.GetProtocolUsageStats("", deviceAddress)
		if err != nil {
			return fmt.Errorf("failed to get protocol stats for device: %w", err)
		}
	} else {
		// Get stats for all protocols (this would need a new repository method in full implementation)
		fmt.Printf("Protocol statistics for all devices not yet implemented\n")
		return nil
	}

	return formatProtocolStats(stats, format)
}

// showCommunicationPatterns shows communication patterns
func showCommunicationPatterns(dbPath, deviceAddress, format string) error {
	repo, err := repository.NewSQLiteRepository(dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer repo.Close()

	var patterns []*model.CommunicationPattern
	if deviceAddress != "" {
		patterns, err = repo.GetCommunicationPatterns("", deviceAddress)
		if err != nil {
			return fmt.Errorf("failed to get communication patterns for device: %w", err)
		}
	} else {
		// Get patterns for all devices (this would need a new repository method in full implementation)
		fmt.Printf("Communication patterns for all devices not yet implemented\n")
		return nil
	}

	return formatCommunicationPatterns(patterns, format)
}

// showIndustrialSummary shows a summary of industrial network analysis
func showIndustrialSummary(dbPath, format string) error {
	repo, err := repository.NewSQLiteRepository(dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer repo.Close()

	summary := make(map[string]interface{})

	// Count devices by type
	deviceCounts := make(map[string]int)
	allTypes := []model.IndustrialDeviceType{
		model.DeviceTypePLC, model.DeviceTypeHMI, model.DeviceTypeSCADA,
		model.DeviceTypeHistorian, model.DeviceTypeEngWorkstation,
		model.DeviceTypeIODevice, model.DeviceTypeSensor, model.DeviceTypeActuator,
	}

	totalDevices := 0
	for _, deviceType := range allTypes {
		devices, err := repo.GetIndustrialDevicesByType("", deviceType)
		if err != nil {
			continue
		}
		count := len(devices)
		deviceCounts[string(deviceType)] = count
		totalDevices += count
	}

	summary["total_industrial_devices"] = totalDevices
	summary["devices_by_type"] = deviceCounts
	summary["timestamp"] = time.Now().Format(time.RFC3339)

	return formatSummary(summary, format)
}

// formatIndustrialDevices formats industrial device information for output
func formatIndustrialDevices(devices []*model.IndustrialDeviceInfo, format string) error {
	switch format {
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(devices)
	case "csv":
		fmt.Printf("Address,Type,Role,Confidence,Protocols,SecurityLevel,Vendor,Product,LastSeen\n")
		for _, device := range devices {
			protocols := strings.Join(device.Protocols, ";")
			fmt.Printf("%s,%s,%s,%.2f,%s,%d,%s,%s,%s\n",
				device.DeviceAddress, device.DeviceType, device.Role,
				device.Confidence, protocols, device.SecurityLevel,
				device.Vendor, device.ProductName, device.LastSeen.Format(time.RFC3339))
		}
	default: // table
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "ADDRESS\tTYPE\tROLE\tCONFIDENCE\tPROTOCOLS\tSECURITY LEVEL\tVENDOR\tPRODUCT\tLAST SEEN\n")
		for _, device := range devices {
			protocols := strings.Join(device.Protocols, ", ")
			fmt.Fprintf(w, "%s\t%s\t%s\t%.2f\t%s\t%d\t%s\t%s\t%s\n",
				device.DeviceAddress, device.DeviceType, device.Role,
				device.Confidence, protocols, device.SecurityLevel,
				device.Vendor, device.ProductName, device.LastSeen.Format("2006-01-02 15:04:05"))
		}
		w.Flush()
	}
	return nil
}

// formatProtocolStats formats protocol usage statistics for output
func formatProtocolStats(stats []*model.ProtocolUsageStats, format string) error {
	switch format {
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(stats)
	case "csv":
		fmt.Printf("DeviceID,Protocol,PacketCountOut,ByteCountOut,PacketCountIn,ByteCountIn,CommunicationRole,FirstSeen,LastSeen\n")
		for _, stat := range stats {
			fmt.Printf("%s,%s,%d,%d,%d,%d,%s,%s,%s\n",
				stat.DeviceID, stat.Protocol, stat.PacketCountOut, stat.ByteCountOut, stat.PacketCountIn, stat.ByteCountIn,
				stat.CommunicationRole, stat.FirstSeen.Format(time.RFC3339),
				stat.LastSeen.Format(time.RFC3339))
		}
	default: // table
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "DEVICE ID\tPROTOCOL\tOUT-PKT\tOUT-BYT\tIN-PKT\tIN-BYT\tROLE\tFIRST SEEN\tLAST SEEN\n")
		for _, stat := range stats {
			fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%d\t%d\t%s\t%s\t%s\n",
				stat.DeviceID, stat.Protocol, stat.PacketCountOut, stat.ByteCountOut, stat.PacketCountIn, stat.ByteCountIn,
				stat.CommunicationRole, stat.FirstSeen.Format("2006-01-02 15:04:05"),
				stat.LastSeen.Format("2006-01-02 15:04:05"))
		}
		w.Flush()
	}
	return nil
}

// Helper functions for industrial analysis

// analyzeFlowForIndustrialProtocols analyzes a flow for industrial protocol usage
func analyzeFlowForIndustrialProtocols(flow *model.Flow) []model.IndustrialProtocolInfo {
	var protocols []model.IndustrialProtocolInfo

	// Check for common industrial protocol ports
	industrialPorts := map[string]string{
		"44818": "ethernetip", // EtherNet/IP
		"2222":  "ethernetip", // EtherNet/IP UDP
		"4840":  "opcua",      // OPC UA
		"502":   "modbus",     // Modbus TCP
		"102":   "s7",         // Siemens S7
		"20000": "dnp3",       // DNP3
	}

	// Check destination ports for protocol detection
	if flow.DestinationPorts != nil {
		for _, portStr := range flow.DestinationPorts.List() {
			if protocolName, exists := industrialPorts[portStr]; exists {
				protocol := model.IndustrialProtocolInfo{
					Protocol:       protocolName,
					Port:           parsePort(portStr),
					Direction:      "outbound",
					Timestamp:      time.Now(),
					Confidence:     0.7, // Medium confidence from port-based detection
					ServiceType:    determineServiceType(protocolName, portStr),
					DeviceIdentity: make(map[string]interface{}),
					SecurityInfo:   make(map[string]interface{}),
					AdditionalData: make(map[string]interface{}),
				}
				protocols = append(protocols, protocol)
			}
		}
	}

	// Check source ports for protocol detection (server responses)
	if flow.SourcePorts != nil {
		for _, portStr := range flow.SourcePorts.List() {
			if protocolName, exists := industrialPorts[portStr]; exists {
				protocol := model.IndustrialProtocolInfo{
					Protocol:       protocolName,
					Port:           parsePort(portStr),
					Direction:      "inbound",
					Timestamp:      time.Now(),
					Confidence:     0.7,
					ServiceType:    determineServiceType(protocolName, portStr),
					DeviceIdentity: make(map[string]interface{}),
					SecurityInfo:   make(map[string]interface{}),
					AdditionalData: make(map[string]interface{}),
				}
				protocols = append(protocols, protocol)
			}
		}
	}

	return protocols
}

// parsePort converts port string to uint16
func parsePort(portStr string) uint16 {
	if port, err := strconv.ParseUint(portStr, 10, 16); err == nil {
		return uint16(port)
	}
	return 0
}

// determineServiceType determines the service type based on protocol and port
func determineServiceType(protocol string, port string) string {
	switch protocol {
	case "ethernetip":
		if port == "44818" {
			return "explicit_messaging"
		}
		return "implicit_io"
	case "opcua":
		return "secure_channel"
	case "modbus":
		return "register_access"
	default:
		return "unknown"
	}
}

// determineDeviceRole determines the role of a device based on its type and protocols
func determineDeviceRole(deviceType model.IndustrialDeviceType, protocols []model.IndustrialProtocolInfo) model.IndustrialDeviceRole {
	switch deviceType {
	case model.DeviceTypePLC:
		return model.RoleController
	case model.DeviceTypeHMI, model.DeviceTypeSCADA:
		return model.RoleOperator
	case model.DeviceTypeEngWorkstation:
		return model.RoleEngineer
	case model.DeviceTypeHistorian:
		return model.RoleDataCollector
	case model.DeviceTypeSensor, model.DeviceTypeActuator, model.DeviceTypeIODevice:
		return model.RoleFieldDevice
	default:
		return model.RoleFieldDevice
	}
}

// calculateConfidence calculates confidence level based on protocol detection
func calculateConfidence(protocols []model.IndustrialProtocolInfo) float64 {
	if len(protocols) == 0 {
		return 0.0
	}

	var totalConfidence float64
	for _, protocol := range protocols {
		totalConfidence += protocol.Confidence
	}

	return totalConfidence / float64(len(protocols))
}

// extractProtocolNames extracts protocol names from protocol info list
func extractProtocolNames(protocols []model.IndustrialProtocolInfo) []string {
	seen := make(map[string]bool)
	var names []string

	for _, protocol := range protocols {
		if !seen[protocol.Protocol] {
			names = append(names, protocol.Protocol)
			seen[protocol.Protocol] = true
		}
	}

	return names
}

// formatCommunicationPatterns formats communication patterns for output
func formatCommunicationPatterns(patterns []*model.CommunicationPattern, format string) error {
	switch format {
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(patterns)
	case "csv":
		fmt.Printf("SourceDevice,DestinationDevice,Protocol,Frequency,DataVolume,PatternType,Criticality\n")
		for _, pattern := range patterns {
			fmt.Printf("%s,%s,%s,%s,%d,%s,%s\n",
				pattern.SourceDevice, pattern.DestinationDevice, pattern.Protocol,
				pattern.Frequency.String(), pattern.DataVolume, pattern.PatternType, pattern.Criticality)
		}
	default: // table
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "SOURCE\tDESTINATION\tPROTOCOL\tFREQUENCY\tDATA VOLUME\tPATTERN\tCRITICALITY\n")
		for _, pattern := range patterns {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
				pattern.SourceDevice, pattern.DestinationDevice, pattern.Protocol,
				pattern.Frequency.String(), pattern.DataVolume, pattern.PatternType, pattern.Criticality)
		}
		w.Flush()
	}
	return nil
}

// formatSummary formats summary information for output
func formatSummary(summary map[string]interface{}, format string) error {
	switch format {
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(summary)
	default: // table
		fmt.Printf("Industrial Network Analysis Summary\n")
		fmt.Printf("===================================\n\n")

		if totalDevices, ok := summary["total_industrial_devices"].(int); ok {
			fmt.Printf("Total Industrial Devices: %d\n\n", totalDevices)
		}

		if deviceCounts, ok := summary["devices_by_type"].(map[string]int); ok {
			fmt.Printf("Devices by Type:\n")
			for deviceType, count := range deviceCounts {
				if count > 0 {
					fmt.Printf("  %s: %d\n", deviceType, count)
				}
			}
		}

		if timestamp, ok := summary["timestamp"].(string); ok {
			fmt.Printf("\nGenerated: %s\n", timestamp)
		}
	}
	return nil
}

func main() {
	provider := &DependencyProvider{}
	rootCmd := newRootCmd(provider)
	// Set up logging to file
	logFile, err := os.OpenFile("importer.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open log file: %v\n", err)
		os.Exit(2)
	}
	log.SetOutput(logFile)
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Error executing command: %v", err)
		os.Exit(1)
	}
}
