package main

import (
	"fmt"
	"log"
	"time"

	"github.com/InfraSecConsult/pcap-importer-go/internal/parser"
	"github.com/InfraSecConsult/pcap-importer-go/internal/repository"
	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
)

func main() {
	// Create a temporary database for this example
	repo, err := repository.NewSQLiteRepository(":memory:")
	if err != nil {
		log.Fatalf("Failed to create repository: %v", err)
	}
	defer repo.Close()

	// Create an industrial protocol parser
	industrialParser := parser.NewIndustrialProtocolParser()

	// Simulate some industrial protocol information
	now := time.Now()
	deviceAddress := "192.168.1.100"

	// Example 1: EtherNet/IP real-time I/O data
	ethernetIPProtocols := []model.IndustrialProtocolInfo{
		{
			Protocol:        "ethernetip",
			Port:            44818,
			Direction:       "outbound",
			IsRealTimeData:  true,
			IsDiscovery:     false,
			IsConfiguration: false,
			Confidence:      0.95,
			Timestamp:       now,
		},
		{
			Protocol:        "ethernetip",
			Port:            2222,
			Direction:       "inbound",
			IsRealTimeData:  false,
			IsDiscovery:     false,
			IsConfiguration: true,
			Confidence:      0.90,
			Timestamp:       now.Add(time.Second),
		},
	}

	// Collect protocol usage statistics
	fmt.Println("=== Protocol Usage Statistics Collection ===")
	stats, err := industrialParser.CollectProtocolUsageStats(deviceAddress, ethernetIPProtocols)
	if err != nil {
		log.Fatalf("Failed to collect protocol usage stats: %v", err)
	}

	if stats != nil {
		fmt.Printf("Device: %s\n", stats.DeviceID)
		fmt.Printf("Protocol: %s\n", stats.Protocol)
		fmt.Printf("Packet Count: %d\n", stats.PacketCount)
		fmt.Printf("Byte Count: %d\n", stats.ByteCount)
		fmt.Printf("Communication Role: %s\n", stats.CommunicationRole)
		fmt.Printf("Ports Used: %v\n", stats.PortsUsed)
		fmt.Printf("First Seen: %s\n", stats.FirstSeen.Format(time.RFC3339))
		fmt.Printf("Last Seen: %s\n", stats.LastSeen.Format(time.RFC3339))

		// Save to database
		err = repo.SaveProtocolUsageStats(stats)
		if err != nil {
			log.Fatalf("Failed to save protocol usage stats: %v", err)
		}
		fmt.Println("✓ Statistics saved to database")
	}

	// Example 2: OPC UA discovery and data exchange
	fmt.Println("\n=== OPC UA Protocol Analysis ===")
	opcuaProtocols := []model.IndustrialProtocolInfo{
		{
			Protocol:        "opcua",
			Port:            4840,
			Direction:       "outbound",
			IsRealTimeData:  false,
			IsDiscovery:     true,
			IsConfiguration: false,
			Confidence:      0.98,
			Timestamp:       now.Add(time.Minute),
		},
		{
			Protocol:        "opcua",
			Port:            4840,
			Direction:       "inbound",
			IsRealTimeData:  true,
			IsDiscovery:     false,
			IsConfiguration: false,
			Confidence:      0.92,
			Timestamp:       now.Add(time.Minute * 2),
		},
	}

	opcuaStats, err := industrialParser.CollectProtocolUsageStats(deviceAddress, opcuaProtocols)
	if err != nil {
		log.Fatalf("Failed to collect OPC UA stats: %v", err)
	}

	if opcuaStats != nil {
		fmt.Printf("OPC UA Statistics:\n")
		fmt.Printf("  Packet Count: %d\n", opcuaStats.PacketCount)
		fmt.Printf("  Byte Count: %d\n", opcuaStats.ByteCount)
		fmt.Printf("  Communication Role: %s\n", opcuaStats.CommunicationRole)

		// Save OPC UA stats
		err = repo.SaveProtocolUsageStats(opcuaStats)
		if err != nil {
			log.Fatalf("Failed to save OPC UA stats: %v", err)
		}
		fmt.Println("✓ OPC UA statistics saved to database")
	}

	// Example 3: Retrieve and aggregate statistics
	fmt.Println("\n=== Statistics Retrieval and Aggregation ===")
	allStats, err := repo.GetProtocolUsageStats(deviceAddress)
	if err != nil {
		log.Fatalf("Failed to retrieve stats: %v", err)
	}

	fmt.Printf("Found %d protocol statistics for device %s:\n", len(allStats), deviceAddress)
	for i, stat := range allStats {
		fmt.Printf("  %d. Protocol: %s, Packets: %d, Bytes: %d, Role: %s\n",
			i+1, stat.Protocol, stat.PacketCount, stat.ByteCount, stat.CommunicationRole)
	}

	// Example 4: Communication Pattern Analysis
	fmt.Println("\n=== Communication Pattern Analysis ===")

	// Create some sample flows for pattern analysis
	flows := []model.Flow{
		{
			Source:      "192.168.1.100",
			Destination: "192.168.1.101",
			Protocol:    "ethernetip",
			Packets:     100,
			Bytes:       5000,
			FirstSeen:   now,
			LastSeen:    now.Add(time.Minute * 10),
		},
		{
			Source:      "192.168.1.101",
			Destination: "192.168.1.102",
			Protocol:    "opcua",
			Packets:     50,
			Bytes:       2500,
			FirstSeen:   now,
			LastSeen:    now.Add(time.Minute * 5),
		},
	}

	patterns := industrialParser.AnalyzeCommunicationPatterns(flows)
	fmt.Printf("Identified %d communication patterns:\n", len(patterns))

	for i, pattern := range patterns {
		fmt.Printf("  %d. %s -> %s (%s)\n", i+1, pattern.SourceDevice, pattern.DestinationDevice, pattern.Protocol)
		fmt.Printf("     Pattern: %s, Criticality: %s, Frequency: %s\n",
			pattern.PatternType, pattern.Criticality, pattern.Frequency)

		// Save pattern to database
		err = repo.SaveCommunicationPattern(&pattern)
		if err != nil {
			log.Printf("Failed to save communication pattern: %v", err)
		} else {
			fmt.Printf("     ✓ Pattern saved to database\n")
		}
	}

	// Example 5: Query patterns by protocol
	fmt.Println("\n=== Protocol-Specific Pattern Queries ===")
	ethernetIPPatterns, err := repo.GetCommunicationPatternsByProtocol("ethernetip")
	if err != nil {
		log.Fatalf("Failed to get EtherNet/IP patterns: %v", err)
	}

	fmt.Printf("EtherNet/IP Communication Patterns: %d\n", len(ethernetIPPatterns))
	for _, pattern := range ethernetIPPatterns {
		fmt.Printf("  %s -> %s: %s (%s)\n",
			pattern.SourceDevice, pattern.DestinationDevice, pattern.PatternType, pattern.Criticality)
	}

	opcuaPatterns, err := repo.GetCommunicationPatternsByProtocol("opcua")
	if err != nil {
		log.Fatalf("Failed to get OPC UA patterns: %v", err)
	}

	fmt.Printf("OPC UA Communication Patterns: %d\n", len(opcuaPatterns))
	for _, pattern := range opcuaPatterns {
		fmt.Printf("  %s -> %s: %s (%s)\n",
			pattern.SourceDevice, pattern.DestinationDevice, pattern.PatternType, pattern.Criticality)
	}

	fmt.Println("\n=== Example Complete ===")
	fmt.Println("This example demonstrated:")
	fmt.Println("1. Protocol usage statistics collection from industrial protocol information")
	fmt.Println("2. Database storage and retrieval of statistics")
	fmt.Println("3. Statistics aggregation across multiple protocols")
	fmt.Println("4. Communication pattern analysis from network flows")
	fmt.Println("5. Protocol-specific pattern queries")
}
