package repository

import (
	"os"
	"testing"
	"time"

	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSQLiteRepository_ProtocolUsageStatsOperations(t *testing.T) {
	// Create temporary database
	tempDB := createTempDB(t)
	defer os.Remove(tempDB)

	repo, err := NewSQLiteRepository(tempDB)
	require.NoError(t, err)
	defer repo.Close()

	now := time.Now()
	deviceAddress := "192.168.1.100"

	// Test SaveProtocolUsageStats
	t.Run("SaveProtocolUsageStats", func(t *testing.T) {
		stats := &model.ProtocolUsageStats{
			DeviceID:          deviceAddress,
			Protocol:          "ethernetip",
			PacketCount:       100,
			ByteCount:         5000,
			FirstSeen:         now,
			LastSeen:          now.Add(time.Hour),
			CommunicationRole: "client",
			PortsUsed:         []uint16{44818, 2222},
		}

		err := repo.SaveProtocolUsageStats(stats)
		assert.NoError(t, err)
	})

	// Test GetProtocolUsageStats
	t.Run("GetProtocolUsageStats", func(t *testing.T) {
		statsList, err := repo.GetProtocolUsageStats("", deviceAddress)
		require.NoError(t, err)
		require.Len(t, statsList, 1)

		stats := statsList[0]
		assert.Equal(t, deviceAddress, stats.DeviceID)
		assert.Equal(t, "ethernetip", stats.Protocol)
		assert.Equal(t, int64(100), stats.PacketCount)
		assert.Equal(t, int64(5000), stats.ByteCount)
		assert.Equal(t, "client", stats.CommunicationRole)
		assert.ElementsMatch(t, []uint16{44818, 2222}, stats.PortsUsed)
		assert.True(t, now.Equal(stats.FirstSeen))
		assert.True(t, now.Add(time.Hour).Equal(stats.LastSeen))
	})

	// Test GetProtocolUsageStatsByProtocol
	t.Run("GetProtocolUsageStatsByProtocol", func(t *testing.T) {
		statsList, err := repo.GetProtocolUsageStatsByProtocol("", "ethernetip")
		require.NoError(t, err)
		require.Len(t, statsList, 1)

		stats := statsList[0]
		assert.Equal(t, deviceAddress, stats.DeviceID)
		assert.Equal(t, "ethernetip", stats.Protocol)
	})

	// Test UpdateProtocolUsageStats
	t.Run("UpdateProtocolUsageStats", func(t *testing.T) {
		updatedStats := &model.ProtocolUsageStats{
			DeviceID:          deviceAddress,
			Protocol:          "ethernetip",
			PacketCount:       200,
			ByteCount:         10000,
			FirstSeen:         now.Add(-time.Hour),    // Earlier first seen
			LastSeen:          now.Add(time.Hour * 2), // Later last seen
			CommunicationRole: "both",
			PortsUsed:         []uint16{44818, 2222, 502},
		}

		err := repo.UpdateProtocolUsageStats(updatedStats)
		assert.NoError(t, err)

		// Verify update
		statsList, err := repo.GetProtocolUsageStats("", deviceAddress)
		require.NoError(t, err)
		require.Len(t, statsList, 1)

		stats := statsList[0]
		assert.Equal(t, int64(200), stats.PacketCount)
		assert.Equal(t, int64(10000), stats.ByteCount)
		assert.Equal(t, "both", stats.CommunicationRole)
		assert.ElementsMatch(t, []uint16{44818, 2222, 502}, stats.PortsUsed)
	})

	// Test UpsertProtocolUsageStats - update existing
	t.Run("UpsertProtocolUsageStats_Update", func(t *testing.T) {
		upsertStats := &model.ProtocolUsageStats{
			DeviceID:          deviceAddress,
			Protocol:          "ethernetip",
			PacketCount:       300,
			ByteCount:         15000,
			FirstSeen:         now.Add(-time.Hour * 2),
			LastSeen:          now.Add(time.Hour * 3),
			CommunicationRole: "server",
			PortsUsed:         []uint16{44818},
		}

		err := repo.UpsertProtocolUsageStats(upsertStats)
		assert.NoError(t, err)

		// Verify update
		statsList, err := repo.GetProtocolUsageStats("", deviceAddress)
		require.NoError(t, err)
		require.Len(t, statsList, 1)

		stats := statsList[0]
		assert.Equal(t, int64(300), stats.PacketCount)
		assert.Equal(t, "server", stats.CommunicationRole)
	})

	// Test UpsertProtocolUsageStats - insert new
	t.Run("UpsertProtocolUsageStats_Insert", func(t *testing.T) {
		newStats := &model.ProtocolUsageStats{
			DeviceID:          deviceAddress,
			Protocol:          "opcua",
			PacketCount:       50,
			ByteCount:         2500,
			FirstSeen:         now,
			LastSeen:          now.Add(time.Minute * 30),
			CommunicationRole: "client",
			PortsUsed:         []uint16{4840},
		}

		err := repo.UpsertProtocolUsageStats(newStats)
		assert.NoError(t, err)

		// Verify insert
		statsList, err := repo.GetProtocolUsageStats("", deviceAddress)
		require.NoError(t, err)
		require.Len(t, statsList, 2) // Should have both ethernetip and opcua

		// Find the OPC UA stats
		var opcuaStats *model.ProtocolUsageStats
		for _, stats := range statsList {
			if stats.Protocol == "opcua" {
				opcuaStats = stats
				break
			}
		}
		require.NotNil(t, opcuaStats)
		assert.Equal(t, int64(50), opcuaStats.PacketCount)
		assert.Equal(t, "client", opcuaStats.CommunicationRole)
	})

	// Test DeleteProtocolUsageStats
	t.Run("DeleteProtocolUsageStats", func(t *testing.T) {
		err := repo.DeleteProtocolUsageStats(deviceAddress, "opcua")
		assert.NoError(t, err)

		// Verify deletion
		statsList, err := repo.GetProtocolUsageStats("", deviceAddress)
		require.NoError(t, err)
		require.Len(t, statsList, 1) // Should only have ethernetip left

		assert.Equal(t, "ethernetip", statsList[0].Protocol)
	})
}

func TestSQLiteRepository_CommunicationPatternOperations(t *testing.T) {
	// Create temporary database
	tempDB := createTempDB(t)
	defer os.Remove(tempDB)

	repo, err := NewSQLiteRepository(tempDB)
	require.NoError(t, err)
	defer repo.Close()

	sourceDevice := "192.168.1.100"
	destDevice := "192.168.1.101"

	// Test SaveCommunicationPattern
	t.Run("SaveCommunicationPattern", func(t *testing.T) {
		pattern := &model.CommunicationPattern{
			SourceDevice:      sourceDevice,
			DestinationDevice: destDevice,
			Protocol:          "ethernetip",
			Frequency:         time.Second * 10,
			DataVolume:        1024,
			PatternType:       "periodic",
			Criticality:       "high",
		}

		err := repo.SaveCommunicationPattern(pattern)
		assert.NoError(t, err)
	})

	// Test GetCommunicationPatterns
	t.Run("GetCommunicationPatterns", func(t *testing.T) {
		patterns, err := repo.GetCommunicationPatterns("", sourceDevice)
		require.NoError(t, err)
		require.Len(t, patterns, 1)

		pattern := patterns[0]
		assert.Equal(t, sourceDevice, pattern.SourceDevice)
		assert.Equal(t, destDevice, pattern.DestinationDevice)
		assert.Equal(t, "ethernetip", pattern.Protocol)
		assert.Equal(t, time.Second*10, pattern.Frequency)
		assert.Equal(t, int64(1024), pattern.DataVolume)
		assert.Equal(t, "periodic", pattern.PatternType)
		assert.Equal(t, "high", pattern.Criticality)
	})

	// Test GetCommunicationPatternsByProtocol
	t.Run("GetCommunicationPatternsByProtocol", func(t *testing.T) {
		patterns, err := repo.GetCommunicationPatternsByProtocol("", "ethernetip")
		require.NoError(t, err)
		require.Len(t, patterns, 1)

		pattern := patterns[0]
		assert.Equal(t, "ethernetip", pattern.Protocol)
	})

	// Test UpdateCommunicationPattern
	t.Run("UpdateCommunicationPattern", func(t *testing.T) {
		updatedPattern := &model.CommunicationPattern{
			SourceDevice:      sourceDevice,
			DestinationDevice: destDevice,
			Protocol:          "ethernetip",
			Frequency:         time.Second * 5, // Updated frequency
			DataVolume:        2048,            // Updated data volume
			PatternType:       "continuous",    // Updated pattern type
			Criticality:       "critical",      // Updated criticality
		}

		err := repo.UpdateCommunicationPattern(updatedPattern)
		assert.NoError(t, err)

		// Verify update
		patterns, err := repo.GetCommunicationPatterns("", sourceDevice)
		require.NoError(t, err)
		require.Len(t, patterns, 1)

		pattern := patterns[0]
		assert.Equal(t, time.Second*5, pattern.Frequency)
		assert.Equal(t, int64(2048), pattern.DataVolume)
		assert.Equal(t, "continuous", pattern.PatternType)
		assert.Equal(t, "critical", pattern.Criticality)
	})

	// Test UpsertCommunicationPattern - update existing
	t.Run("UpsertCommunicationPattern_Update", func(t *testing.T) {
		upsertPattern := &model.CommunicationPattern{
			SourceDevice:      sourceDevice,
			DestinationDevice: destDevice,
			Protocol:          "ethernetip",
			Frequency:         time.Minute,
			DataVolume:        4096,
			PatternType:       "event-driven",
			Criticality:       "medium",
		}

		err := repo.UpsertCommunicationPattern(upsertPattern)
		assert.NoError(t, err)

		// Verify update
		patterns, err := repo.GetCommunicationPatterns("", sourceDevice)
		require.NoError(t, err)
		require.Len(t, patterns, 1)

		pattern := patterns[0]
		assert.Equal(t, time.Minute, pattern.Frequency)
		assert.Equal(t, "event-driven", pattern.PatternType)
	})

	// Test UpsertCommunicationPattern - insert new
	t.Run("UpsertCommunicationPattern_Insert", func(t *testing.T) {
		newPattern := &model.CommunicationPattern{
			SourceDevice:      sourceDevice,
			DestinationDevice: destDevice,
			Protocol:          "opcua", // Different protocol
			Frequency:         time.Second * 30,
			DataVolume:        512,
			PatternType:       "periodic",
			Criticality:       "low",
		}

		err := repo.UpsertCommunicationPattern(newPattern)
		assert.NoError(t, err)

		// Verify insert
		patterns, err := repo.GetCommunicationPatterns("", sourceDevice)
		require.NoError(t, err)
		require.Len(t, patterns, 2) // Should have both ethernetip and opcua

		// Find the OPC UA pattern
		var opcuaPattern *model.CommunicationPattern
		for _, pattern := range patterns {
			if pattern.Protocol == "opcua" {
				opcuaPattern = pattern
				break
			}
		}
		require.NotNil(t, opcuaPattern)
		assert.Equal(t, time.Second*30, opcuaPattern.Frequency)
		assert.Equal(t, "low", opcuaPattern.Criticality)
	})

	// Test DeleteCommunicationPattern
	t.Run("DeleteCommunicationPattern", func(t *testing.T) {
		err := repo.DeleteCommunicationPattern(sourceDevice, destDevice, "opcua")
		assert.NoError(t, err)

		// Verify deletion
		patterns, err := repo.GetCommunicationPatterns("", sourceDevice)
		require.NoError(t, err)
		require.Len(t, patterns, 1) // Should only have ethernetip left

		assert.Equal(t, "ethernetip", patterns[0].Protocol)
	})
}

func TestSQLiteRepository_BatchIndustrialOperations(t *testing.T) {
	// Create temporary database
	tempDB := createTempDB(t)
	defer os.Remove(tempDB)

	repo, err := NewSQLiteRepository(tempDB)
	require.NoError(t, err)
	defer repo.Close()

	now := time.Now()

	// Test SaveProtocolUsageStatsMultiple
	t.Run("SaveProtocolUsageStatsMultiple", func(t *testing.T) {
		statsList := []*model.ProtocolUsageStats{
			{
				DeviceID:          "192.168.1.100",
				Protocol:          "ethernetip",
				PacketCount:       100,
				ByteCount:         5000,
				FirstSeen:         now,
				LastSeen:          now.Add(time.Hour),
				CommunicationRole: "client",
				PortsUsed:         []uint16{44818},
			},
			{
				DeviceID:          "192.168.1.101",
				Protocol:          "opcua",
				PacketCount:       50,
				ByteCount:         2500,
				FirstSeen:         now,
				LastSeen:          now.Add(time.Minute * 30),
				CommunicationRole: "server",
				PortsUsed:         []uint16{4840},
			},
		}

		err := repo.SaveProtocolUsageStatsMultiple(statsList)
		assert.NoError(t, err)

		// Verify both were saved
		stats1, err := repo.GetProtocolUsageStats("", "192.168.1.100")
		require.NoError(t, err)
		require.Len(t, stats1, 1)
		assert.Equal(t, "ethernetip", stats1[0].Protocol)

		stats2, err := repo.GetProtocolUsageStats("", "192.168.1.101")
		require.NoError(t, err)
		require.Len(t, stats2, 1)
		assert.Equal(t, "opcua", stats2[0].Protocol)
	})

	// Test SaveCommunicationPatterns
	t.Run("SaveCommunicationPatterns", func(t *testing.T) {
		patterns := []*model.CommunicationPattern{
			{
				SourceDevice:      "192.168.1.100",
				DestinationDevice: "192.168.1.101",
				Protocol:          "ethernetip",
				Frequency:         time.Second * 10,
				DataVolume:        1024,
				PatternType:       "periodic",
				Criticality:       "high",
			},
			{
				SourceDevice:      "192.168.1.101",
				DestinationDevice: "192.168.1.102",
				Protocol:          "opcua",
				Frequency:         time.Minute,
				DataVolume:        512,
				PatternType:       "event-driven",
				Criticality:       "medium",
			},
		}

		err := repo.SaveCommunicationPatterns(patterns)
		assert.NoError(t, err)

		// Verify both were saved
		patterns1, err := repo.GetCommunicationPatterns("", "192.168.1.100")
		require.NoError(t, err)
		require.Len(t, patterns1, 1)
		assert.Equal(t, "ethernetip", patterns1[0].Protocol)

		patterns2, err := repo.GetCommunicationPatterns("", "192.168.1.101")
		require.NoError(t, err)
		require.Len(t, patterns2, 2) // 192.168.1.101 appears in both patterns (as destination in first, source in second)

		// Check that we have both protocols
		protocols := make([]string, len(patterns2))
		for i, pattern := range patterns2 {
			protocols[i] = pattern.Protocol
		}
		assert.Contains(t, protocols, "ethernetip")
		assert.Contains(t, protocols, "opcua")
	})
}

func TestSQLiteRepository_ProtocolUsageStatsValidation(t *testing.T) {
	// Create temporary database
	tempDB := createTempDB(t)
	defer os.Remove(tempDB)

	repo, err := NewSQLiteRepository(tempDB)
	require.NoError(t, err)
	defer repo.Close()

	// Test validation errors
	t.Run("SaveProtocolUsageStats_ValidationError", func(t *testing.T) {
		invalidStats := &model.ProtocolUsageStats{
			DeviceID:          "", // Invalid: empty device ID
			Protocol:          "ethernetip",
			PacketCount:       100,
			ByteCount:         5000,
			FirstSeen:         time.Now(),
			LastSeen:          time.Now().Add(time.Hour),
			CommunicationRole: "client",
			PortsUsed:         []uint16{44818},
		}

		err := repo.SaveProtocolUsageStats(invalidStats)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "device ID must not be empty")
	})

	t.Run("UpdateProtocolUsageStats_ValidationError", func(t *testing.T) {
		invalidStats := &model.ProtocolUsageStats{
			DeviceID:          "192.168.1.100",
			Protocol:          "", // Invalid: empty protocol
			PacketCount:       100,
			ByteCount:         5000,
			FirstSeen:         time.Now(),
			LastSeen:          time.Now().Add(time.Hour),
			CommunicationRole: "client",
			PortsUsed:         []uint16{44818},
		}

		err := repo.UpdateProtocolUsageStats(invalidStats)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "protocol must not be empty")
	})
}

func TestSQLiteRepository_CommunicationPatternValidation(t *testing.T) {
	// Create temporary database
	tempDB := createTempDB(t)
	defer os.Remove(tempDB)

	repo, err := NewSQLiteRepository(tempDB)
	require.NoError(t, err)
	defer repo.Close()

	// Test validation errors
	t.Run("SaveCommunicationPattern_ValidationError", func(t *testing.T) {
		invalidPattern := &model.CommunicationPattern{
			SourceDevice:      "", // Invalid: empty source device
			DestinationDevice: "192.168.1.101",
			Protocol:          "ethernetip",
			Frequency:         time.Second * 10,
			DataVolume:        1024,
			PatternType:       "periodic",
			Criticality:       "high",
		}

		err := repo.SaveCommunicationPattern(invalidPattern)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "source device must not be empty")
	})

	t.Run("UpdateCommunicationPattern_ValidationError", func(t *testing.T) {
		invalidPattern := &model.CommunicationPattern{
			SourceDevice:      "192.168.1.100",
			DestinationDevice: "192.168.1.100", // Invalid: same as source
			Protocol:          "ethernetip",
			Frequency:         time.Second * 10,
			DataVolume:        1024,
			PatternType:       "periodic",
			Criticality:       "high",
		}

		err := repo.UpdateCommunicationPattern(invalidPattern)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "source and destination devices must be different")
	})
}

// Helper function to create a temporary database for testing
func createTempDB(t *testing.T) string {
	tempFile, err := os.CreateTemp("", "test_*.db")
	require.NoError(t, err)
	tempFile.Close()
	return tempFile.Name()
}
