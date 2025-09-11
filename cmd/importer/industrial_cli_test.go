package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/InfraSecConsult/pcap-importer-go/internal/repository"
	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIndustrialCLICommands(t *testing.T) {
	// Create a temporary database for testing
	tmpDB := "test_industrial.sqlite"
	defer os.Remove(tmpDB)

	// Set up test data
	setupIndustrialTestData(t, tmpDB)

	tests := []struct {
		name     string
		args     []string
		expected []string // strings that should be present in output
	}{
		{
			name:     "list devices table format",
			args:     []string{"industrial", "list-devices", "--db-path", tmpDB, "--format", "table"},
			expected: []string{"ADDRESS", "TYPE", "ROLE", "CONFIDENCE", "192.168.1.10", "PLC", "Controller"},
		},
		{
			name:     "list devices json format",
			args:     []string{"industrial", "list-devices", "--db-path", tmpDB, "--format", "json"},
			expected: []string{`"device_address"`, `"device_type"`, `"192.168.1.10"`, `"PLC"`},
		},
		{
			name:     "list devices csv format",
			args:     []string{"industrial", "list-devices", "--db-path", tmpDB, "--format", "csv"},
			expected: []string{"Address,Type,Role", "192.168.1.10,PLC,Controller"},
		},
		{
			name:     "devices by type PLC",
			args:     []string{"industrial", "devices-by-type", "PLC", "--db-path", tmpDB, "--format", "table"},
			expected: []string{"ADDRESS", "TYPE", "192.168.1.10", "PLC"},
		},
		{
			name:     "devices by type HMI",
			args:     []string{"industrial", "devices-by-type", "HMI", "--db-path", tmpDB, "--format", "table"},
			expected: []string{"ADDRESS", "TYPE", "192.168.1.20", "HMI"},
		},
		{
			name:     "protocol stats for specific device",
			args:     []string{"industrial", "protocol-stats", "192.168.1.10", "--db-path", tmpDB, "--format", "table"},
			expected: []string{"DEVICE ID", "PROTOCOL", "PACKETS", "192.168.1.10", "EtherNet/IP"},
		},
		{
			name:     "communication patterns for specific device",
			args:     []string{"industrial", "communication-patterns", "192.168.1.10", "--db-path", tmpDB, "--format", "table"},
			expected: []string{"SOURCE", "DESTINATION", "PROTOCOL", "192.168.1.10", "192.168.1.20"},
		},
		{
			name:     "industrial summary",
			args:     []string{"industrial", "summary", "--db-path", tmpDB, "--format", "table"},
			expected: []string{"Industrial Network Analysis Summary", "Total Industrial Devices:", "PLC:", "HMI:"},
		},
		{
			name:     "industrial summary json",
			args:     []string{"industrial", "summary", "--db-path", tmpDB, "--format", "json"},
			expected: []string{`"total_industrial_devices"`, `"devices_by_type"`, `"PLC"`, `"HMI"`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture stdout
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			// Create a new command instance for each test
			provider := &DependencyProvider{}
			rootCmd := newRootCmd(provider)
			rootCmd.SetArgs(tt.args)

			// Execute command
			err := rootCmd.Execute()

			// Restore stdout and capture output
			w.Close()
			os.Stdout = oldStdout

			var buf bytes.Buffer
			buf.ReadFrom(r)
			output := buf.String()

			// Verify no error occurred
			assert.NoError(t, err, "Command should execute without error")

			// Verify expected strings are present in output
			for _, expected := range tt.expected {
				assert.Contains(t, output, expected, "Output should contain expected string: %s", expected)
			}
		})
	}
}

func TestIndustrialImportWithAnalysis(t *testing.T) {
	tmpDB := "test_import_industrial.sqlite"
	defer os.Remove(tmpDB)

	// Create a minimal test PCAP file (this would be a real PCAP in practice)
	testPcapFile := "test_minimal.pcap"
	createMinimalTestPcap(t, testPcapFile)
	defer os.Remove(testPcapFile)

	// Test import with industrial analysis enabled
	provider := &DependencyProvider{}
	rootCmd := newRootCmd(provider)
	rootCmd.SetArgs([]string{"import", testPcapFile, "--db-path", tmpDB, "--industrial", "--clear"})

	err := rootCmd.Execute()
	assert.NoError(t, err, "Import with industrial analysis should succeed")

	// Verify database was created
	_, err = os.Stat(tmpDB)
	assert.NoError(t, err, "Database file should exist after import")
}

func TestIndustrialCLIErrorHandling(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectError bool
	}{
		{
			name:        "missing database file",
			args:        []string{"industrial", "list-devices", "--db-path", "/nonexistent/path/database.sqlite"},
			expectError: true,
		},
		{
			name:        "invalid device type",
			args:        []string{"industrial", "devices-by-type", "InvalidType", "--db-path", "test.sqlite"},
			expectError: true,
		},
		{
			name:        "invalid output format",
			args:        []string{"industrial", "list-devices", "--format", "xml"},
			expectError: false, // Should default to table format
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &DependencyProvider{}
			rootCmd := newRootCmd(provider)
			rootCmd.SetArgs(tt.args)

			err := rootCmd.Execute()
			if tt.expectError {
				assert.Error(t, err, "Command should return an error")
			} else {
				// For non-error cases, we just verify it doesn't panic
				// The actual output validation is done in other tests
			}
		})
	}
}

func TestIndustrialOutputFormats(t *testing.T) {
	tmpDB := "test_formats.sqlite"
	defer os.Remove(tmpDB)

	setupIndustrialTestData(t, tmpDB)

	// Test JSON output format validation
	t.Run("json output is valid", func(t *testing.T) {
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		provider := &DependencyProvider{}
		rootCmd := newRootCmd(provider)
		rootCmd.SetArgs([]string{"industrial", "list-devices", "--db-path", tmpDB, "--format", "json"})

		err := rootCmd.Execute()
		w.Close()
		os.Stdout = oldStdout

		var buf bytes.Buffer
		buf.ReadFrom(r)
		output := buf.String()

		assert.NoError(t, err)

		// Verify JSON is valid
		var devices []model.IndustrialDeviceInfo
		err = json.Unmarshal([]byte(output), &devices)
		assert.NoError(t, err, "JSON output should be valid")
		assert.Greater(t, len(devices), 0, "Should have at least one device")
	})

	// Test CSV output format
	t.Run("csv output format", func(t *testing.T) {
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		provider := &DependencyProvider{}
		rootCmd := newRootCmd(provider)
		rootCmd.SetArgs([]string{"industrial", "list-devices", "--db-path", tmpDB, "--format", "csv"})

		err := rootCmd.Execute()
		w.Close()
		os.Stdout = oldStdout

		var buf bytes.Buffer
		buf.ReadFrom(r)
		output := buf.String()

		assert.NoError(t, err)

		lines := strings.Split(strings.TrimSpace(output), "\n")
		assert.Greater(t, len(lines), 1, "CSV should have header and at least one data row")

		// Verify CSV header
		header := lines[0]
		assert.Contains(t, header, "Address,Type,Role", "CSV should have proper header")
	})
}

// setupIndustrialTestData creates test data for industrial device CLI tests
func setupIndustrialTestData(t *testing.T, dbPath string) {
	repo, err := repository.NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	now := time.Now()

	// Create test industrial devices
	devices := []*model.IndustrialDeviceInfo{
		{
			DeviceAddress:   "192.168.1.10",
			DeviceType:      model.DeviceTypePLC,
			Role:            model.RoleController,
			Confidence:      0.95,
			Protocols:       []string{"EtherNet/IP", "Modbus"},
			SecurityLevel:   model.SecurityLevel2,
			Vendor:          "Rockwell",
			ProductName:     "CompactLogix",
			SerialNumber:    "12345",
			FirmwareVersion: "v1.2.3",
			LastSeen:        now,
			CreatedAt:       now,
			UpdatedAt:       now,
		},
		{
			DeviceAddress:   "192.168.1.20",
			DeviceType:      model.DeviceTypeHMI,
			Role:            model.RoleOperator,
			Confidence:      0.88,
			Protocols:       []string{"OPC UA", "HTTP"},
			SecurityLevel:   model.SecurityLevel1,
			Vendor:          "Siemens",
			ProductName:     "WinCC",
			SerialNumber:    "67890",
			FirmwareVersion: "v2.1.0",
			LastSeen:        now,
			CreatedAt:       now,
			UpdatedAt:       now,
		},
		{
			DeviceAddress:   "192.168.1.30",
			DeviceType:      model.DeviceTypeSCADA,
			Role:            model.RoleDataCollector,
			Confidence:      0.92,
			Protocols:       []string{"OPC UA", "DNP3"},
			SecurityLevel:   model.SecurityLevel3,
			Vendor:          "Schneider",
			ProductName:     "Wonderware",
			SerialNumber:    "54321",
			FirmwareVersion: "v3.0.1",
			LastSeen:        now,
			CreatedAt:       now,
			UpdatedAt:       now,
		},
	}

	for _, device := range devices {
		err := repo.SaveIndustrialDeviceInfo(device)
		require.NoError(t, err)
	}

	// Create test protocol usage statistics
	stats := []*model.ProtocolUsageStats{
		{
			DeviceID:          "192.168.1.10",
			Protocol:          "EtherNet/IP",
			PacketCount:       1500,
			ByteCount:         75000,
			FirstSeen:         now.Add(-time.Hour),
			LastSeen:          now,
			CommunicationRole: "server",
			PortsUsed:         []uint16{44818, 2222},
		},
		{
			DeviceID:          "192.168.1.20",
			Protocol:          "OPC UA",
			PacketCount:       800,
			ByteCount:         40000,
			FirstSeen:         now.Add(-time.Hour),
			LastSeen:          now,
			CommunicationRole: "client",
			PortsUsed:         []uint16{4840},
		},
	}

	for _, stat := range stats {
		err := repo.SaveProtocolUsageStats(stat)
		require.NoError(t, err)
	}

	// Create test communication patterns
	patterns := []*model.CommunicationPattern{
		{
			SourceDevice:      "192.168.1.10",
			DestinationDevice: "192.168.1.20",
			Protocol:          "EtherNet/IP",
			Frequency:         time.Second * 5,
			DataVolume:        1024,
			PatternType:       "periodic",
			Criticality:       "high",
		},
		{
			SourceDevice:      "192.168.1.20",
			DestinationDevice: "192.168.1.30",
			Protocol:          "OPC UA",
			Frequency:         time.Second * 10,
			DataVolume:        2048,
			PatternType:       "event-driven",
			Criticality:       "medium",
		},
	}

	for _, pattern := range patterns {
		err := repo.SaveCommunicationPattern(pattern)
		require.NoError(t, err)
	}

	err = repo.Commit()
	require.NoError(t, err)
}

// createMinimalTestPcap creates a minimal test PCAP file for testing
func createMinimalTestPcap(t *testing.T, filename string) {
	// Create a minimal PCAP file with just the header
	// In a real implementation, this would contain actual packet data
	pcapHeader := []byte{
		0xD4, 0xC3, 0xB2, 0xA1, // Magic number (little endian)
		0x02, 0x00, // Version major
		0x04, 0x00, // Version minor
		0x00, 0x00, 0x00, 0x00, // Timezone offset
		0x00, 0x00, 0x00, 0x00, // Timestamp accuracy
		0xFF, 0xFF, 0x00, 0x00, // Max packet length
		0x01, 0x00, 0x00, 0x00, // Data link type (Ethernet)
	}

	err := os.WriteFile(filename, pcapHeader, 0644)
	require.NoError(t, err)
}
