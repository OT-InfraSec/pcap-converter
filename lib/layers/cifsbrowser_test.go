// Copyright 2025 Patrick InfraSec Consult. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package lib_layers

import (
	"encoding/binary"
	"testing"
)

// TestHostAnnounce tests decoding of Host Announce messages
func TestHostAnnounce(t *testing.T) {
	// Construct a minimal Host Announce packet
	data := make([]byte, 0)
	data = append(data, byte(CIFSBrowserCmdHostAnnounce)) // Command

	// UpdateCount
	data = append(data, 0x02) // update count = 2

	// Periodicity (4 bytes, little-endian)
	periodicity := make([]byte, 4)
	binary.LittleEndian.PutUint32(periodicity, 60000) // 60 seconds
	data = append(data, periodicity...)

	// ServerName (16 bytes, null-padded)
	serverName := "WORKSTATION01\x00\x00\x00"
	data = append(data, []byte(serverName)...)

	// OS Major and Minor Version
	data = append(data, 0x06) // Windows 7 major
	data = append(data, 0x01) // Windows 7 minor

	// Server Type Flags (4 bytes, little-endian)
	// Set: IsWorkstation (bit 0), IsNTWorkstation (bit 12), IsWindows95 (bit 22)
	serverTypeFlags := make([]byte, 4)
	flags := uint32(1 | (1 << 12) | (1 << 22))
	binary.LittleEndian.PutUint32(serverTypeFlags, flags)
	data = append(data, serverTypeFlags...)

	// Browser Protocol Major and Minor
	data = append(data, 0x0F) // major version 15
	data = append(data, 0x0B) // minor version 11

	// Signature Constant
	sig := make([]byte, 2)
	binary.LittleEndian.PutUint16(sig, 0xAA55)
	data = append(data, sig...)

	// Server Comment (null-terminated)
	comment := "Test Host\x00"
	data = append(data, []byte(comment)...)

	// Decode the message
	msg, err := DecodeCIFSBrowserMessage(data)
	if err != nil {
		t.Fatalf("Failed to decode Host Announce: %v", err)
	}

	announce, ok := msg.(*CIFSBrowserAnnouncement)
	if !ok {
		t.Fatalf("Expected CIFSBrowserAnnouncement, got %T", msg)
	}

	if announce.Command != CIFSBrowserCmdHostAnnounce {
		t.Errorf("Command mismatch: expected %d, got %d", CIFSBrowserCmdHostAnnounce, announce.Command)
	}

	if announce.UpdateCount != 2 {
		t.Errorf("UpdateCount mismatch: expected 2, got %d", announce.UpdateCount)
	}

	if announce.Periodicity != 60000 {
		t.Errorf("Periodicity mismatch: expected 60000, got %d", announce.Periodicity)
	}

	if announce.ServerName != "WORKSTATION01" {
		t.Errorf("ServerName mismatch: expected 'WORKSTATION01', got '%s'", announce.ServerName)
	}

	if announce.OSMajorVersion != 6 {
		t.Errorf("OSMajorVersion mismatch: expected 6, got %d", announce.OSMajorVersion)
	}

	if announce.OSMinorVersion != 1 {
		t.Errorf("OSMinorVersion mismatch: expected 1, got %d", announce.OSMinorVersion)
	}

	// Check server type flags
	if !announce.ServerTypeFlags.IsWorkstation {
		t.Error("Expected IsWorkstation to be true")
	}

	if !announce.ServerTypeFlags.IsNTWorkstation {
		t.Error("Expected IsNTWorkstation to be true")
	}

	if !announce.ServerTypeFlags.IsWindows95 {
		t.Error("Expected IsWindows95 to be true")
	}

	if announce.BrowserProtocolMajor != 15 {
		t.Errorf("BrowserProtocolMajor mismatch: expected 15, got %d", announce.BrowserProtocolMajor)
	}

	if announce.CommentOrMBServerName != "Test Host" {
		t.Errorf("CommentOrMBServerName mismatch: expected 'Test Host', got '%s'", announce.CommentOrMBServerName)
	}
}

// TestPrintQueueServerDetection tests detection of print queue servers
func TestPrintQueueServerDetection(t *testing.T) {
	data := make([]byte, 0)
	data = append(data, byte(CIFSBrowserCmdHostAnnounce))

	// UpdateCount
	data = append(data, 0x01)

	// Periodicity
	periodicity := make([]byte, 4)
	binary.LittleEndian.PutUint32(periodicity, 60000)
	data = append(data, periodicity...)

	// ServerName
	serverName := "PRINTER01\x00\x00\x00\x00\x00\x00\x00"
	data = append(data, []byte(serverName)...)

	// OS Version
	data = append(data, 0x06, 0x01)

	// Server Type Flags: IsPrintQueueServer (bit 9) and IsServer (bit 1)
	serverTypeFlags := make([]byte, 4)
	flags := uint32((1 << 9) | (1 << 1))
	binary.LittleEndian.PutUint32(serverTypeFlags, flags)
	data = append(data, serverTypeFlags...)

	// Browser Protocol
	data = append(data, 0x0F, 0x0B)

	// Signature
	sig := make([]byte, 2)
	binary.LittleEndian.PutUint16(sig, 0xAA55)
	data = append(data, sig...)

	// Comment
	data = append(data, []byte("Printer\x00")...)

	msg, err := DecodeCIFSBrowserMessage(data)
	if err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	announce := msg.(*CIFSBrowserAnnouncement)

	if !announce.ServerTypeFlags.IsPrintQueueServer {
		t.Error("Expected IsPrintQueueServer to be true")
	}

	if !announce.ServerTypeFlags.IsServer {
		t.Error("Expected IsServer to be true")
	}
}

// TestAppleAndWindowsHostDetection tests detection of Apple and Windows hosts
func TestAppleAndWindowsHostDetection(t *testing.T) {
	tests := []struct {
		name      string
		flag      uint32
		isApple   bool
		isWindows bool
	}{
		{
			name:      "Apple Server",
			flag:      (1 << 6), // IsAppleServer
			isApple:   true,
			isWindows: false,
		},
		{
			name:      "Windows NT Workstation",
			flag:      (1 << 12), // IsNTWorkstation
			isApple:   false,
			isWindows: true,
		},
		{
			name:      "Windows 95",
			flag:      (1 << 22), // IsWindows95
			isApple:   false,
			isWindows: true,
		},
		{
			name:      "Workstation (generic Windows)",
			flag:      (1 << 0), // IsWorkstation
			isApple:   false,
			isWindows: true,
		},
		{
			name:      "Novell Server",
			flag:      (1 << 7), // IsNovellServer
			isApple:   false,
			isWindows: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, 0)
			data = append(data, byte(CIFSBrowserCmdHostAnnounce))
			data = append(data, 0x01)

			periodicity := make([]byte, 4)
			binary.LittleEndian.PutUint32(periodicity, 60000)
			data = append(data, periodicity...)

			serverName := "SERVER01\x00\x00\x00\x00\x00\x00\x00\x00"
			data = append(data, []byte(serverName)...)

			data = append(data, 0x06, 0x01)

			serverTypeFlags := make([]byte, 4)
			binary.LittleEndian.PutUint32(serverTypeFlags, tt.flag)
			data = append(data, serverTypeFlags...)

			data = append(data, 0x0F, 0x0B)

			sig := make([]byte, 2)
			binary.LittleEndian.PutUint16(sig, 0xAA55)
			data = append(data, sig...)

			data = append(data, []byte("Server\x00")...)

			msg, err := DecodeCIFSBrowserMessage(data)
			if err != nil {
				t.Fatalf("Failed to decode: %v", err)
			}

			announce := msg.(*CIFSBrowserAnnouncement)

			if announce.ServerTypeFlags.IsAppleServer != tt.isApple {
				t.Errorf("IsAppleServer: expected %v, got %v", tt.isApple, announce.ServerTypeFlags.IsAppleServer)
			}

			isWindows := announce.ServerTypeFlags.IsWorkstation ||
				announce.ServerTypeFlags.IsNTWorkstation ||
				announce.ServerTypeFlags.IsWindows95 ||
				announce.ServerTypeFlags.IsWindowsForWorkgroups
			if isWindows != tt.isWindows {
				t.Errorf("IsWindows: expected %v, got %v", tt.isWindows, isWindows)
			}
		})
	}
}

// TestElectionRequest tests decoding of Election Request messages
func TestElectionRequest(t *testing.T) {
	data := make([]byte, 0)
	data = append(data, byte(CIFSBrowserCmdElectionRequest)) // Command

	// ElectionVersion
	data = append(data, 0x0B) // version 11

	// ElectionCriteria (4 bytes)
	criteria := make([]byte, 4)
	// Set DesiredBackup (bit 0), DesiredMaster (bit 2), DesiredNT (bit 7)
	// OS type in bits 24-31, revision in bits 16-23
	criteriaValue := uint32(1 | (1 << 2) | (1 << 7) | (0x05 << 24) | (0x00 << 16))
	binary.LittleEndian.PutUint32(criteria, criteriaValue)
	data = append(data, criteria...)

	// ServerUptime (4 bytes)
	uptime := make([]byte, 4)
	binary.LittleEndian.PutUint32(uptime, 3600000) // 1 hour
	data = append(data, uptime...)

	// Reserved (4 bytes)
	data = append(data, 0x00, 0x00, 0x00, 0x00)

	// ServerName (null-terminated)
	serverName := "SERVER01\x00"
	data = append(data, []byte(serverName)...)

	msg, err := DecodeCIFSBrowserMessage(data)
	if err != nil {
		t.Fatalf("Failed to decode Election Request: %v", err)
	}

	election, ok := msg.(*CIFSBrowserElectionRequest)
	if !ok {
		t.Fatalf("Expected CIFSBrowserCmdElectionRequest, got %T", msg)
	}

	if election.Command != CIFSBrowserCmdElectionRequest {
		t.Errorf("Command mismatch: expected %d, got %d", CIFSBrowserCmdElectionRequest, election.Command)
	}

	if election.ElectionVersion != 11 {
		t.Errorf("ElectionVersion mismatch: expected 11, got %d", election.ElectionVersion)
	}

	if !election.ElectionCriteria.DesiredBackup {
		t.Error("Expected DesiredBackup to be true")
	}

	if !election.ElectionCriteria.DesiredMaster {
		t.Error("Expected DesiredMaster to be true")
	}

	if !election.ElectionCriteria.DesiredNT {
		t.Error("Expected DesiredNT to be true")
	}

	if election.ServerUptime != 3600000 {
		t.Errorf("ServerUptime mismatch: expected 3600000, got %d", election.ServerUptime)
	}

	if election.ServerName != "SERVER01" {
		t.Errorf("ServerName mismatch: expected 'SERVER01', got '%s'", election.ServerName)
	}
}

// TestBackupListResponse tests decoding of Backup List Response messages
func TestBackupListResponse(t *testing.T) {
	data := make([]byte, 0)
	data = append(data, byte(CIFSBrowserCmdBackupListResponse)) // Command

	// BackupServerCount
	data = append(data, 0x03) // 3 backup servers

	// BackupRequestToken (4 bytes)
	token := make([]byte, 4)
	binary.LittleEndian.PutUint32(token, 0x12345678)
	data = append(data, token...)

	// BackupServerNames
	data = append(data, []byte("SERVER01\x00")...)
	data = append(data, []byte("SERVER02\x00")...)
	data = append(data, []byte("SERVER03\x00")...)

	msg, err := DecodeCIFSBrowserMessage(data)
	if err != nil {
		t.Fatalf("Failed to decode Backup List Response: %v", err)
	}

	response, ok := msg.(*CIFSBrowserBackupListResponse)
	if !ok {
		t.Fatalf("Expected CIFSBrowserCmdBackupListResponse, got %T", msg)
	}

	if response.Command != CIFSBrowserCmdBackupListResponse {
		t.Errorf("Command mismatch: expected %d, got %d", CIFSBrowserCmdBackupListResponse, response.Command)
	}

	if response.BackupServerCount != 3 {
		t.Errorf("BackupServerCount mismatch: expected 3, got %d", response.BackupServerCount)
	}

	if len(response.BackupServerNames) != 3 {
		t.Errorf("BackupServerNames count mismatch: expected 3, got %d", len(response.BackupServerNames))
	}

	expectedNames := []string{"SERVER01", "SERVER02", "SERVER03"}
	for i, expected := range expectedNames {
		if i < len(response.BackupServerNames) && response.BackupServerNames[i] != expected {
			t.Errorf("BackupServerName[%d] mismatch: expected '%s', got '%s'", i, expected, response.BackupServerNames[i])
		}
	}
}

// TestResetBrowserState tests decoding of Reset Browser State messages
func TestResetBrowserState(t *testing.T) {
	tests := []struct {
		name            string
		flags           byte
		expectedDemote  bool
		expectedFlush   bool
		expectedStopLMB bool
	}{
		{
			name:            "Demote to Backup",
			flags:           0x01,
			expectedDemote:  true,
			expectedFlush:   false,
			expectedStopLMB: false,
		},
		{
			name:            "Flush Browse List",
			flags:           0x02,
			expectedDemote:  false,
			expectedFlush:   true,
			expectedStopLMB: false,
		},
		{
			name:            "Stop Being LMB",
			flags:           0x04,
			expectedDemote:  false,
			expectedFlush:   false,
			expectedStopLMB: true,
		},
		{
			name:            "All Flags Set",
			flags:           0x07,
			expectedDemote:  true,
			expectedFlush:   true,
			expectedStopLMB: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, 0)
			data = append(data, byte(CIFSBrowserCmdResetBrowserStateAnnouncement))
			data = append(data, tt.flags)

			msg, err := DecodeCIFSBrowserMessage(data)
			if err != nil {
				t.Fatalf("Failed to decode: %v", err)
			}

			reset, ok := msg.(*CIFSBrowserResetBrowserState)
			if !ok {
				t.Fatalf("Expected CIFSBrowserResetBrowserState, got %T", msg)
			}

			if reset.DemoteToBackup != tt.expectedDemote {
				t.Errorf("DemoteToBackup: expected %v, got %v", tt.expectedDemote, reset.DemoteToBackup)
			}

			if reset.FlushBrowseList != tt.expectedFlush {
				t.Errorf("FlushBrowseList: expected %v, got %v", tt.expectedFlush, reset.FlushBrowseList)
			}

			if reset.StopBeingLMB != tt.expectedStopLMB {
				t.Errorf("StopBeingLMB: expected %v, got %v", tt.expectedStopLMB, reset.StopBeingLMB)
			}
		})
	}
}

// TestMasterAnnouncement tests decoding of Master Announcement messages
func TestMasterAnnouncement(t *testing.T) {
	data := make([]byte, 0)
	data = append(data, byte(CIFSBrowserCmdMasterAnnouncement)) // Command

	// Master Browser Server Name
	masterName := "MASTERSERVER\x00"
	data = append(data, []byte(masterName)...)

	msg, err := DecodeCIFSBrowserMessage(data)
	if err != nil {
		t.Fatalf("Failed to decode Master Announcement: %v", err)
	}

	master, ok := msg.(*CIFSBrowserMasterAnnouncement)
	if !ok {
		t.Fatalf("Expected CIFSBrowserCmdMasterAnnouncement, got %T", msg)
	}

	if master.Command != CIFSBrowserCmdMasterAnnouncement {
		t.Errorf("Command mismatch: expected %d, got %d", CIFSBrowserCmdMasterAnnouncement, master.Command)
	}

	if master.MasterBrowserName != "MASTERSERVER" {
		t.Errorf("MasterBrowserName mismatch: expected 'MASTERSERVER', got '%s'", master.MasterBrowserName)
	}
}

// TestBecomeBackup tests decoding of Become Backup messages
func TestBecomeBackup(t *testing.T) {
	data := make([]byte, 0)
	data = append(data, byte(CIFSBrowserCmdBecomeBackup)) // Command

	// Browser to Promote Name
	browserName := "SERVER02\x00"
	data = append(data, []byte(browserName)...)

	msg, err := DecodeCIFSBrowserMessage(data)
	if err != nil {
		t.Fatalf("Failed to decode Become Backup: %v", err)
	}

	backup, ok := msg.(*CIFSBrowserBecomeBackupMsg)
	if !ok {
		t.Fatalf("Expected CIFSBrowserBecomeBackupMsg, got %T", msg)
	}

	if backup.Command != CIFSBrowserCmdBecomeBackup {
		t.Errorf("Command mismatch: expected %d, got %d", CIFSBrowserCmdBecomeBackup, backup.Command)
	}

	if backup.BrowserToPromote != "SERVER02" {
		t.Errorf("BrowserToPromote mismatch: expected 'SERVER02', got '%s'", backup.BrowserToPromote)
	}
}

// TestRequestAnnounce tests decoding of Request Announce messages
func TestRequestAnnounce(t *testing.T) {
	data := make([]byte, 0)
	data = append(data, byte(CIFSBrowserCmdRequestAnnounce)) // Command

	// UnusedFlags
	data = append(data, 0x00)

	// ResponseComputerName
	computerName := "MYCOMPUTER\x00"
	data = append(data, []byte(computerName)...)

	msg, err := DecodeCIFSBrowserMessage(data)
	if err != nil {
		t.Fatalf("Failed to decode Request Announce: %v", err)
	}

	request, ok := msg.(*CIFSBrowserRequestAnnounce)
	if !ok {
		t.Fatalf("Expected CIFSBrowserCmdRequestAnnounce, got %T", msg)
	}

	if request.Command != CIFSBrowserCmdRequestAnnounce {
		t.Errorf("Command mismatch: expected %d, got %d", CIFSBrowserCmdRequestAnnounce, request.Command)
	}

	if request.ResponseComputerName != "MYCOMPUTER" {
		t.Errorf("ResponseComputerName mismatch: expected 'MYCOMPUTER', got '%s'", request.ResponseComputerName)
	}
}

// TestCommandTypeString tests the String representation of command types
func TestCommandTypeString(t *testing.T) {
	tests := []struct {
		cmd      CIFSBrowserCommandType
		expected string
	}{
		{CIFSBrowserCmdHostAnnounce, "Host Announce"},
		{CIFSBrowserCmdRequestAnnounce, "Request Announce"},
		{CIFSBrowserCmdElectionRequest, "Election Request"},
		{CIFSBrowserCmdBackupListRequest, "Backup List Request"},
		{CIFSBrowserCmdBackupListResponse, "Backup List Response"},
		{CIFSBrowserCmdBecomeBackup, "Become Backup"},
		{CIFSBrowserCmdDomainAnnouncement, "Domain Announcement"},
		{CIFSBrowserCmdMasterAnnouncement, "Master Announcement"},
		{CIFSBrowserCmdResetBrowserStateAnnouncement, "Reset Browser State Announcement"},
		{CIFSBrowserCmdLocalMasterAnnouncement, "Local Master Announcement"},
		{CIFSBrowserCommandType(255), "Unknown"},
	}

	for _, tt := range tests {
		if tt.cmd.String() != tt.expected {
			t.Errorf("Command %d: expected '%s', got '%s'", tt.cmd, tt.expected, tt.cmd.String())
		}
	}
}
