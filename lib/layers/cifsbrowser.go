// Copyright 2025 Patrick InfraSec Consult. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package lib_layers

import (
	"encoding/binary"
	"errors"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog/log"
)

// CIFSBrowserCommandType represents the CIFS Browser command type
type CIFSBrowserCommandType uint8

// LayerTypeCIFSBrowser is the layer type for CIFS Browser protocol
var LayerTypeCIFSBrowser gopacket.LayerType

// CIFS Browser command types as defined in the protocol
const (
	CIFSBrowserCmdHostAnnounce                  CIFSBrowserCommandType = 1
	CIFSBrowserCmdRequestAnnounce               CIFSBrowserCommandType = 2
	CIFSBrowserCmdElectionRequest               CIFSBrowserCommandType = 8
	CIFSBrowserCmdBackupListRequest             CIFSBrowserCommandType = 9
	CIFSBrowserCmdBackupListResponse            CIFSBrowserCommandType = 10
	CIFSBrowserCmdBecomeBackup                  CIFSBrowserCommandType = 11
	CIFSBrowserCmdDomainAnnouncement            CIFSBrowserCommandType = 12
	CIFSBrowserCmdMasterAnnouncement            CIFSBrowserCommandType = 13
	CIFSBrowserCmdResetBrowserStateAnnouncement CIFSBrowserCommandType = 14
	CIFSBrowserCmdLocalMasterAnnouncement       CIFSBrowserCommandType = 15
)

// String returns the string representation of the CIFS Browser command type
func (c CIFSBrowserCommandType) String() string {
	switch c {
	case CIFSBrowserCmdHostAnnounce:
		return "Host Announce"
	case CIFSBrowserCmdRequestAnnounce:
		return "Request Announce"
	case CIFSBrowserCmdElectionRequest:
		return "Election Request"
	case CIFSBrowserCmdBackupListRequest:
		return "Backup List Request"
	case CIFSBrowserCmdBackupListResponse:
		return "Backup List Response"
	case CIFSBrowserCmdBecomeBackup:
		return "Become Backup"
	case CIFSBrowserCmdDomainAnnouncement:
		return "Domain Announcement"
	case CIFSBrowserCmdMasterAnnouncement:
		return "Master Announcement"
	case CIFSBrowserCmdResetBrowserStateAnnouncement:
		return "Reset Browser State Announcement"
	case CIFSBrowserCmdLocalMasterAnnouncement:
		return "Local Master Announcement"
	default:
		return "Unknown"
	}
}

// ServerTypeFlags represents the server type flags in CIFS Browser
type ServerTypeFlags struct {
	IsWorkstation          bool
	IsServer               bool
	IsSQLServer            bool
	IsDomainController     bool
	IsBackupController     bool
	IsTimeSource           bool
	IsAppleServer          bool
	IsNovellServer         bool
	IsDomainMemberServer   bool
	IsPrintQueueServer     bool
	IsDialinServer         bool
	IsXenixServer          bool
	IsNTWorkstation        bool
	IsWindowsForWorkgroups bool
	IsNTServer             bool
	IsPotentialBrowser     bool
	IsBackupBrowser        bool
	IsMasterBrowser        bool
	IsDomainMasterBrowser  bool
	IsOSF                  bool
	IsVMS                  bool
	IsWindows95            bool
	IsDFSServer            bool
	IsLocalListOnly        bool
	IsDomainEnum           bool
}

// ElectionCriteria represents the election criteria used in election requests
type ElectionCriteria struct {
	DesiredBackup       bool
	DesiredStandby      bool
	DesiredMaster       bool
	DesiredDomainMaster bool
	DesiredWins         bool
	DesiredNT           bool
	OSType              uint8
	Revision            uint8
}

// CIFSBrowserAnnouncement represents a Host Announce, Domain Announcement, or Local Master Announcement
type CIFSBrowserAnnouncement struct {
	layers.BaseLayer
	Command               CIFSBrowserCommandType
	UpdateCount           uint8
	Periodicity           uint32 // in milliseconds
	ServerName            string // up to 16 bytes
	OSMajorVersion        uint8
	OSMinorVersion        uint8
	ServerTypeFlags       ServerTypeFlags
	BrowserProtocolMajor  uint8
	BrowserProtocolMinor  uint8
	SignatureConstant     uint16
	CommentOrMBServerName string
}

// CIFSBrowserRequestAnnounce represents a Request Announce message
type CIFSBrowserRequestAnnounce struct {
	layers.BaseLayer
	Command              CIFSBrowserCommandType
	UnusedFlags          uint8
	ResponseComputerName string
}

// CIFSBrowserElectionRequest represents an Election Request message
type CIFSBrowserElectionRequest struct {
	layers.BaseLayer
	Command          CIFSBrowserCommandType
	ElectionVersion  uint8
	ElectionCriteria ElectionCriteria
	ServerUptime     uint32 // in milliseconds
	ServerName       string
}

// CIFSBrowserBackupListRequest represents a Backup List Request message
type CIFSBrowserBackupListRequest struct {
	layers.BaseLayer
	Command            CIFSBrowserCommandType
	BackupListCount    uint8
	BackupRequestToken uint32
}

// CIFSBrowserBackupListResponse represents a Backup List Response message
type CIFSBrowserBackupListResponse struct {
	layers.BaseLayer
	Command            CIFSBrowserCommandType
	BackupServerCount  uint8
	BackupRequestToken uint32
	BackupServerNames  []string
}

// CIFSBrowserMasterAnnouncement represents a Master Announcement message
type CIFSBrowserMasterAnnouncement struct {
	layers.BaseLayer
	Command           CIFSBrowserCommandType
	MasterBrowserName string
}

// CIFSBrowserResetBrowserState represents a Reset Browser State Announcement
type CIFSBrowserResetBrowserState struct {
	layers.BaseLayer
	Command         CIFSBrowserCommandType
	DemoteToBackup  bool
	FlushBrowseList bool
	StopBeingLMB    bool
}

// CIFSBrowserBecomeBackupMsg represents a Become Backup message
type CIFSBrowserBecomeBackupMsg struct {
	layers.BaseLayer
	Command          CIFSBrowserCommandType
	BrowserToPromote string
}

// GenericCIFSBrowser is a generic container for any CIFS Browser message
type GenericCIFSBrowser struct {
	layers.BaseLayer
	Command CIFSBrowserCommandType
	Payload []byte
}

// parseServerTypeFlags parses the 4-byte server type flags field
func parseServerTypeFlags(data []byte) ServerTypeFlags {
	if len(data) < 4 {
		return ServerTypeFlags{}
	}

	flags := binary.LittleEndian.Uint32(data)

	return ServerTypeFlags{
		IsWorkstation:          (flags & (1 << 0)) != 0,
		IsServer:               (flags & (1 << 1)) != 0,
		IsSQLServer:            (flags & (1 << 2)) != 0,
		IsDomainController:     (flags & (1 << 3)) != 0,
		IsBackupController:     (flags & (1 << 4)) != 0,
		IsTimeSource:           (flags & (1 << 5)) != 0,
		IsAppleServer:          (flags & (1 << 6)) != 0,
		IsNovellServer:         (flags & (1 << 7)) != 0,
		IsDomainMemberServer:   (flags & (1 << 8)) != 0,
		IsPrintQueueServer:     (flags & (1 << 9)) != 0,
		IsDialinServer:         (flags & (1 << 10)) != 0,
		IsXenixServer:          (flags & (1 << 11)) != 0,
		IsNTWorkstation:        (flags & (1 << 12)) != 0,
		IsWindowsForWorkgroups: (flags & (1 << 13)) != 0,
		IsNTServer:             (flags & (1 << 15)) != 0,
		IsPotentialBrowser:     (flags & (1 << 16)) != 0,
		IsBackupBrowser:        (flags & (1 << 17)) != 0,
		IsMasterBrowser:        (flags & (1 << 18)) != 0,
		IsDomainMasterBrowser:  (flags & (1 << 19)) != 0,
		IsOSF:                  (flags & (1 << 20)) != 0,
		IsVMS:                  (flags & (1 << 21)) != 0,
		IsWindows95:            (flags & (1 << 22)) != 0,
		IsDFSServer:            (flags & (1 << 23)) != 0,
		IsLocalListOnly:        (flags & (1 << 30)) != 0,
		IsDomainEnum:           (flags & (1 << 31)) != 0,
	}
}

// parseElectionCriteria parses the 4-byte election criteria field
func parseElectionCriteria(data []byte) ElectionCriteria {
	if len(data) < 4 {
		return ElectionCriteria{}
	}

	criteria := binary.LittleEndian.Uint32(data)

	return ElectionCriteria{
		DesiredBackup:       (criteria & (1 << 0)) != 0,
		DesiredStandby:      (criteria & (1 << 1)) != 0,
		DesiredMaster:       (criteria & (1 << 2)) != 0,
		DesiredDomainMaster: (criteria & (1 << 3)) != 0,
		DesiredWins:         (criteria & (1 << 5)) != 0,
		DesiredNT:           (criteria & (1 << 7)) != 0,
		OSType:              uint8((criteria >> 24) & 0xFF),
		Revision:            uint8((criteria >> 16) & 0xFF),
	}
}

// readNullTerminatedString reads a null-terminated ASCII string from data at offset
func readNullTerminatedString(data []byte, offset int) (string, int) {
	start := offset
	for i := offset; i < len(data); i++ {
		if data[i] == 0 {
			return string(data[start:i]), i + 1
		}
	}
	// No null terminator found, return from offset to end
	if offset < len(data) {
		return string(data[offset:]), len(data)
	}
	return "", offset
}

// readPaddedString reads a fixed-length null-padded string
func readPaddedString(data []byte, offset, length int) (string, int) {
	if offset+length > len(data) {
		return "", offset + length
	}
	// Find the first null byte or use the full length
	result := make([]byte, 0, length)
	for i := 0; i < length; i++ {
		if data[offset+i] != 0 {
			result = append(result, data[offset+i])
		} else {
			break
		}
	}
	return string(result), offset + length
}

// decodeCIFSBrowserAnnouncement decodes Host Announce, Domain Announcement, or Local Master Announcement
func decodeCIFSBrowserAnnouncement(data []byte, cmdType CIFSBrowserCommandType) (*CIFSBrowserAnnouncement, error) {
	if len(data) < 1 {
		return nil, errors.New("CIFS Browser message too short")
	}

	if len(data) < 2 {
		return nil, errors.New("CIFS Browser announcement too short for update count")
	}

	announcement := &CIFSBrowserAnnouncement{
		Command:     cmdType,
		UpdateCount: data[0],
	}

	offset := 1

	// Periodicity (4 bytes, little-endian)
	if offset+4 > len(data) {
		return announcement, nil
	}
	announcement.Periodicity = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	// Server name (16 bytes, null-padded)
	if offset+16 > len(data) {
		return announcement, nil
	}
	announcement.ServerName, _ = readPaddedString(data, offset, 16)
	offset += 16

	// OS Major and Minor Version (2 bytes)
	if offset+2 > len(data) {
		return announcement, nil
	}
	announcement.OSMajorVersion = data[offset]
	announcement.OSMinorVersion = data[offset+1]
	offset += 2

	// Server Type Flags (4 bytes, little-endian)
	if offset+4 > len(data) {
		return announcement, nil
	}
	announcement.ServerTypeFlags = parseServerTypeFlags(data[offset : offset+4])
	offset += 4

	// Browser protocol version and signature constant
	if offset+4 <= len(data) {
		// Check if this is a domain announcement with mysterious field
		if cmdType == CIFSBrowserCmdDomainAnnouncement && len(data) > offset+4 {
			sigConstant := binary.LittleEndian.Uint16(data[offset+2 : offset+4])
			if sigConstant != 0xAA55 {
				// This is the mysterious field, skip it
				offset += 4
			} else {
				// This is the browser protocol version and signature
				announcement.BrowserProtocolMajor = data[offset]
				announcement.BrowserProtocolMinor = data[offset+1]
				announcement.SignatureConstant = sigConstant
				offset += 4
			}
		} else {
			announcement.BrowserProtocolMajor = data[offset]
			announcement.BrowserProtocolMinor = data[offset+1]
			announcement.SignatureConstant = binary.LittleEndian.Uint16(data[offset+2 : offset+4])
			offset += 4
		}
	}

	// Comment or MB Server Name (null-terminated string)
	if offset < len(data) {
		announcement.CommentOrMBServerName, _ = readNullTerminatedString(data, offset)
	}

	return announcement, nil
}

// decodeCIFSBrowserRequestAnnounce decodes a Request Announce message
func decodeCIFSBrowserRequestAnnounce(data []byte) (*CIFSBrowserRequestAnnounce, error) {
	if len(data) < 2 {
		return nil, errors.New("CIFS Browser RequestAnnounce too short")
	}

	msg := &CIFSBrowserRequestAnnounce{
		Command:     CIFSBrowserCmdRequestAnnounce,
		UnusedFlags: data[0],
	}

	// Computer name (null-terminated string)
	if len(data) > 1 {
		msg.ResponseComputerName, _ = readNullTerminatedString(data, 1)
	}

	return msg, nil
}

// decodeCIFSBrowserElectionRequest decodes an Election Request message
func decodeCIFSBrowserElectionRequest(data []byte) (*CIFSBrowserElectionRequest, error) {
	if len(data) < 14 {
		return nil, errors.New("CIFS Browser ElectionRequest too short")
	}

	msg := &CIFSBrowserElectionRequest{
		Command:          CIFSBrowserCmdElectionRequest,
		ElectionVersion:  data[0],
		ElectionCriteria: parseElectionCriteria(data[1:5]),
		ServerUptime:     binary.LittleEndian.Uint32(data[5:9]),
	}

	// Skip 4 bytes that must be zero (offset 9-12)
	// Server name at offset 13
	if len(data) > 13 {
		msg.ServerName, _ = readNullTerminatedString(data, 13)
	}

	return msg, nil
}

// decodeCIFSBrowserBackupListRequest decodes a Backup List Request message
func decodeCIFSBrowserBackupListRequest(data []byte) (*CIFSBrowserBackupListRequest, error) {
	if len(data) < 5 {
		return nil, errors.New("CIFS Browser BackupListRequest too short")
	}

	msg := &CIFSBrowserBackupListRequest{
		Command:            CIFSBrowserCmdBackupListRequest,
		BackupListCount:    data[0],
		BackupRequestToken: binary.LittleEndian.Uint32(data[1:5]),
	}

	return msg, nil
}

// decodeCIFSBrowserBackupListResponse decodes a Backup List Response message
func decodeCIFSBrowserBackupListResponse(data []byte) (*CIFSBrowserBackupListResponse, error) {
	if len(data) < 5 {
		return nil, errors.New("CIFS Browser BackupListResponse too short")
	}

	msg := &CIFSBrowserBackupListResponse{
		Command:            CIFSBrowserCmdBackupListResponse,
		BackupServerCount:  data[0],
		BackupRequestToken: binary.LittleEndian.Uint32(data[1:5]),
		BackupServerNames:  make([]string, 0),
	}

	offset := 5
	for i := 0; i < int(msg.BackupServerCount); i++ {
		if offset >= len(data) {
			break
		}
		name, nextOffset := readNullTerminatedString(data, offset)
		msg.BackupServerNames = append(msg.BackupServerNames, name)
		offset = nextOffset
	}

	return msg, nil
}

// decodeCIFSBrowserMasterAnnouncement decodes a Master Announcement message
func decodeCIFSBrowserMasterAnnouncement(data []byte) (*CIFSBrowserMasterAnnouncement, error) {
	msg := &CIFSBrowserMasterAnnouncement{
		Command: CIFSBrowserCmdMasterAnnouncement,
	}

	if len(data) > 0 {
		msg.MasterBrowserName, _ = readNullTerminatedString(data, 0)
	}

	return msg, nil
}

// decodeCIFSBrowserResetBrowserState decodes a Reset Browser State Announcement
func decodeCIFSBrowserResetBrowserState(data []byte) (*CIFSBrowserResetBrowserState, error) {
	if len(data) < 1 {
		return nil, errors.New("CIFS Browser ResetBrowserState too short")
	}

	flags := data[0]

	msg := &CIFSBrowserResetBrowserState{
		Command:         CIFSBrowserCmdResetBrowserStateAnnouncement,
		DemoteToBackup:  (flags & 0x01) != 0,
		FlushBrowseList: (flags & 0x02) != 0,
		StopBeingLMB:    (flags & 0x04) != 0,
	}

	return msg, nil
}

// decodeCIFSBrowserBecomeBackup decodes a Become Backup message
func decodeCIFSBrowserBecomeBackup(data []byte) (*CIFSBrowserBecomeBackupMsg, error) {
	msg := &CIFSBrowserBecomeBackupMsg{
		Command: CIFSBrowserCmdBecomeBackup,
	}

	if len(data) > 0 {
		msg.BrowserToPromote, _ = readNullTerminatedString(data, 0)
	}

	return msg, nil
}

// LayerType returns the layer type for CIFS Browser
// Using a custom layer type since there may not be a standard gopacket type
func (c *CIFSBrowserAnnouncement) LayerType() gopacket.LayerType {
	return LayerTypeCIFSBrowser
}

func (c *CIFSBrowserRequestAnnounce) LayerType() gopacket.LayerType {
	return LayerTypeCIFSBrowser
}

func (c *CIFSBrowserElectionRequest) LayerType() gopacket.LayerType {
	return LayerTypeCIFSBrowser
}

func (c *CIFSBrowserBackupListRequest) LayerType() gopacket.LayerType {
	return LayerTypeCIFSBrowser
}

func (c *CIFSBrowserBackupListResponse) LayerType() gopacket.LayerType {
	return LayerTypeCIFSBrowser
}

func (c *CIFSBrowserMasterAnnouncement) LayerType() gopacket.LayerType {
	return LayerTypeCIFSBrowser
}

func (c *CIFSBrowserResetBrowserState) LayerType() gopacket.LayerType {
	return LayerTypeCIFSBrowser
}

func (c *CIFSBrowserBecomeBackupMsg) LayerType() gopacket.LayerType {
	return LayerTypeCIFSBrowser
}

func (c *GenericCIFSBrowser) LayerType() gopacket.LayerType {
	return LayerTypeCIFSBrowser
}

// NextLayerType returns the next layer type (none for CIFS Browser)
func (c *CIFSBrowserAnnouncement) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypeZero
}

func (c *CIFSBrowserRequestAnnounce) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypeZero
}

func (c *CIFSBrowserElectionRequest) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypeZero
}

func (c *CIFSBrowserBackupListRequest) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypeZero
}

func (c *CIFSBrowserBackupListResponse) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypeZero
}

func (c *CIFSBrowserMasterAnnouncement) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypeZero
}

func (c *CIFSBrowserResetBrowserState) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypeZero
}

func (c *CIFSBrowserBecomeBackupMsg) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypeZero
}

func (c *GenericCIFSBrowser) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypeZero
}

// DecodeCIFSBrowser decodes CIFS Browser protocol data
// Returns a generic container with the parsed command type and payload
func DecodeCIFSBrowser(data []byte) (*GenericCIFSBrowser, error) {
	if len(data) < 1 {
		return nil, errors.New("CIFS Browser message too short")
	}

	cmdType := CIFSBrowserCommandType(data[0])

	browser := &GenericCIFSBrowser{
		Command: cmdType,
		Payload: data[1:],
	}

	return browser, nil
}

// DecodeCIFSBrowserMessage decodes CIFS Browser protocol data and returns the appropriate message type
// This is the main function for decoding CIFS Browser messages
func DecodeCIFSBrowserMessage(data []byte) (interface{}, error) {
	if len(data) < 1 {
		return nil, errors.New("CIFS Browser message too short")
	}

	cmdType := CIFSBrowserCommandType(data[0])
	payload := data[1:]

	switch cmdType {
	case CIFSBrowserCmdHostAnnounce, CIFSBrowserCmdDomainAnnouncement, CIFSBrowserCmdLocalMasterAnnouncement:
		return decodeCIFSBrowserAnnouncement(payload, cmdType)
	case CIFSBrowserCmdRequestAnnounce:
		return decodeCIFSBrowserRequestAnnounce(payload)
	case CIFSBrowserCmdElectionRequest:
		return decodeCIFSBrowserElectionRequest(payload)
	case CIFSBrowserCmdBackupListRequest:
		return decodeCIFSBrowserBackupListRequest(payload)
	case CIFSBrowserCmdBackupListResponse:
		return decodeCIFSBrowserBackupListResponse(payload)
	case CIFSBrowserCmdMasterAnnouncement:
		return decodeCIFSBrowserMasterAnnouncement(payload)
	case CIFSBrowserCmdResetBrowserStateAnnouncement:
		return decodeCIFSBrowserResetBrowserState(payload)
	case CIFSBrowserCmdBecomeBackup:
		return decodeCIFSBrowserBecomeBackup(payload)
	default:
		log.Warn().Uint8("command", uint8(cmdType)).Msg("Unknown CIFS Browser command type")
		return &GenericCIFSBrowser{
			Command: cmdType,
			Payload: payload,
		}, nil
	}
}

// init initializes the CIFS Browser layer type
func init() {
	LayerTypeCIFSBrowser = gopacket.OverrideLayerType(150, gopacket.LayerTypeMetadata{Name: "CIFSBrowser"})
}
