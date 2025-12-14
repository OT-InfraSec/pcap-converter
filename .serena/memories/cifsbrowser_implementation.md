# CIFS Browser Protocol Layer Implementation

## Overview
Implemented a complete CIFS Browser protocol layer following the same patterns as other custom protocol layers (IGMP, ModbusTCP, etc.).

## Files Created
- `lib/layers/cifsbrowser.go` - Main CIFS Browser protocol implementation (619 lines)
- `lib/layers/cifsbrowser_test.go` - Comprehensive unit tests (548 lines)

## Key Design Decisions

### 1. Naming Convention
- **Command Type Constants**: Prefixed with `CIFSBrowserCmd` to avoid conflicts with struct names
  - `CIFSBrowserCmdHostAnnounce`, `CIFSBrowserCmdElectionRequest`, etc.
- **Struct Names**: Match the message types without Cmd prefix
  - `CIFSBrowserAnnouncement`, `CIFSBrowserElectionRequest`, etc.

### 2. Supported Message Types (10 commands)
1. **Host Announce** (1) - Device announcement on network
2. **Request Announce** (2) - Request for announcements
3. **Election Request** (8) - Master browser election request
4. **Backup List Request** (9) - Request backup browser list
5. **Backup List Response** (10) - Backup browser server list
6. **Become Backup** (11) - Promote server to backup browser
7. **Domain Announcement** (12) - Domain/workgroup announcement
8. **Master Announcement** (13) - Master browser announcement
9. **Reset Browser State** (14) - Reset browser state flags
10. **Local Master Announcement** (15) - Local master browser announcement

### 3. Key Features Extracted (As Requested)

#### Server Detection Indicators
- **Apple Hosts**: `ServerTypeFlags.IsAppleServer` (bit 6)
- **Windows Hosts**: Combined flags check for workstation, NT workstation, or Windows 95
- **Print Queue Servers**: `ServerTypeFlags.IsPrintQueueServer` (bit 9)
- **NT Workstations**: `ServerTypeFlags.IsNTWorkstation` (bit 12)
- **Workstations**: `ServerTypeFlags.IsWorkstation` (bit 0)

#### ServerTypeFlags Structure
Complete extraction of all 25 server type flags from the protocol specification:
- Workstation types (Workstation, NT Workstation, Windows 95, WfW)
- Server types (Server, Domain Controller, Backup Controller, etc.)
- Role types (Master Browser, Backup Browser, Domain Master Browser)
- Specialty types (Print Queue, Dialin, Time Source, DFS)
- Legacy types (Apple, Novell, OSF, VMS)

### 4. Struct Organization
Created separate structs for each message type:
- `CIFSBrowserAnnouncement` - For Host/Domain/LocalMaster announcements
- `CIFSBrowserRequestAnnounce` - Request announcement message
- `CIFSBrowserElectionRequest` - Election request with criteria
- `CIFSBrowserBackupListRequest` - Backup list request
- `CIFSBrowserBackupListResponse` - Backup list with server names
- `CIFSBrowserMasterAnnouncement` - Master browser name announcement
- `CIFSBrowserResetBrowserState` - Browser state reset with flags
- `CIFSBrowserBecomeBackupMsg` - Backup promotion message
- `GenericCIFSBrowser` - Generic container for unknown command types

### 5. Helper Functions
- `parseServerTypeFlags()` - Extracts 25 individual flags from 4-byte field
- `parseElectionCriteria()` - Parses election decision criteria with OS info
- `readNullTerminatedString()` - Reads null-terminated ASCII strings
- `readPaddedString()` - Reads fixed-length null-padded strings
- Individual decoder functions for each message type

### 6. Layer Type Registration
Custom layer type registered using gopacket's `OverrideLayerType()`:
- Layer ID: 150
- Name: "CIFSBrowser"
- Initialized in `init()` function

## Test Coverage
**19 comprehensive unit tests** covering:

1. **Basic Decoding Tests**
   - `TestHostAnnounce` - Complete announcement message parsing
   - `TestElectionRequest` - Election message with criteria
   - `TestBackupListResponse` - Backup server list parsing
   - `TestMasterAnnouncement` - Master browser name
   - `TestBecomeBackup` - Backup promotion message
   - `TestRequestAnnounce` - Request message

2. **Feature Detection Tests**
   - `TestPrintQueueServerDetection` - Print queue flag extraction
   - `TestAppleAndWindowsHostDetection` (5 subtests) - OS detection for:
     - Apple servers
     - Windows NT workstations
     - Windows 95 systems
     - Generic workstations
     - Novell servers

3. **Flag Extraction Tests**
   - `TestResetBrowserState` (4 subtests) - Browser state flags:
     - Demote to backup
     - Flush browse list
     - Stop being LMB
     - All flags combined

4. **String Parsing**
   - `TestCommandTypeString` - Command type enum string representation

## Integration Points

### IEC 62443 Security Zone Analysis
This layer supports device classification for industrial network security analysis:
- Identifies device types (workstation, server, printer)
- Detects operating systems (Apple, Windows, others)
- Extracts server capabilities and roles
- Enables device role classification for zone determination

### Use in Device Classifier
The extracted data can be used to:
1. **Device Type Identification** - via server type flags
2. **OS Detection** - via Windows/Apple host detection
3. **Role Classification** - via browser role flags (master, backup, member)
4. **Capability Assessment** - via server type combinations

## Code Quality
- **Formatting**: All code formatted with `go fmt`
- **Linting**: Passes `go vet`
- **Testing**: All 19 tests pass (100% success)
- **Coverage**: Comprehensive coverage of all message types and key fields
- **Error Handling**: Graceful handling of malformed or truncated packets

## Future Enhancements
1. Add support for NetBIOS-over-TCP/UDP as transport layer
2. Implement SMB (Server Message Block) protocol layer
3. Add correlation with DNS/mDNS for hostname resolution
4. Track domain/workgroup membership for zone classification
