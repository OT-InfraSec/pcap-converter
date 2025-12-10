# CIFS Browser Integration Architecture

## Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        Packet Capture                            │
│              (UDP port 137 - NetBIOS Name Service)              │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
        ┌────────────────────────────────────┐
        │   GoPacketParser.parsePackets()    │
        │   - Identifies UDP port 137        │
        │   - Extracts CIFS Browser data     │
        └────────────────┬───────────────────┘
                         │
                         ▼
    ┌────────────────────────────────────────┐
    │ IndustrialProtocolParserImpl            │
    │ .ParseIndustrialProtocols()            │
    │ .parseCIFSBrowser()                    │
    │                                        │
    │ Returns:                               │
    │ IndustrialProtocolInfo {               │
    │   Protocol: "CIFSBROWSER"              │
    │   Port: 137                            │
    │   DeviceIdentity: {                    │
    │     server_name: string                │
    │     is_workstation: bool               │
    │     is_printer: bool                   │
    │     is_domain_controller: bool         │
    │     ...                                │
    │   }                                    │
    │ }                                      │
    └────────────────┬───────────────────────┘
                     │
                     ▼
    ┌─────────────────────────────────────────┐
    │ DeviceClassifierImpl                     │
    │ .AnalyzeProtocolUsage()                 │
    │ .analyzeCIFSBrowserProtocol()           │
    │                                         │
    │ Input: IndustrialProtocolInfo           │
    │ Output: ProtocolAnalysisResult {        │
    │   DeviceTypeHints: []                   │
    │   RoleHints: []                         │
    │   SecurityIndicators: {}                │
    │ }                                       │
    └────────────────┬────────────────────────┘
                     │
                     ▼
    ┌──────────────────────────────────────┐
    │ CIFSBrowserClassifier                │
    │ .ClassifyFromCIFSBrowserAnnouncement()│
    │                                      │
    │ Returns:                             │
    │ CIFSBrowserClassificationResult {    │
    │   DeviceType: {                      │
    │     Type: IndustrialDeviceType       │
    │     Confidence: float64              │
    │   }                                  │
    │   Role: {                            │
    │     Role: IndustrialDeviceRole       │
    │     Confidence: float64              │
    │   }                                  │
    │   OSType: {                          │
    │     OSType: string                   │
    │     Confidence: float64              │
    │   }                                  │
    │ }                                    │
    └────────────────┬─────────────────────┘
                     │
                     ▼
    ┌──────────────────────────────────────┐
    │ Device Model Update                  │
    │ - Device Type: Printer, Controller,  │
    │   Workstation, I/O Device            │
    │ - Device Role: Controller, Operator, │
    │   FieldDevice, Engineer              │
    │ - OS: Windows, Apple, Novell         │
    └──────────────────────────────────────┘
```

## Component Interaction

```
Packet Data Flow:
  Packet → GoPacketParser → IndustrialParser → DeviceClassifier → CIFSBrowserClassifier
                              ↓                                        ↓
                    IndustrialProtocolInfo ──────────────────────────────→
                                                                  Classification Result
                                                                        ↓
                                                               Industrial Device Model
```

## Classification Logic

```
Server Type Flags (from CIFS Browser)
        │
        ├─→ IsPrintQueueServer=true ────→ DeviceTypePrinter (0.85)
        │
        ├─→ IsDomainController=true ────→ DeviceTypeDomainController (0.90)
        │
        ├─→ IsWorkstation/IsNTWorkstation ──→ DeviceTypeEngWorkstation (0.60)
        │
        ├─→ IsServer/IsNTServer ────→ DeviceTypeIODevice (0.55)
        │
        └─→ Is[Master|Backup]Browser ──→ RoleController (0.75)

OS Detection:
        │
        ├─→ IsAppleServer ────→ Apple (0.90)
        ├─→ IsNTWorkstation ──→ Windows (0.80)
        ├─→ IsNTServer ──────→ Windows (0.85)
        ├─→ IsWfwServer ─────→ Windows (0.70)
        └─→ IsNovaServer ────→ Novell (0.80)
```

## Integration Points Summary

| Component | Role | Status |
|-----------|------|--------|
| `lib/layers/cifsbrowser.go` | Protocol layer decoding | ✅ Implemented |
| `internal/parser/industrial_parser.go` | Packet extraction | ✅ Integrated |
| `internal/iec62443/device_classifier_impl.go` | Protocol analysis | ✅ Integrated |
| `internal/iec62443/cifsbrowser_classifier.go` | Device classification | ✅ Implemented |
| `lib/model/industrial_device.go` | Device types | ✅ Extended |

## Test Coverage

```
Protocol Layer Tests:        19 tests
├─ Command Type Tests:       10 tests
├─ Device Detection Tests:   5 tests
└─ Edge Case Tests:          4 tests

Classifier Tests:            14 tests
├─ Device Type Classification: 7 tests
├─ Role Classification:       3 tests
├─ OS Detection Tests:        2 tests
└─ Integration Tests:         2 tests

Total:                       33 tests ✅ ALL PASSING
```

## Confidence Scoring Rules

### Device Type Confidence
- **Printer** (IsPrintQueueServer): 0.85
- **DomainController** (IsDomainController): 0.90
- **EngWorkstation** (IsWorkstation): 0.60
- **IODevice** (IsServer): 0.55
- **Unknown** (No flags): 0.10

### Role Confidence
- **RoleController** (Domain Controller): 0.85
- **RoleController** (Master Browser): 0.75
- **RoleFieldDevice** (Print Queue): 0.80
- **RoleOperator** (Workstation): 0.65

### OS Detection Confidence
- **Apple**: 0.90
- **Windows** (NT Server): 0.85
- **Windows** (NT Workstation): 0.80
- **Windows** (WFW): 0.70
- **Novell**: 0.80
- **Unknown**: 0.20

## Network Communication Patterns

```
CIFS Browser Typical Communication:

Workstation → Network (Broadcast/Multicast)
├─ Host Announce (periodic, ~12 minutes)
├─ Election Request (during browser election)
└─ Backup List Request (to master browser)

Domain Controller → Network
├─ Domain Announcement
├─ Master Announcement
└─ Reset Browser State

Network Device → Network
└─ Backup Browser Responses
```

## Security Indicators Set

When CIFS Browser is detected:

```
SecurityInfo {
  "cifs_browser_detected": true,
  "windows_network_protocol": true,
  "network_discovery_detected": true
}

AdditionalData {
  "command": string,           // Command type
  "os_version": string,        // e.g., "6.1" for Windows 7
}

DeviceIdentity {
  "server_name": string,
  "is_workstation": bool,
  "is_printer": bool,
  "is_domain_controller": bool,
  "is_apple": bool,
  // ... other flags
}
```
