# Industrial Protocol Parser Documentation

## Overview

The Industrial Protocol Parser provides comprehensive support for IEC 62443 device classification and industrial protocol detection. It extends the existing PCAP importer to identify industrial devices and classify them based on protocol usage patterns, with initial support for EtherNet/IP and OPC UA protocols.

## Architecture

The industrial protocol parsing system consists of several components:

### Core Components

1. **Protocol Layer Validators** (`lib/layers/`)
   - `ethernetip.go`: EtherNet/IP protocol parsing with comprehensive validation
   - `opcua.go`: OPC UA protocol parsing with security analysis

2. **Industrial Protocol Parser** (`internal/parser/industrial_parser.go`)
   - Main parsing engine for industrial protocols
   - Device classification based on protocol patterns
   - Communication pattern analysis
   - Configurable parsing options

3. **Repository Extensions** (`internal/repository/sqlite_repository_industrial_methods.go`)
   - Industrial device information storage
   - Protocol usage statistics
   - Communication pattern persistence
   - Industrial protocol information tracking

4. **Device Classification** (`internal/iec62443/`)
   - Device type detection algorithms
   - Confidence scoring for classifications
   - Communication pattern analysis

## Configuration

### IndustrialParserConfig

The parser supports extensive configuration through the `IndustrialParserConfig` struct:

```go
type IndustrialParserConfig struct {
    // Protocol enablement
    EnableEtherNetIP bool `json:"enable_ethernetip"`
    EnableOPCUA      bool `json:"enable_opcua"`
    EnableModbus     bool `json:"enable_modbus"`
    EnableDNP3       bool `json:"enable_dnp3"`
    EnableS7         bool `json:"enable_s7"`

    // Confidence thresholds
    ConfidenceThreshold               float64 `json:"confidence_threshold"`
    MinDeviceClassificationConfidence float64 `json:"min_device_classification_confidence"`

    // Performance optimization
    MaxPacketsPerFlow          int  `json:"max_packets_per_flow"`
    MaxConcurrentAnalysis      int  `json:"max_concurrent_analysis"`
    EnableCaching              bool `json:"enable_caching"`
    CacheExpirationMinutes     int  `json:"cache_expiration_minutes"`

    // Analysis depth
    EnableDeepPacketInspection bool `json:"enable_deep_packet_inspection"`
    EnableDeviceFingerprinting bool `json:"enable_device_fingerprinting"`
    EnableSecurityAnalysis     bool `json:"enable_security_analysis"`

    // Error handling
    MaxErrorsPerFlow int    `json:"max_errors_per_flow"`
    ContinueOnError  bool   `json:"continue_on_error"`
    LogLevel         string `json:"log_level"`
}
```

### Default Configuration

```go
config := DefaultIndustrialParserConfig()
// Returns:
// - EnableEtherNetIP: true
// - EnableOPCUA: true
// - EnableModbus: true
// - ConfidenceThreshold: 0.7
// - EnableCaching: true
// - EnableDeepPacketInspection: true
// - ContinueOnError: true
```

## Usage

### Basic Usage

```go
// Create parser with default configuration
parser := parser.NewIndustrialProtocolParser()

// Parse packets for industrial protocols
protocols, err := parser.ParseIndustrialProtocols(packet)
if err != nil {
    log.Printf("Parse error: %v", err)
}

for _, protocol := range protocols {
    log.Printf("Detected %s protocol on port %d with confidence %.2f", 
               protocol.Protocol, protocol.Port, protocol.Confidence)
}
```

### Custom Configuration

```go
// Create custom configuration
config := IndustrialParserConfig{
    EnableEtherNetIP:    true,
    EnableOPCUA:         true,
    EnableModbus:        false,
    ConfidenceThreshold: 0.8,
    EnableCaching:       true,
    ContinueOnError:     false,
}

// Create parser with custom config
parser := parser.NewIndustrialProtocolParserWithConfig(config)
```

### Device Classification

```go
// Classify devices based on protocol usage
deviceType := parser.DetectDeviceType(protocols, flows)

// Analyze communication patterns
patterns := parser.AnalyzeCommunicationPatterns(flows)

// Generate protocol usage statistics
stats, err := parser.CollectProtocolUsageStats(deviceID, protocols)
```

## Protocol Support

### EtherNet/IP

The EtherNet/IP implementation provides:

- **Header Validation**: Comprehensive validation of EtherNet/IP headers
- **CIP Message Parsing**: Support for CIP (Common Industrial Protocol) messages  
- **Device Identity Extraction**: Vendor ID, Product Code, Serial Number
- **Service Classification**: Explicit messaging, implicit I/O, discovery
- **Security Analysis**: Basic security policy detection

**Supported Ports**: 44818 (TCP), 2222 (UDP)

**Detection Features**:
- Command classification (ListIdentity, SendRRData, SendUnitData)
- CIP service identification
- Real-time data vs configuration message detection
- Device fingerprinting based on identity response

### OPC UA

The OPC UA implementation provides:

- **Message Type Detection**: HEL, ACK, OPN, CLO, MSG message types
- **Security Policy Analysis**: Security policy URI extraction and analysis
- **Service Request Classification**: Read, Write, Call, Subscription services
- **Certificate Analysis**: Client/Server certificate presence detection
- **Session Management**: Session and subscription tracking

**Supported Ports**: 4840 (TCP)

**Detection Features**:
- Handshake message identification
- Secure channel analysis
- Service call classification
- Security mode detection (None, Sign, SignAndEncrypt)

## Error Handling

### Error Types

The system defines specific error types for robust error handling:

```go
type IndustrialProtocolError struct {
    Protocol    string
    Packet      gopacket.Packet
    Err         error
    Context     string
    Recoverable bool
    Timestamp   time.Time
}
```

### Error Handlers

- **NoOpErrorHandler**: Ignores all errors (default for production)
- **IndustrialErrorHandler**: Logs errors and implements threshold-based stopping
- **Custom Error Handlers**: Implement `ErrorHandler` interface

### Configuration Options

- `ContinueOnError`: Whether to continue parsing after errors
- `MaxErrorsPerFlow`: Maximum errors before stopping flow analysis
- `LogLevel`: Error logging verbosity

## CLI Integration

### Import with Industrial Analysis

```bash
# Import PCAP with industrial protocol analysis
./importer import --industrial --db-path industrial.sqlite capture.pcap
```

### Device Listing

```bash
# List all industrial devices
./importer industrial list-devices --db-path industrial.sqlite

# List devices by type
./importer industrial list-devices-by-type PLC --db-path industrial.sqlite

# Show protocol usage statistics
./importer industrial protocol-stats --db-path industrial.sqlite
```

### Output Formats

- **Table Format** (default): Human-readable tabular output
- **JSON Format**: Machine-readable JSON output for integration

## Data Models

### IndustrialDeviceInfo

```go
type IndustrialDeviceInfo struct {
    DeviceAddress   string               `json:"device_address"`
    DeviceType      IndustrialDeviceType `json:"device_type"`
    Role            IndustrialDeviceRole `json:"role"`
    Confidence      float64              `json:"confidence"`
    Protocols       []string             `json:"protocols"`
    SecurityLevel   SecurityLevel        `json:"security_level"`
    Vendor          string               `json:"vendor"`
    ProductName     string               `json:"product_name"`
    SerialNumber    string               `json:"serial_number"`
    FirmwareVersion string               `json:"firmware_version"`
    LastSeen        time.Time            `json:"last_seen"`
    CreatedAt       time.Time            `json:"created_at"`
    UpdatedAt       time.Time            `json:"updated_at"`
}
```

### IndustrialProtocolInfo

```go
type IndustrialProtocolInfo struct {
    Protocol        string                 `json:"protocol"`
    Port            uint16                 `json:"port"`
    Direction       string                 `json:"direction"`
    Timestamp       time.Time              `json:"timestamp"`
    Confidence      float64                `json:"confidence"`
    ServiceType     string                 `json:"service_type"`
    MessageType     string                 `json:"message_type"`
    IsRealTimeData  bool                   `json:"is_real_time"`
    IsDiscovery     bool                   `json:"is_discovery"`
    IsConfiguration bool                   `json:"is_configuration"`
    DeviceIdentity  map[string]interface{} `json:"device_identity"`
    SecurityInfo    map[string]interface{} `json:"security_info"`
    AdditionalData  map[string]interface{} `json:"additional_data"`
}
```

## Database Schema

The industrial features extend the SQLite schema with new tables:

### industrial_devices
- Device information and classifications
- Protocol usage summaries  
- Security level assessments

### industrial_protocol_info
- Detailed protocol detection records
- Per-packet analysis results
- Security and device identity information

### protocol_usage_stats
- Aggregated statistics per device/protocol
- Communication role tracking
- Temporal analysis data

### communication_patterns
- Inter-device communication patterns
- Traffic flow analysis
- Criticality assessments

## Performance Considerations

### Optimization Features

- **Caching**: Protocol and device classification results caching
- **Concurrent Processing**: Configurable concurrent analysis threads
- **Packet Limits**: Configurable packet analysis limits per flow
- **Selective Parsing**: Enable/disable protocols as needed

### Memory Management

- Configurable cache expiration times
- Automatic cache cleanup
- Memory-efficient data structures for large captures

### Scalability

The system is designed to handle:
- Large PCAP files (>1GB)
- High packet rates (>100k packets/second)  
- Long-running analysis sessions
- Multiple concurrent analysis jobs

## Security Considerations

### IEC 62443 Compliance

The implementation follows IEC 62443 security guidelines:

- Device security level assessment
- Security policy analysis for OPC UA
- Insecure configuration detection
- Communication encryption analysis

### Risk Mitigation

- Input validation for all protocol fields
- Bounds checking for buffer operations
- Secure error handling to prevent information leakage
- Logging sanitization for sensitive data

## Troubleshooting

### Common Issues

1. **Low Confidence Scores**: Adjust `ConfidenceThreshold` configuration
2. **Missing Devices**: Check protocol enablement configuration  
3. **Performance Issues**: Enable caching, reduce analysis depth
4. **Parse Errors**: Enable `ContinueOnError` and check log levels

### Debug Configuration

```go
config := IndustrialParserConfig{
    LogLevel:        "debug",
    ContinueOnError: false,
    MaxErrorsPerFlow: 1,
}
```

### Validation

All configuration objects support validation:

```go
if err := config.Validate(); err != nil {
    log.Printf("Configuration error: %v", err)
}
```