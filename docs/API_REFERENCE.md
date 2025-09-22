# Industrial Protocol Parser API Reference

## Table of Contents
1. [Parser Interface](#parser-interface)
2. [Configuration](#configuration)
3. [Protocol Layers](#protocol-layers)
4. [Repository Methods](#repository-methods)
5. [Error Handling](#error-handling)
6. [Models](#models)

## Parser Interface

### IndustrialProtocolParser

Main interface for industrial protocol parsing and device classification.

#### Constructor Methods

```go
// NewIndustrialProtocolParser creates a new parser with default configuration
func NewIndustrialProtocolParser() *IndustrialProtocolParser

// NewIndustrialProtocolParserWithConfig creates a parser with custom configuration
func NewIndustrialProtocolParserWithConfig(config IndustrialParserConfig) *IndustrialProtocolParser

// NewIndustrialProtocolParserWithDependencies creates a parser with injected dependencies
func NewIndustrialProtocolParserWithDependencies(
    config IndustrialParserConfig,
    classifier DeviceClassifier,
    analyzer CommunicationPatternAnalyzer,
    errorHandler ErrorHandler,
) *IndustrialProtocolParser
```

#### Core Parsing Methods

```go
// ParseIndustrialProtocols extracts industrial protocol information from a packet
func (p *IndustrialProtocolParser) ParseIndustrialProtocols(packet gopacket.Packet) ([]*IndustrialProtocolInfo, error)

// DetectDeviceType classifies device based on protocol patterns
func (p *IndustrialProtocolParser) DetectDeviceType(protocols []*IndustrialProtocolInfo, flows []FlowInfo) IndustrialDeviceType

// AnalyzeCommunicationPatterns identifies communication patterns between devices
func (p *IndustrialProtocolParser) AnalyzeCommunicationPatterns(flows []FlowInfo) ([]*CommunicationPattern, error)

// CollectProtocolUsageStats generates usage statistics for a device
func (p *IndustrialProtocolParser) CollectProtocolUsageStats(deviceID string, protocols []*IndustrialProtocolInfo) (*ProtocolUsageStats, error)
```

#### Flow Analysis Methods

```go
// ExtractFlowInfo extracts flow information from packets
func (p *IndustrialProtocolParser) ExtractFlowInfo(packets []gopacket.Packet) ([]FlowInfo, error)

// ClassifyDeviceRole determines if device is Client, Server, or Master/Slave
func (p *IndustrialProtocolParser) ClassifyDeviceRole(deviceAddr string, flows []FlowInfo) IndustrialDeviceRole

// AssessSecurityLevel evaluates security posture based on communications
func (p *IndustrialProtocolParser) AssessSecurityLevel(protocols []*IndustrialProtocolInfo) SecurityLevel
```

#### Utility Methods

```go
// IsIndustrialPacket quickly checks if packet contains industrial protocols
func (p *IndustrialProtocolParser) IsIndustrialPacket(packet gopacket.Packet) bool

// GetSupportedProtocols returns list of supported protocol names
func (p *IndustrialProtocolParser) GetSupportedProtocols() []string

// GetConfiguration returns current parser configuration
func (p *IndustrialProtocolParser) GetConfiguration() IndustrialParserConfig

// UpdateConfiguration updates parser configuration at runtime
func (p *IndustrialProtocolParser) UpdateConfiguration(config IndustrialParserConfig) error
```

## Configuration

### IndustrialParserConfig

```go
type IndustrialParserConfig struct {
    // Protocol enablement flags
    EnableEtherNetIP bool `json:"enable_ethernetip"`
    EnableOPCUA      bool `json:"enable_opcua"`
    EnableModbus     bool `json:"enable_modbus"`
    EnableDNP3       bool `json:"enable_dnp3"`
    EnableS7         bool `json:"enable_s7"`

    // Confidence and classification thresholds
    ConfidenceThreshold               float64 `json:"confidence_threshold"`
    MinDeviceClassificationConfidence float64 `json:"min_device_classification_confidence"`

    // Performance optimization settings
    MaxPacketsPerFlow          int  `json:"max_packets_per_flow"`
    MaxConcurrentAnalysis      int  `json:"max_concurrent_analysis"`
    EnableCaching              bool `json:"enable_caching"`
    CacheExpirationMinutes     int  `json:"cache_expiration_minutes"`

    // Analysis depth configuration
    EnableDeepPacketInspection bool `json:"enable_deep_packet_inspection"`
    EnableDeviceFingerprinting bool `json:"enable_device_fingerprinting"`
    EnableSecurityAnalysis     bool `json:"enable_security_analysis"`

    // Error handling configuration
    MaxErrorsPerFlow int    `json:"max_errors_per_flow"`
    ContinueOnError  bool   `json:"continue_on_error"`
    LogLevel         string `json:"log_level"`
}

// Validate validates the configuration and returns any errors
func (c *IndustrialParserConfig) Validate() error

// DefaultIndustrialParserConfig returns sensible default configuration
func DefaultIndustrialParserConfig() IndustrialParserConfig
```

## Protocol Layers

### EtherNet/IP Layer

```go
// EtherNetIPLayer represents the EtherNet/IP protocol layer
type EtherNetIPLayer struct {
    Header      EtherNetIPHeader
    CIPData     CIPData
    DeviceInfo  DeviceIdentityInfo
    LayerType   gopacket.LayerType
}

// Validate validates the EtherNet/IP packet structure
func (layer *EtherNetIPLayer) Validate() error

// ExtractDeviceIdentity extracts device identity information
func (layer *EtherNetIPLayer) ExtractDeviceIdentity() (*DeviceIdentityInfo, error)

// GetServiceType returns the CIP service type
func (layer *EtherNetIPLayer) GetServiceType() string

// IsRealTimeData determines if this is real-time I/O data
func (layer *EtherNetIPLayer) IsRealTimeData() bool

// IsDiscoveryMessage determines if this is a discovery message
func (layer *EtherNetIPLayer) IsDiscoveryMessage() bool
```

#### EtherNet/IP Data Structures

```go
type EtherNetIPHeader struct {
    Command       uint16
    Length        uint16
    SessionHandle uint32
    Status        uint32
    SenderContext [8]byte
    Options       uint32
}

type CIPData struct {
    Service     uint8
    RequestPath []byte
    Data        []byte
}

type DeviceIdentityInfo struct {
    VendorID         uint16
    DeviceType       uint16
    ProductCode      uint16
    MajorRevision    uint8
    MinorRevision    uint8
    Status           uint16
    SerialNumber     uint32
    ProductNameLen   uint8
    ProductName      string
    State            uint8
}
```

### OPC UA Layer

```go
// OPCUALayer represents the OPC UA protocol layer
type OPCUALayer struct {
    Header         OPCUAHeader
    MessageType    string
    SecurityInfo   SecurityInfo
    ServiceInfo    ServiceInfo
    LayerType      gopacket.LayerType
}

// Validate validates the OPC UA packet structure  
func (layer *OPCUALayer) Validate() error

// GetMessageType returns the OPC UA message type
func (layer *OPCUALayer) GetMessageType() string

// ExtractSecurityInfo extracts security-related information
func (layer *OPCUALayer) ExtractSecurityInfo() (*SecurityInfo, error)

// ExtractServiceInfo extracts service request/response information
func (layer *OPCUALayer) ExtractServiceInfo() (*ServiceInfo, error)

// IsSecureChannel determines if this uses secure channel
func (layer *OPCUALayer) IsSecureChannel() bool
```

#### OPC UA Data Structures

```go
type OPCUAHeader struct {
    MessageType   [3]byte
    ChunkType     byte
    MessageSize   uint32
    SecureChannelID uint32
}

type SecurityInfo struct {
    SecurityPolicyURI string
    SecurityMode     string
    HasClientCert    bool
    HasServerCert    bool
    EncryptionAlg    string
    SigningAlg       string
}

type ServiceInfo struct {
    ServiceType    string
    RequestID      uint32
    RequestHandle  uint32
    IsRequest      bool
    NodeIDCount    int
    AttributeIDs   []uint32
}
```

## Repository Methods

### Industrial Device Repository

```go
// SaveIndustrialDeviceInfo stores industrial device information
func (r *SQLiteRepository) SaveIndustrialDeviceInfo(deviceInfo *IndustrialDeviceInfo) error

// GetIndustrialDeviceInfo retrieves device information by address
func (r *SQLiteRepository) GetIndustrialDeviceInfo(deviceAddress string) (*IndustrialDeviceInfo, error)

// GetIndustrialDevicesByType retrieves all devices of specified type
func (r *SQLiteRepository) GetIndustrialDevicesByType(deviceType IndustrialDeviceType) ([]*IndustrialDeviceInfo, error)

// UpdateIndustrialDeviceLastSeen updates the last seen timestamp
func (r *SQLiteRepository) UpdateIndustrialDeviceLastSeen(deviceAddress string) error
```

### Protocol Information Repository

```go
// SaveIndustrialProtocolInfo stores protocol detection results
func (r *SQLiteRepository) SaveIndustrialProtocolInfo(protocolInfo *IndustrialProtocolInfo) error

// GetIndustrialProtocolInfos retrieves protocol information with filters
func (r *SQLiteRepository) GetIndustrialProtocolInfos(
    protocol string, 
    deviceAddress string, 
    limit int,
) ([]*IndustrialProtocolInfo, error)

// GetProtocolUsageStats retrieves usage statistics for a device
func (r *SQLiteRepository) GetProtocolUsageStats(deviceAddress string) ([]*ProtocolUsageStats, error)

// SaveProtocolUsageStats stores aggregated protocol statistics
func (r *SQLiteRepository) SaveProtocolUsageStats(stats *ProtocolUsageStats) error
```

### Communication Pattern Repository

```go
// SaveCommunicationPattern stores communication pattern information
func (r *SQLiteRepository) SaveCommunicationPattern(pattern *CommunicationPattern) error

// GetCommunicationPatterns retrieves communication patterns with filters
func (r *SQLiteRepository) GetCommunicationPatterns(
    sourceDevice string,
    targetDevice string,
    protocol string,
) ([]*CommunicationPattern, error)

// GetCriticalCommunications retrieves high-criticality communications
func (r *SQLiteRepository) GetCriticalCommunications() ([]*CommunicationPattern, error)
```

## Error Handling

### Error Handler Interface

```go
type ErrorHandler interface {
    HandleError(err error, packet gopacket.Packet, context string) error
    ShouldContinue(err error) bool
    GetErrorCount() int
    Reset()
}
```

### Industrial Error Handler

```go
type IndustrialErrorHandler struct {
    maxErrors       int
    errorCount      int
    continueOnError bool
    logger          *log.Logger
}

// NewIndustrialErrorHandler creates a new industrial-specific error handler
func NewIndustrialErrorHandler(maxErrors int, continueOnError bool) *IndustrialErrorHandler

// HandleError processes an error and determines continuation
func (h *IndustrialErrorHandler) HandleError(err error, packet gopacket.Packet, context string) error

// ShouldContinue determines if processing should continue after error
func (h *IndustrialErrorHandler) ShouldContinue(err error) bool

// GetErrorCount returns current error count
func (h *IndustrialErrorHandler) GetErrorCount() int

// Reset resets error counters
func (h *IndustrialErrorHandler) Reset()
```

### Custom Error Types

```go
type IndustrialProtocolError struct {
    Protocol    string
    Packet      gopacket.Packet
    Err         error
    Context     string
    Recoverable bool
    Timestamp   time.Time
}

func (e *IndustrialProtocolError) Error() string
func (e *IndustrialProtocolError) Unwrap() error
func (e *IndustrialProtocolError) IsRecoverable() bool

// Error constructors
func NewProtocolValidationError(protocol string, packet gopacket.Packet, details string) *IndustrialProtocolError
func NewDeviceClassificationError(deviceAddr string, reason string) *IndustrialProtocolError
func NewConfigurationError(field string, value interface{}) *IndustrialProtocolError
```

## Models

### Flow Models

```go
type Flow struct {
    ID                  int64
    Source              string
    Destination         string
    Protocol            string
    Packets             int
    Bytes               int
    FirstSeen           time.Time
    LastSeen            time.Time
    SourceDeviceID      int64
    DestinationDeviceID int64
    PacketRefs          []int64
    MinPacketSize       int
    MaxPacketSize       int
    SourcePorts         *Set
    DestinationPorts    *Set

    // Bidirectional statistics
    PacketsClientToServer int `json:"packets_client_to_server"`
    PacketsServerToClient int `json:"packets_server_to_client"`
    BytesClientToServer   int `json:"bytes_client_to_server"`
    BytesServerToClient   int `json:"bytes_server_to_client"`
}

// Validate validates the flow data
func (f *Flow) Validate() error
```

#### Bidirectional Flow Aggregation

The system automatically aggregates bidirectional network flows by canonicalizing flow direction based on service ports. Request-response pairs (e.g., HTTP, OPC UA) are merged into single flow records with separate statistics for each direction.

**Canonicalization Rules:**
- Flows to well-known service ports (80/HTTP, 443/HTTPS, 4840/OPC UA, etc.) are stored with client as source
- Flows between unknown ports use lexicographic ordering of `ip:port` addresses
- Reverse-direction packets update the existing canonical flow with server-to-client statistics

**Example:** HTTP request (192.168.1.10:12345 → 192.168.1.20:80) and response (192.168.1.20:80 → 192.168.1.10:12345) are merged into one flow record with:
- Source: "192.168.1.10:12345" (client)
- Destination: "192.168.1.20:80" (server)
- PacketsClientToServer: 1, BytesClientToServer: 200
- PacketsServerToClient: 1, BytesServerToClient: 1500

### Device Information Models

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

// Validate validates the device information
func (d *IndustrialDeviceInfo) Validate() error

// IsExpired checks if device information is stale
func (d *IndustrialDeviceInfo) IsExpired(timeout time.Duration) bool

// UpdateLastSeen updates the last seen timestamp
func (d *IndustrialDeviceInfo) UpdateLastSeen()
```

### Protocol Information Models

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

// Validate validates the protocol information
func (p *IndustrialProtocolInfo) Validate() error

// GetConfidenceLevel returns human-readable confidence level
func (p *IndustrialProtocolInfo) GetConfidenceLevel() string

// IsHighConfidence checks if confidence meets threshold
func (p *IndustrialProtocolInfo) IsHighConfidence(threshold float64) bool
```

### Enumeration Types

```go
type IndustrialDeviceType int

const (
    DeviceTypeUnknown IndustrialDeviceType = iota
    DeviceTypePLC
    DeviceTypeHMI
    DeviceTypeSCADA
    DeviceTypeDCS
    DeviceTypeSafetyPLC
    DeviceTypeIEDProtection
    DeviceTypeIEDControl
    DeviceTypeRTU
    DeviceTypeSensor
    DeviceTypeActuator
    DeviceTypeGateway
    DeviceTypeHistorian
    DeviceTypeEngWorkstation
    DeviceTypeOpsWorkstation
)

type IndustrialDeviceRole int

const (
    RoleUnknown IndustrialDeviceRole = iota
    RoleClient
    RoleServer
    RoleMaster
    RoleSlave
    RolePeer
)

type SecurityLevel int

const (
    SecurityLevelUnknown SecurityLevel = iota
    SecurityLevel1 // No security
    SecurityLevel2 // Authentication
    SecurityLevel3 // Authentication + Integrity
    SecurityLevel4 // Authentication + Integrity + Confidentiality
)
```

### Usage Statistics Models

```go
type ProtocolUsageStats struct {
    DeviceAddress    string    `json:"device_address"`
    Protocol         string    `json:"protocol"`
    Role             string    `json:"role"`
    TotalPackets     int64     `json:"total_packets"`
    TotalBytes       int64     `json:"total_bytes"`
    UniqueServices   int       `json:"unique_services"`
    ErrorCount       int       `json:"error_count"`
    FirstSeen        time.Time `json:"first_seen"`
    LastSeen         time.Time `json:"last_seen"`
    AvgConfidence    float64   `json:"avg_confidence"`
    IsRealTimeTraffic bool     `json:"is_real_time_traffic"`
}

type CommunicationPattern struct {
    SourceDevice      string    `json:"source_device"`
    TargetDevice      string    `json:"target_device"`
    Protocol          string    `json:"protocol"`
    CommunicationType string    `json:"communication_type"`
    Frequency         int64     `json:"frequency"`
    LastCommunication time.Time `json:"last_communication"`
    IsCritical        bool      `json:"is_critical"`
    IsRegular         bool      `json:"is_regular"`
    SecurityRisk      string    `json:"security_risk"`
}
```

## Constants and Defaults

### Default Values

```go
const (
    DefaultConfidenceThreshold = 0.7
    DefaultMaxPacketsPerFlow   = 1000
    DefaultMaxConcurrentAnalysis = 4
    DefaultCacheExpirationMinutes = 30
    DefaultMaxErrorsPerFlow = 10
)

// Protocol ports
const (
    EtherNetIPTCPPort = 44818
    EtherNetIPUDPPort = 2222
    OPCUATCPPort      = 4840
    ModbusTCPPort     = 502
    DNP3TCPPort       = 20000
    S7TCPPort         = 102
)
```

### Logging Levels

```go
const (
    LogLevelDebug = "debug"
    LogLevelInfo  = "info"
    LogLevelWarn  = "warn"
    LogLevelError = "error"
)
```