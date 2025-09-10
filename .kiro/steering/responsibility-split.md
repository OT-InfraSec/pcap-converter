# Responsibility Split Plan

This document defines the clear separation of responsibilities between the open-source core library and the closed-source web visualizer.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Web Visualizer (Closed-Source)          │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐│
│  │   Web UI/UX     │ │  Visualization  │ │   Reports/PDF   ││
│  │                 │ │                 │ │                 ││
│  │ • File Upload   │ │ • Cytoscape.js  │ │ • PDF Export    ││
│  │ • Auth/Sessions │ │ • Interactive   │ │ • Compliance    ││
│  │ • Device Tables │ │   Topology      │ │   Reports       ││
│  │ • Dashboards    │ │ • Filtering     │ │ • Audit Docs    ││
│  └─────────────────┘ └─────────────────┘ └─────────────────┘│
└─────────────────────────────────────────────────────────────┘
                                │
                                │ Library Import
                                │ github.com/InfraSecConsult/pcap-importer-go
                                ▼
┌─────────────────────────────────────────────────────────────┐
│                 Open-Source Core Library                    │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐│
│  │ PCAP Processing │ │ IEC 62443 Engine│ │  Data Models    ││
│  │                 │ │                 │ │                 ││
│  │ • Packet Parse  │ │ • Zone Classify │ │ • Device/Flow   ││
│  │ • Protocol Anal │ │ • Boundary Det  │ │ • Security Zone ││
│  │ • Device Disc   │ │ • Compliance    │ │ • Compliance    ││
│  │ • Flow Analysis │ │ • Risk Assess   │ │ • Shared Schema ││
│  └─────────────────┘ └─────────────────┘ └─────────────────┘│
└─────────────────────────────────────────────────────────────┘
```

## Open-Source Core Responsibilities

### 1. PCAP Processing Engine
**Location**: `internal/parser/`, `lib/layers/`, `lib/pcapgo/`

**Responsibilities**:
- PCAP/PCAPNG file parsing using gopacket
- Protocol layer analysis (Ethernet, IP, TCP, UDP, etc.)
- Industrial protocol detection and parsing
- Packet metadata extraction and validation
- Performance-optimized batch processing

**Key Interfaces**:
```go
type PacketParser interface {
    ParseFile(filename string) ([]Packet, error)
    ParseStream(reader io.Reader) ([]Packet, error)
}
```

### 2. Device Discovery and Analysis
**Location**: `internal/parser/`, `lib/model/`

**Responsibilities**:
- MAC/IP address extraction and correlation
- Device type identification via protocol usage patterns
- Industrial device classification (PLCs, HMIs, SCADA, workstations)
- Device relationship mapping and communication patterns
- DNS correlation and hostname resolution

**Key Data Models**:
```go
type Device struct {
    Address           string
    AddressType       string
    MacAddresses      []string
    DeviceType        IndustrialDeviceType
    SecurityRole      SecurityRole
    Protocols         []string
    // ... other fields
}
```

### 3. IEC 62443 Compliance Engine
**Location**: `internal/iec62443/` (planned)

**Responsibilities**:
- Security zone classification (SL 1-4)
- Network boundary detection (routers, firewalls, VLANs)
- Industrial protocol security analysis
- Compliance rule validation against IEC 62443 standards
- Risk assessment and security requirement inference

**Key Interfaces**:
```go
type ZoneClassifier interface {
    ClassifySecurityZones(devices []Device, flows []Flow) ([]SecurityZone, error)
}

type ComplianceChecker interface {
    ValidateCompliance(zones []SecurityZone) (ComplianceResult, error)
}
```

### 4. Data Persistence Layer
**Location**: `internal/repository/`, `lib/model/`

**Responsibilities**:
- SQLite database schema definition
- Repository pattern implementation for data access
- Batch operations for performance optimization
- Data model validation and integrity
- Migration support for schema evolution

**Key Interfaces**:
```go
type Repository interface {
    SaveDevices(devices []Device) error
    SaveFlows(flows []Flow) error
    SaveSecurityZones(zones []SecurityZone) error
    GetDevicesByType(deviceType IndustrialDeviceType) ([]Device, error)
    // ... other CRUD operations
}
```

### 5. CLI Application
**Location**: `cmd/importer/`

**Responsibilities**:
- Command-line interface using Cobra framework
- Batch processing workflows
- Configuration management
- Progress reporting and logging
- Integration with CI/CD pipelines

### 6. Library API
**Location**: `lib/` (public interfaces)

**Responsibilities**:
- Public Go API for external consumption
- Stable interfaces for web visualizer integration
- Documentation and examples
- Backward compatibility guarantees

## Web Visualizer Responsibilities (Closed-Source)

### 1. Web Application Framework
**Location**: `web_visualizer/main.go`, `web_visualizer/handler.go`

**Responsibilities**:
- HTTP server setup and routing (Echo framework)
- Request/response handling
- Middleware for logging, security, CORS
- Error handling and user feedback
- Session management and state

### 2. Authentication and Security
**Location**: `web_visualizer/auth.go`

**Responsibilities**:
- User authentication system
- Session-based security with secure cookies
- Access control and authorization
- HTTPS/TLS certificate management
- Security headers and CSRF protection

### 3. File Upload and Processing
**Location**: `web_visualizer/handler.go`

**Responsibilities**:
- PCAP file upload handling (200MB limit)
- File validation and security checks
- Progress tracking for large file processing
- Integration with open-source processing engine
- Temporary file management and cleanup

### 4. Network Topology Visualization
**Location**: `web_visualizer/topology.go`, `web_visualizer/static/js/`

**Responsibilities**:
- Cytoscape.js integration and configuration
- Interactive network graph rendering
- Node positioning and layout algorithms (Dagre)
- Device relationship visualization
- Zoom, pan, and selection controls

### 5. Device Management Interface
**Location**: `web_visualizer/device_table_view.go`, `web_visualizer/templates/`

**Responsibilities**:
- Device table rendering and pagination
- Advanced filtering and search capabilities
- Device detail views and editing
- Bulk operations and selections
- Export functionality (CSV, JSON)

### 6. Dashboard and Analytics
**Location**: `web_visualizer/templates/`, `web_visualizer/static/`

**Responsibilities**:
- Security dashboard with key metrics
- IEC 62443 compliance status overview
- Risk assessment summaries
- Protocol distribution charts
- Network health indicators

### 7. Report Generation
**Location**: `web_visualizer/` (planned)

**Responsibilities**:
- PDF report generation for compliance audits
- Customizable report templates
- Executive summaries and technical details
- Compliance findings and recommendations
- Audit trail and documentation

### 8. Caching and Performance
**Location**: `web_visualizer/cache.go`

**Responsibilities**:
- Web-specific caching strategies
- Session data management
- Static asset optimization
- Database query optimization for web use cases
- Memory management for large datasets

## Integration Points

### 1. Library Import
```go
import "github.com/InfraSecConsult/pcap-importer-go/lib/model"
import "github.com/InfraSecConsult/pcap-importer-go/internal/parser"
```

### 2. Shared Database Schema
- Both components use identical SQLite schema
- Web visualizer reads data written by core library
- No direct database coupling, only through shared models

### 3. API Boundaries
```go
// Web visualizer calls core library functions
parser := gopacket_parser.NewGopacketParser()
devices, err := parser.ParseFile(uploadedFile)

// Core library returns structured data
zones, err := zoneClassifier.ClassifySecurityZones(devices, flows)
```

### 4. Configuration Sharing
- Shared configuration for database paths
- Common logging configuration
- Consistent error handling patterns

## Development Workflow

### Open-Source Development
1. **Library-First**: All core functionality developed as library
2. **Interface-Driven**: Public APIs defined before implementation
3. **Test Coverage**: Comprehensive unit and integration tests
4. **Documentation**: Public API documentation and examples
5. **Versioning**: Semantic versioning for library releases

### Web Visualizer Development
1. **Consumer-Driven**: Develop against stable library interfaces
2. **UI/UX Focus**: Concentrate on user experience and visualization
3. **Integration Testing**: E2E tests with Playwright
4. **Performance**: Optimize for web-specific use cases
5. **Commercial Features**: Advanced analytics and reporting

### Release Coordination
1. **Library Releases**: Independent versioning and release cycle
2. **Web Visualizer Updates**: Update library dependency as needed
3. **Breaking Changes**: Coordinate major version updates
4. **Feature Development**: Core features in library, UI in visualizer

## Benefits of This Split

### For Open-Source Community
- **Reusable Library**: Can integrate PCAP analysis into other tools
- **CLI Tool**: Scriptable automation and CI/CD integration
- **Extensible**: Plugin architecture for custom protocols
- **Transparent**: Full access to analysis algorithms and data models

### For Commercial Product
- **Rapid Development**: Focus on UI/UX without reimplementing core logic
- **Differentiation**: Advanced visualization and reporting features
- **Maintenance**: Core library maintained by community
- **Integration**: Easy to add new data sources and analysis methods

### For Both
- **Shared Quality**: Core library benefits from community testing
- **Innovation**: New features can start in either component
- **Compatibility**: Shared data models ensure seamless integration
- **Scalability**: Clear separation enables independent scaling