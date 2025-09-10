# Technology Stack

## Language & Runtime
- **Go 1.24.1** - Primary language
- Uses Go modules for dependency management

## Key Dependencies
- **github.com/google/gopacket** - Packet parsing and protocol analysis
- **github.com/mattn/go-sqlite3** - SQLite database driver
- **github.com/spf13/cobra** - CLI framework
- **github.com/rs/zerolog** - Structured logging

## Architecture Patterns
- **Repository Pattern** - Database abstraction layer
- **Dependency Injection** - Testable component wiring
- **Interface-First Design** - All core logic behind interfaces
- **London School TDD** - Mock-driven development and testing
- **Plugin Architecture** - Extensible protocol and analysis modules for industrial protocols

## IEC 62443 Technical Requirements

### Industrial Protocol Support (Planned)
- **EtherNet/IP** - Priority #1: Industrial Ethernet protocol (TCP port 44818, UDP port 2222)
- **OPC UA** - Priority #2: Machine-to-machine communication (TCP port 4840)
- **Modbus TCP/RTU** - Common industrial communication protocol (TCP port 502)
- **PROFINET** - Process field network protocol
- **DNP3** - Distributed Network Protocol for SCADA (TCP/UDP port 20000)
- **IEC 61850** - Power system automation

### Security Zone Analysis Components
- **Device Classifier** - Identifies device types via protocol usage and communication patterns
- **Boundary Detector** - Detects zone boundaries at routers, firewalls, and VLAN changes
- **Security Requirements Inferrer** - Determines device security requirements based on type/role
- **Zone Classifier** - Combines topology analysis with device classification for SL 1-4 zones
- **Compliance Checker** - Validates against IEC 62443 requirements
- **PDF Report Generator** - Creates audit reports in PDF format

## Build Commands

### Development Build
```bash
go build -o pcap-importer ./cmd/importer
```

### Production Build (optimized)
```bash
go build -ldflags="-s -w" -o pcap-importer ./cmd/importer
```

### Testing
```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run specific package tests
go test ./internal/parser
```

### Common Development Tasks
```bash
# Format code
go fmt ./...

# Vet code for issues
go vet ./...

# Tidy dependencies
go mod tidy

# Download dependencies
go mod download
```

## Database
- **SQLite** as primary storage backend
- Repository pattern allows for easy database backend swapping
- Batch operations for performance optimization

### IEC 62443 Data Models (Planned)
- **SecurityZone** - Zone classification and security levels
- **IndustrialDevice** - Device types, roles, and security attributes
- **NetworkBoundary** - Zone boundaries and conduits
- **ComplianceResult** - Audit findings and recommendations
- **RiskAssessment** - Security risk evaluations per zone