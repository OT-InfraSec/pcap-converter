# AGENTS.md - Project Context & Guidelines

This document provides comprehensive context for AI agents working on this project. Read this first for all conversations.

---

## Executive Summary

**Go PCAP Importer** is a high-performance, testable, and extensible open-source library and CLI tool for importing PCAP (packet capture) files into SQL databases and performing **IEC 62443 industrial network security analysis**.

### Primary Goal
**Identify network security zones of industrial networks according to IEC 62443-2 and IEC 62443-3 standards through PCAP file analysis alone.**

This enables comprehensive IEC 62443 compliance audits using only network packet capture data, without requiring direct access to industrial control systems.

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────┐
│   Web Visualizer (Closed-Source)                     │
│   ├─ HTTP Server & Routing                           │
│   ├─ Authentication & Sessions                       │
│   ├─ Network Visualization (Cytoscape.js)            │
│   ├─ Device Tables & Dashboards                      │
│   └─ Report Generation (PDF)                         │
└──────────────────────────────────────────────────────┘
                        │
         Imports as Library: github.com/InfraSecConsult/pcap-importer-go
                        │
┌──────────────────────────────────────────────────────┐
│   Open-Source Core Library (This Project)            │
│   ├─ PCAP Processing Engine (gopacket)               │
│   ├─ Protocol Analysis                               │
│   ├─ Device Discovery & Classification               │
│   ├─ Flow & Communication Analysis                   │
│   ├─ IEC 62443 Compliance Engine (planned)           │
│   ├─ Data Models & Validation                        │
│   ├─ SQLite Repository Layer                         │
│   └─ CLI Tool (Cobra)                                │
└──────────────────────────────────────────────────────┘
         │
         └─ Shared: SQLite Schema + Data Models
```

---

## Project Responsibilities

### Open-Source Core (This Repository)

#### 1. PCAP Processing Engine
**Location**: `internal/parser/`, `lib/layers/`, `lib/pcapgo/`

- PCAP/PCAPNG file parsing using gopacket
- Protocol layer analysis (Ethernet, IP, TCP, UDP, DNS, etc.)
- Industrial protocol detection and parsing
- Packet metadata extraction and validation
- Performance-optimized batch processing

#### 2. Device Discovery & Analysis
**Location**: `internal/parser/`, `lib/model/`

- MAC/IP address extraction and correlation
- Device type identification via protocol usage patterns
- Industrial device classification (PLCs, HMIs, SCADA, workstations)
- Device relationship mapping and communication patterns
- DNS correlation and hostname resolution

#### 3. IEC 62443 Compliance Engine
**Location**: `internal/iec62443/` (currently planned)

- Security zone classification (SL 1-4)
- Network boundary detection (routers, firewalls, VLANs)
- Industrial protocol security analysis
- Compliance rule validation against IEC 62443 standards
- Risk assessment and security requirement inference

#### 4. Data Persistence Layer
**Location**: `internal/repository/`, `lib/model/`

- SQLite database schema definition
- Repository pattern for data access
- Batch operations for performance
- Data model validation and integrity
- Migration support for schema evolution

#### 5. CLI Application
**Location**: `cmd/importer/`

- Command-line interface using Cobra framework
- Batch processing workflows
- Configuration management
- Progress reporting and logging
- CI/CD pipeline integration

#### 6. Public Go Library API
**Location**: `lib/`

- Public Go interfaces for external consumption
- Stable interfaces for web visualizer integration
- Documentation and examples
- Backward compatibility guarantees

### Web Visualizer (Closed-Source)

- Web UI/UX with file upload and management
- Authentication and session management
- Interactive network topology visualization
- Device management and filtering interfaces
- Dashboard with security analytics
- PDF report generation and compliance documentation

---

## Project Structure

### Open-Source Core Structure

```
pcap-importer-go/
├── cmd/
│   └── importer/
│       ├── main.go              # CLI entry point, dependency injection
│       └── main_test.go          # CLI integration tests
│
├── internal/                    # Private application code
│   ├── parser/
│   │   ├── parser.go            # PacketParser interface
│   │   ├── gopacket_parser.go   # Main gopacket implementation
│   │   ├── industrial_parser.go # Industrial protocol parsing
│   │   └── *_test.go            # Tests
│   │
│   ├── repository/
│   │   ├── repository.go        # Repository interface
│   │   ├── sqlite_repository.go # SQLite implementation
│   │   └── *_test.go            # Tests
│   │
│   │   ├── connection_labeler.go # Per-connection protocol label (ConnectionLabeler interface)
│   │   └── industrial_{enip,modbus,dnp3,s7}.go # Map lib/detect messages to IndustrialProtocolInfo
│   │
│   ├── dns/                     # DNS post-processing
│   │   ├── dns_processor.go
│   │   └── dns_processor_impl.go
│   │
│   ├── iec62443/                # IEC 62443 analysis (planned)
│   │   ├── zone_classifier.go
│   │   ├── boundary_detector.go
│   │   └── compliance_checker.go
│   │
│   └── testutil/                # Test utilities
│       └── mock_*.go            # Interface mocks
│
├── lib/                         # Public reusable library code
│   ├── detect/                  # Protocol registry, content probes and OT decoders
│   │   ├── detect.go, default.go    # Registry; hint ports; the default protocol set
│   │   ├── tcptrack.go              # Shared TCP stream tracker core (ordering, limits, partial frames)
│   │   ├── modbus*.go, enip*.go, s7*.go, dnp3*.go  # Probe, decoder and tracker per protocol
│   │   └── *_test.go                # Unit, corpus, fuzz and random-input tests
│   │
│   ├── tcpseq/                  # TCP sequence-number ordering of segments
│   │
│   ├── model/
│   │   ├── device.go            # Device data structures
│   │   ├── flow.go              # Flow data structures
│   │   ├── packet.go            # Packet definitions
│   │   ├── security_zone.go     # IEC 62443 zones (planned)
│   │   ├── set.go               # Set data structure
│   │   └── *_test.go            # Validation tests
│   │
│   ├── helper/
│   │   ├── address.go           # Address parsing utilities
│   │   ├── ringbuffer.go        # Ring buffer implementation
│   │   └── flow_canonicalizer.go # Flow normalization
│   │
│   ├── layers/
│   │   ├── base.go              # Base layer functionality
│   │   ├── http.go              # HTTP protocol layer
│   │   ├── tls.go               # TLS/SSL layer
│   │   ├── dns.go               # DNS layer
│   │   └── *.go                 # Other protocol layers
│   │
│   └── pcapgo/
│       ├── ngread.go            # PCAP-NG reading
│       └── pcapng.go            # PCAP-NG utilities
│
├── scripts/                     # Differential tools: *_demo_pcap.py, *_dump/, compare_*.py
│
├── go.mod / go.sum              # Module definition and dependencies
├── database.sqlite              # Default SQLite database
├── README.md                     # Project documentation
├── LICENSE                       # License file
└── AGENTS.md                     # This file
```

### Web Visualizer Structure (Closed-Source)

```
web_visualizer/
├── main.go                      # Web app entry point
├── handler.go                   # HTTP request handlers
├── auth.go                      # Authentication logic
├── topology.go                  # Topology analysis
├── device_table_view.go         # Device table rendering
├── cache.go                     # Web caching
│
├── static/
│   ├── css/                     # Stylesheets
│   └── js/                      # JavaScript (Cytoscape.js, etc.)
│
├── templates/                   # Go HTML templates
│
├── tests/
│   ├── e2e/                     # Playwright E2E tests
│   └── *_test.go               # Unit tests
│
├── go.mod / go.sum              # Depends on pcap-importer-go
└── playwright.config.ts         # E2E test configuration
```

---

## Technology Stack

### Languages & Runtimes
- **Go 1.24.1+** - Primary backend language
- **Go modules** - Dependency management
- **Node.js** - Frontend tooling and testing

### Core Dependencies

#### Open-Source Core
| Package | Purpose | Version |
|---------|---------|---------|
| `github.com/google/gopacket` | Packet parsing and protocol analysis | Latest |
| `github.com/mattn/go-sqlite3` | SQLite database driver | Latest |
| `github.com/spf13/cobra` | CLI framework | v1.x |
| `github.com/rs/zerolog` | Structured logging | Latest |

#### Web Visualizer
| Package | Purpose | Version |
|---------|---------|---------|
| `github.com/labstack/echo/v4` | HTTP web framework | v4.x |
| `github.com/InfraSecConsult/pcap-importer-go` | Core analysis library | Latest |
| `cytoscape.js` | Network visualization | Latest |
| `@playwright/test` | E2E testing | Latest |

### Database
- **SQLite** - Primary storage backend
- Repository pattern allows easy backend swapping
- Batch operations for performance optimization

---

## Key Features

### ✅ Currently Implemented
- PCAP/PCAPNG file parsing
- Device discovery (MAC/IP addresses)
- Flow analysis (5-tuple communication patterns)
- DNS query analysis and correlation
- Protocol analysis (Ethernet, IPv4/IPv6, TCP, UDP, DNS, HTTP, TLS, mDNS, EIGRP, LLMD, etc.)
- Packet, device, flow, and service extraction
- SQLite persistent storage
- CLI tool for batch processing
- Go library API for programmatic access
- Docker support for containerized deployment
- Multi-tenant support (tenant ID tracking)

### 🔄 In Progress / Planned

#### Phase 1: Enhanced Device Classification
- Industrial protocol detection (EtherNet/IP, OPC UA)
- Industrial device type classification (PLCs, HMIs, SCADA, workstations)
- Device role identification

#### Phase 2: Network Boundary Detection
- Router-based zone separation detection
- Firewall boundary identification
- VLAN-based zone detection

#### Phase 3: Security Zone Classification
- IEC 62443-3-2 Security Level (SL 1-4) classification
- Zone-specific security requirement inference
- Compliance validation

#### Phase 4: Compliance Reporting
- PDF audit report generation
- IEC 62443 compliance findings
- Security recommendations

---

## Integration Points

### Library Import
```go
import "github.com/InfraSecConsult/pcap-importer-go/lib/model"
import "github.com/InfraSecConsult/pcap-importer-go/internal/parser"
```

### Shared Database Schema
- Both components use identical SQLite schema
- Web visualizer reads data written by core library
- No direct database coupling; all through shared models

### API Boundaries
```go
// Web visualizer calls core library functions
parser := gopacket_parser.NewGopacketParser(pcapFile, repo, tenantID)
devices, err := parser.ParseFile()

// Core library returns structured data
zones, err := zoneClassifier.ClassifySecurityZones(devices, flows)
```

---

## Critical Known Issues & Fixes

### Issue: Application Hangs Indefinitely ✅ FIXED
**Date Fixed**: December 11, 2025

**Problem**: SQLite database locking deadlock between main thread and worker goroutine
- Main thread: Writing devices and protocol stats during packet processing
- Worker goroutine: Trying to batch-write packets
- Result: Both threads deadlock waiting for exclusive database write lock

**Solution**: Option A - Deferred Database Operations
- Protocol usage stats collected in memory during parsing
- All database writes deferred to end of ParseFile()
- Uses `SaveProtocolUsageStatsMultiple()` for batch insertion
- Eliminates concurrent database access

**Test Results**: ✅ 20/20 consecutive runs passed (2-second timeout each)
- Average execution time: ~315ms
- Zero data loss or corruption
- All data properly persisted

**Files Modified**: `internal/parser/gopacket_parser.go`

**Related Documentation**:
- [HANGING_ISSUE_ANALYSIS.md](HANGING_ISSUE_ANALYSIS.md) - Root cause analysis
- [FIX_SUMMARY.md](FIX_SUMMARY.md) - Fix implementation and testing details

---

## Architecture Patterns

### Design Patterns Used

#### Interface-Driven Design
All business logic is defined behind interfaces for testability and swappability:
```go
type PacketParser interface {
    ParseFile() error
}

type Repository interface {
    SaveDevices(devices []*Device) error
    GetDevices(tenantID string, filters map[string]interface{}) ([]*Device, error)
    // ... other methods
}
```

#### Repository Pattern
Database operations abstracted through repository interface:
- Enables testing with mock repository
- Easy database backend swapping (SQLite → PostgreSQL, etc.)
- Consistent data access patterns

#### Dependency Injection
Components receive dependencies through constructors:
```go
func NewGopacketParser(pcapFile string, repo Repository, tenantID string) *GopacketParser
```

#### Plugin Architecture (Planned)
Industrial protocols can be extended without modifying core:
- Protocol parsers registered at initialization
- Device classifiers pluggable
- Custom analysis modules supported

### Architectural Decisions

#### Database Schema Evolution
- Uses **database regeneration** rather than migrations
- Development: Delete `database.sqlite`, regenerate with new schema
- Production: Export data, regenerate, re-import if needed
- Simplifies development and ensures schema consistency

#### Batch Processing
- Packets collected in channel and batch-written
- Devices, flows, and services batch-inserted at end
- Protocol stats deferred and batch-saved
- Reduces database write operations and improves performance

#### Multi-Tenant Support
- All data includes `tenant_id` field
- Queries filter by tenant by default
- Enables multiple organizations in single database

---

## Development Workflow

### Open-Source Development
1. **Library-First**: All core functionality developed as library
2. **Interface-Driven**: Public APIs defined before implementation
3. **Test Coverage**: Comprehensive unit and integration tests
4. **Documentation**: Public API documentation and examples
5. **Versioning**: Semantic versioning for releases

### Web Visualizer Development
1. **Consumer-Driven**: Develops against stable library interfaces
2. **UI/UX Focus**: Concentrates on user experience
3. **Integration Testing**: E2E tests with Playwright
4. **Performance**: Optimized for web-specific use cases

### Building & Testing

```bash
# Build the CLI
go build -o pcap-importer ./cmd/importer

# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Format and vet code
go fmt ./...
go vet ./...

# Dependency management
go mod tidy
go mod download
```

---

## Important Context for AI Agents

### Code Style & Conventions

#### Naming Conventions
- **Interfaces**: Descriptive names without "I" prefix (e.g., `PacketParser`, `Repository`)
- **Implementations**: Include technology name (e.g., `SQLiteRepository`, `GopacketParser`)
- **Test files**: Follow `*_test.go` pattern
- **Mock files**: Use `mock_*.go` pattern in `testutil/`
- **Functions**: Exported start with capital letter; private start with lowercase

#### Error Handling
- Use `fmt.Errorf()` with `%w` for error wrapping
- Return errors as values, don't panic
- Log errors with context before returning

#### Comments
- Explain **why**, not what the code does
- Exported functions should have comment starting with function name
- Document interfaces and complex algorithms

#### Testing
- Mock interfaces using `testutil` mocks
- Use dependency injection for testability
- Test interfaces, not implementations
- Integration tests verify end-to-end behavior

### Common Tasks

#### Adding an OT Protocol Decoder (lib/detect)
1. Write the strict probe and the decoder in `lib/detect/<proto>*.go`; register the protocol in `default.go`.
2. For TCP, embed `tcpTracker[*yourConn, YourMessage]` (see `tcptrack.go`); the protocol keeps only framing and decoding.
3. Add the label in `internal/parser/connection_labeler.go` (`flowLabel`) and `cmd/importer/main.go` (`industrialPortLabels`).
4. Add the decoder to `decodeAllNoPanic` in `lib/detect/fuzz_test.go`, and its probe to `FuzzProbes`.
5. Build a `scripts/<proto>_demo_pcap.py`, `<proto>_dump` and `compare_<proto>.py` against an independent dissector, and record the result in `docs/SURICATA_PROTOCOL_COMPARISON.md`.

#### Adding a New Protocol Parser
1. Implement protocol detection in `internal/parser/gopacket_parser.go`
2. Add data extraction to layer maps
3. Create tests in corresponding `_test.go` file
4. Document protocol support in README

#### Adding a New Database Field
1. Update data model in `lib/model/`
2. Modify SQLite schema in `internal/repository/sqlite_repository.go`
3. Update upsert/query logic
4. Add validation in model tests
5. Update web visualizer accordingly

#### Fixing Performance Issues
1. Profile with `go test -bench -cpuprofile`
2. Look for:
   - Unnecessary string allocations
   - Repeated database queries
   - Unoptimized loops
   - Unbounded memory growth
3. Test fix with stress tests before committing

#### Debugging Database Issues
1. Check SQLite schema: `sqlite3 database.sqlite ".schema"`
2. Query data: `sqlite3 database.sqlite "SELECT * FROM devices LIMIT 5;"`
3. Check transaction handling in repository
4. Verify batch operations complete properly

---

## Critical Dependencies & Known Behaviors

### gopacket Library
- Very fast packet parsing using native Go code
- Lazy decoding with `NoCopy` option for memory efficiency
- Custom protocol layers registered in `lib/layers/`
- Some protocols require manual definition (HTTP, TLS, OPC UA, EtherNet/IP)

### SQLite Locking Behavior
- ⚠️ **CRITICAL**: SQLite uses exclusive write locks
- Multiple concurrent writes will block each other
- Solution: Defer writes, use batch operations

### Memory Management
- Ring buffer used for HTTP requests to avoid unbounded growth
- Device/flow maps grow with packet processing
- Large PCAP files can consume significant memory
- Consider splitting very large files

---

## Testing Strategy

### Unit Tests
- Mock all external dependencies (Repository, Parser)
- Test individual functions and methods
- Focus on business logic and edge cases
- Located in `*_test.go` files next to code

### Integration Tests
- Test with real SQLite database
- Use test PCAP files in `test_data/` or inline
- Verify end-to-end packet processing
- Check data persistence and retrieval

### Performance Tests
- Benchmark critical paths
- Profile memory usage with large files
- Stress test with high packet volume
- Test batch operations effectiveness

### End-to-End Tests (Web Visualizer)
- Playwright tests in `web_visualizer/tests/e2e/`
- Upload PCAP files and verify visualization
- Test authentication and session management
- Verify report generation

---

## Future Enhancements

### Short-term (1-2 months)
- Industrial protocol support (EtherNet/IP, OPC UA)
- Enhanced device classification

### Medium-term (3-6 months)
- Network boundary detection
- Security zone classification
- Basic compliance reporting

### Long-term (6-12 months)
- Full IEC 62443 compliance audit
- PDF report generation
- Risk assessment and scoring
- Multi-language support

---

## Getting Help

### Code References
- Protocol analysis: See `internal/parser/gopacket_parser.go` and `lib/layers/`
- Database operations: See `internal/repository/sqlite_repository.go`
- Data models: See `lib/model/`
- CLI setup: See `cmd/importer/main.go`

### Documentation Files
- [README.md](README.md) - User-facing documentation
- [docs/API_REFERENCE.md](docs/API_REFERENCE.md) - API documentation
- [docs/db_schema.md](docs/db_schema.md) - Database schema
- [docs/INDUSTRIAL_PROTOCOLS.md](docs/INDUSTRIAL_PROTOCOLS.md) - Industrial protocol analysis

### Steering Documents
- [.kiro/steering/product.md](.kiro/steering/product.md) - Product vision and goals
- [.kiro/steering/tech.md](.kiro/steering/tech.md) - Technology decisions
- [.kiro/steering/structure.md](.kiro/steering/structure.md) - Project organization
- [.kiro/steering/responsibility-split.md](.kiro/steering/responsibility-split.md) - Component responsibilities

---

## Quick Reference

### Key Files
- Main CLI: `cmd/importer/main.go`
- PCAP parser: `internal/parser/gopacket_parser.go`
- Database: `internal/repository/sqlite_repository.go`
- Data models: `lib/model/`
- Custom layers: `lib/layers/`

### Key Interfaces
- `PacketParser` - Parse PCAP files
- `Repository` - Database operations
- `DNSProcessor` - DNS analysis
- `ZoneClassifier` - IEC 62443 zones (planned)

### Important Constants
- Batch size: 1000 packets
- Ring buffer size: 100 HTTP requests
- Default database: `database.sqlite`

### Database Tables
- `packets` - Individual packet records
- `devices` - Discovered network devices
- `flows` - Network communication flows
- `services` - Identified services
- `device_relations` - Device relationships
- `dns_queries` - DNS queries
- `ssdp_queries` - SSDP queries
- `industrial_devices` - IEC 62443 device info
- `protocol_usage_stats` - Protocol statistics
- `communication_patterns` - Network patterns

---

**Last Updated**: December 11, 2025  
**Status**: Active Development  
**Maintainer**: InfraSecConsult
