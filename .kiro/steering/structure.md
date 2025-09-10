# Project Structure

This project consists of two main components with different organizational structures:

## Open-Source Core Structure

### Root Level
- `go.mod` / `go.sum` - Go module definition and dependencies
- `database.sqlite` - Default SQLite database file
- `pcap-importer` - Compiled binary (gitignored)
- `README.md` - Project documentation
- `web_visualizer/` - Closed-source web application (separate module)

### Core Directories

#### `cmd/importer/`
CLI application entry point using Cobra framework
- `main.go` - CLI setup, dependency injection, and command execution
- `main_test.go` - CLI integration tests

#### `internal/` (Private Application Code)
Core business logic, not importable by external packages

##### `internal/parser/`
Packet parsing logic using gopacket
- `parser.go` - PacketParser interface definition
- `gopacket_parser.go` - Main gopacket implementation
- `gopacket_parser_test.go` - Parser tests
- `test_arp_icmp.pcap` - Test data

##### `internal/repository/`
Database abstraction layer
- `repository.go` - Repository interface (CRUD operations)
- `sqlite_repository.go` - SQLite implementation
- `sqlite_repository_test.go` - Repository tests

##### `internal/dns/`
DNS post-processing logic
- `dns_processor.go` - DNSProcessor interface
- `dns_processor_impl.go` - DNS correlation implementation
- `noop_dns_processor.go` - No-op implementation for testing

##### `internal/iec62443/` (Planned)
IEC 62443 compliance analysis
- `zone_classifier.go` - Security zone identification logic
- `boundary_detector.go` - Network boundary analysis
- `compliance_checker.go` - IEC 62443 standard validation
- `risk_assessor.go` - Security risk evaluation
- `industrial_protocol_analyzer.go` - Industrial protocol detection

##### `internal/testutil/`
Test utilities and mocks
- `mock_*.go` - Generated or manual mocks for interfaces

#### `lib/` (Shared Library Code)
Reusable components that could be imported by external packages

##### `lib/model/`
Data models and validation
- `packet.go` - Core data structures (Packet, Device, Flow, DNSQuery, etc.)
- `set.go` - Set data structure implementation
- `mac_address_set.go` - MAC address collection utilities
- `security_zone.go` - IEC 62443 security zone models (planned)
- `industrial_device.go` - Industrial device classification (planned)
- `compliance.go` - IEC 62443 compliance data structures (planned)
- `*_test.go` - Model validation tests

##### `lib/helper/`
Utility functions
- `address.go` - Address parsing and validation
- `ringbuffer.go` - Ring buffer implementation

##### `lib/layers/`
Custom protocol layer definitions
- `base.go` - Base layer functionality
- Protocol-specific files: `http.go`, `dns.go`, `tls.go`, etc.

##### `lib/pcapgo/`
Extended pcap reading functionality
- `ngread.go` - PCAP-NG format support
- `pcapng.go` - PCAP-NG utilities

## Web Visualizer Structure (Closed-Source)

### Root Level (`web_visualizer/`)
- `go.mod` / `go.sum` - Separate Go module depending on core library
- `main.go` - Web application entry point
- `database.sqlite` - Web app database (shared schema with core)
- `cert.pem` / `key.pem` - TLS certificates
- `package.json` - Node.js dependencies for E2E testing

### Core Application Files
- `config.go` - Configuration constants and web-specific settings
- `models.go` - Web-specific data structures (extends core models)
- `handler.go` - HTTP request handlers for web routes
- `auth.go` - Authentication logic and session middleware
- `topology.go` - Network topology analysis and visualization logic
- `device_table_view.go` - Device table rendering and filtering
- `network_helper.go` - Network utility functions for web context
- `cache.go` - Caching functionality for web performance
- `oui.go` - OUI (Organizationally Unique Identifier) handling

### Web Assets
- `static/css/` - Custom stylesheets for visualization
- `static/js/` - JavaScript files (Cytoscape.js integration, custom scripts)
- `templates/` - Go HTML templates for web pages

### Testing Infrastructure
- `*_test.go` - Unit tests for web components
- `tests/e2e/` - Playwright end-to-end tests
- `playwright.config.ts` - E2E test configuration
- `test-results/` - Test execution artifacts

## Naming Conventions

### Open-Source Core
- Interfaces use descriptive names without "I" prefix (e.g., `PacketParser`, `Repository`)
- Implementations often include technology name (e.g., `SQLiteRepository`, `GopacketParser`)
- Test files follow `*_test.go` pattern
- Mock files use `mock_*.go` pattern in `testutil/`

### Web Visualizer
- Single package structure with descriptive filenames
- Use snake_case for multi-word filenames
- Template files match their purpose/route names
- Fragment templates end with `_fragment.html`

## Architecture Principles

### Open-Source Core
- `internal/` contains application-specific logic
- `lib/` contains reusable, potentially exportable code
- All core functionality is interface-driven for testability
- Repository pattern abstracts database operations
- Dependency injection enables easy testing and component swapping
- Library-first design enables external consumption

### Web Visualizer
- Depends on open-source core as external library
- Single package structure for rapid development
- MVC-like separation through file organization
- Middleware pattern for cross-cutting concerns
- Template inheritance for consistent UI

## Integration Architecture
- **Library Dependency**: Web visualizer imports core as `github.com/InfraSecConsult/pcap-importer-go`
- **Shared Data Models**: Both use same SQLite schema and data structures
- **API Boundary**: Web visualizer calls core library functions, doesn't duplicate logic
- **Separate Concerns**: Core handles analysis, web visualizer handles presentation