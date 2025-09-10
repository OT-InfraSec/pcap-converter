# Project Structure

## Root Level
- `go.mod` / `go.sum` - Go module definition and dependencies
- `database.sqlite` - Default SQLite database file
- `pcap-importer` - Compiled binary (gitignored)
- `README.md` - Project documentation

## Core Directories

### `cmd/importer/`
CLI application entry point using Cobra framework
- `main.go` - CLI setup, dependency injection, and command execution
- `main_test.go` - CLI integration tests

### `internal/` (Private Application Code)
Core business logic, not importable by external packages

#### `internal/parser/`
Packet parsing logic using gopacket
- `parser.go` - PacketParser interface definition
- `gopacket_parser.go` - Main gopacket implementation
- `gopacket_parser_test.go` - Parser tests
- `test_arp_icmp.pcap` - Test data

#### `internal/repository/`
Database abstraction layer
- `repository.go` - Repository interface (CRUD operations)
- `sqlite_repository.go` - SQLite implementation
- `sqlite_repository_test.go` - Repository tests

#### `internal/dns/`
DNS post-processing logic
- `dns_processor.go` - DNSProcessor interface
- `dns_processor_impl.go` - DNS correlation implementation
- `noop_dns_processor.go` - No-op implementation for testing

#### `internal/iec62443/` (Planned)
IEC 62443 compliance analysis
- `zone_classifier.go` - Security zone identification logic
- `boundary_detector.go` - Network boundary analysis
- `compliance_checker.go` - IEC 62443 standard validation
- `risk_assessor.go` - Security risk evaluation
- `industrial_protocol_analyzer.go` - Industrial protocol detection

#### `internal/testutil/`
Test utilities and mocks
- `mock_*.go` - Generated or manual mocks for interfaces

### `lib/` (Shared Library Code)
Reusable components that could be imported by external packages

#### `lib/model/`
Data models and validation
- `packet.go` - Core data structures (Packet, Device, Flow, DNSQuery, etc.)
- `set.go` - Set data structure implementation
- `mac_address_set.go` - MAC address collection utilities
- `security_zone.go` - IEC 62443 security zone models (planned)
- `industrial_device.go` - Industrial device classification (planned)
- `compliance.go` - IEC 62443 compliance data structures (planned)
- `*_test.go` - Model validation tests

#### `lib/helper/`
Utility functions
- `address.go` - Address parsing and validation
- `ringbuffer.go` - Ring buffer implementation

#### `lib/layers/`
Custom protocol layer definitions
- `base.go` - Base layer functionality
- Protocol-specific files: `http.go`, `dns.go`, `tls.go`, etc.

#### `lib/pcapgo/`
Extended pcap reading functionality
- `ngread.go` - PCAP-NG format support
- `pcapng.go` - PCAP-NG utilities

## Naming Conventions
- Interfaces use descriptive names without "I" prefix (e.g., `PacketParser`, `Repository`)
- Implementations often include technology name (e.g., `SQLiteRepository`, `GopacketParser`)
- Test files follow `*_test.go` pattern
- Mock files use `mock_*.go` pattern in `testutil/`

## Architecture Principles
- `internal/` contains application-specific logic
- `lib/` contains reusable, potentially exportable code
- All core functionality is interface-driven for testability
- Repository pattern abstracts database operations
- Dependency injection enables easy testing and component swapping