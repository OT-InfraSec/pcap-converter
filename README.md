# Go PCAP Importer

A high-performance, testable, and extensible tool for importing PCAP files into a SQL database, written in Go. This project is a migration and improvement of the original Python-based PCAP importer.

## Features
- **CLI tool** for importing PCAP files into SQLite (or other SQL DBs via repository pattern)
- **Packet, device, and flow extraction** (MAC, IP, 5-tuple, etc.)
- **DNS post-processing**: matches DNS requests and responses, stores DNS queries
- **Industrial protocol support**: EtherNet/IP, OPC UA, Modbus TCP with IEC 62443 device classification
- **Device classification and security analysis**: Automatic industrial device detection and security assessment
- **Extensible protocol support**: currently supports Ethernet, IPv4/IPv6, TCP, UDP, DNS; more protocols coming soon
- **Repository pattern** for easy swapping of database backends
- **London School TDD**: interface-first, mock-driven, and end-to-end tested

## Usage

### Build
```
go build -o pcap-importer ./cmd/importer
```

### Build for production
```
go build -ldflags="-s -w" -o pcap-importer ./cmd/importer
```

### Run Import
```
./pcap-importer import <pcap-file> [--db-path <sqlite-file>] [--batch-size <n>] [--clear] [--industrial]
```
- `--db-path`: Path to SQLite database (default: `database.sqlite`)
- `--batch-size`: Number of packets per batch (future optimization)
- `--clear`: (planned) Clear the database before importing
- `--industrial`: Enable industrial protocol analysis and device classification

### Run Industrial Analysis
```
./pcap-importer industrial list-devices [--db-path <sqlite-file>]
./pcap-importer industrial list-devices-by-type PLC [--db-path <sqlite-file>]
./pcap-importer industrial protocol-stats [--db-path <sqlite-file>]
```

### Example
```
# Basic PCAP import
./pcap-importer import testdata/example.pcap --db-path result.sqlite

# Import with industrial protocol analysis
./pcap-importer import industrial_capture.pcap --db-path industrial.sqlite --industrial

# List detected industrial devices  
./pcap-importer industrial list-devices --db-path industrial.sqlite

# Show protocol usage statistics
./pcap-importer industrial protocol-stats --db-path industrial.sqlite
```

## Architecture
- **cmd/importer/**: CLI entry point (Cobra-based)
- **internal/model/**: Data models (Packet, Device, Flow, DNSQuery, IndustrialDeviceInfo)
- **internal/repository/**: Repository interface and SQLite implementation with industrial extensions
- **internal/parser/**: Packet parsing logic (using gopacket) with industrial protocol support
- **internal/dns/**: DNS post-processing logic
- **internal/iec62443/**: IEC 62443 device classification and communication pattern analysis
- **lib/layers/**: Protocol layer definitions including EtherNet/IP and OPC UA
- **internal/testutil/**: Mocks and test helpers

## Documentation
- [Industrial Protocol Features](docs/INDUSTRIAL_PROTOCOLS.md) - Complete guide to industrial protocol parsing
- [API Reference](docs/API_REFERENCE.md) - Comprehensive API documentation for all interfaces

## Development & Testing
- All core logic is behind interfaces for testability
- Run all tests:
  ```
  go test ./...
  ```
- Add new protocol support by extending `internal/parser/gopacket_parser.go`
- Add new DB features by extending `internal/repository/sqlite_repository.go`

## Roadmap
- [ ] Add support for more protocols (ARP, ICMP, LLDP, CDP, VLAN, etc.)
- [ ] Enrich device/flow extraction (relations, advanced heuristics)
- [x] Batch/optimized DB insertion for performance
- [ ] More integration and end-to-end tests
- [ ] Improved documentation and developer guides

## Future Analyses

- [ ] Get Proxy Authentication credentials from HTTP requests (SELECT layers FROM packets WHERE layers like '%http%"method":"CONNECT%')
- [ ] Inspect number of hops distance between source and destination devices

## License
MIT 