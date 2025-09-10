# Go PCAP Importer

A high-performance, testable, and extensible tool for importing PCAP files into a SQL database, written in Go. This project is a migration and improvement of the original Python-based PCAP importer.

## Features
- **CLI tool** for importing PCAP files into SQLite (or other SQL DBs via repository pattern)
- **Packet, device, and flow extraction** (MAC, IP, 5-tuple, etc.)
- **DNS post-processing**: matches DNS requests and responses, stores DNS queries
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
./pcap-importer import <pcap-file> [--db-path <sqlite-file>] [--batch-size <n>] [--clear]
```
- `--db-path`: Path to SQLite database (default: `database.sqlite`)
- `--batch-size`: Number of packets per batch (future optimization)
- `--clear`: (planned) Clear the database before importing

### Example
```
./pcap-importer import testdata/example.pcap --db-path result.sqlite
```

## Architecture
- **cmd/importer/**: CLI entry point (Cobra-based)
- **internal/model/**: Data models (Packet, Device, Flow, DNSQuery)
- **internal/repository/**: Repository interface and SQLite implementation
- **internal/parser/**: Packet parsing logic (using gopacket)
- **internal/dns/**: DNS post-processing logic
- **internal/testutil/**: Mocks and test helpers

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