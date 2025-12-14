# PCAP Importer Go - Project Overview

## Purpose
Go PCAP Importer is a high-performance, testable, and extensible **open-source library and CLI tool** for:
- Importing PCAP (packet capture) files into SQLite databases
- Performing IEC 62443 industrial network security analysis
- Identifying network security zones according to IEC 62443-2 and IEC 62443-3 standards

## Tech Stack
- **Language**: Go 1.24.1
- **Core Framework**: github.com/google/gopacket for packet parsing
- **Database**: SQLite with github.com/mattn/go-sqlite3
- **CLI Framework**: github.com/spf13/cobra
- **Logging**: github.com/rs/zerolog

## Architecture
- **Open-Source Core**: Library + CLI at `cmd/importer/`
- **Closed-Source Web Visualizer**: Separate module depending on core library
- **Library-First Design**: CLI built on top of reusable library components

## Key Directories
- `cmd/importer/` - CLI entry point
- `internal/parser/` - PCAP parsing logic
- `internal/repository/` - Database abstraction (SQLite)
- `internal/dns/` - DNS post-processing
- `internal/iec62443/` - IEC 62443 analysis (planned)
- `lib/model/` - Data models (Device, Flow, Packet, etc.)
- `lib/helper/` - Utility functions
- `lib/layers/` - Custom protocol layer definitions
- `lib/pcapgo/` - Extended pcap reading (PCAP-NG support)

## Design Patterns
- Repository Pattern for database abstraction
- Dependency Injection for testable components
- Interface-First Design - all core logic behind interfaces
- London School TDD - mock-driven development
- Plugin Architecture - extensible protocol modules
