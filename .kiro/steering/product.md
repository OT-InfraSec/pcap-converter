# Product Overview

Go PCAP Importer is a high-performance, testable, and extensible **open-source library and CLI tool** for importing PCAP (packet capture) files into SQL databases and performing IEC 62443 industrial network security analysis.

## Architecture Overview
This project consists of two main components:
- **Open-Source Core** (`pcap-importer-go`): Library and CLI for PCAP processing and analysis
- **Closed-Source Web Visualizer** (`web_visualizer`): Web application that consumes the open-source library

## Primary Goal
**Identify network security zones of industrial networks according to IEC 62443-2 and IEC 62443-3 standards through PCAP file analysis alone.**

The ultimate objective is to enable comprehensive IEC 62443 compliance audits using only network packet capture data, without requiring direct access to industrial control systems.

## Core Purpose (Open-Source Library)
- Import network packet capture files into SQLite databases
- Remove secrets or sensitive data transmitted over network 
- Extract and analyze network devices, flows, and protocol information
- **Identify and classify network security zones per IEC 62443 standards**
- **Enable IEC 62443 compliance auditing via PCAP analysis**
- Support extensible protocol analysis for network security and monitoring
- Provide reusable Go library for PCAP analysis integration

## Web Visualizer Purpose (Closed-Source)
- Interactive web interface for PCAP file upload and processing
- Network topology visualization using Cytoscape.js
- Device discovery and relationship mapping
- Authentication and session management
- Security analysis dashboard and reporting interface

## Current Implementation Status
- ✅ **Device Discovery**: MAC/IP address extraction and device identification
- ✅ **Protocol Analysis**: Ethernet, IPv4/IPv6, TCP, UDP, DNS support
- ✅ **Flow Analysis**: Network communication patterns and relationships
- 🔄 **Next Phase**: Network security zone identification and IEC 62443 compliance analysis

## Key Features

### Open-Source Core Features
- CLI tool for PCAP file processing
- Go library for programmatic PCAP analysis
- Packet, device, and flow extraction (MAC addresses, IP addresses, 5-tuple flows)
- DNS query analysis and correlation
- Extensible protocol support (with industrial protocol support planned)
- Performance-optimized batch processing
- **Industrial network security zone classification (planned)**
- **IEC 62443 compliance analysis engine (planned)**

### Web Visualizer Features (Closed-Source)
- Web-based PCAP file upload (.pcap, .pcapng, .cap formats)
- Interactive network topology visualization
- Device table with filtering and search capabilities
- Authentication system with secure sessions
- Multiple router detection methods (heuristic, EIGRP, combined)
- **IEC 62443 compliance dashboard (planned)**
- **PDF report generation (planned)**

## Target Use Cases
- **IEC 62443 compliance auditing for industrial networks**
- **Industrial network security zone identification and validation**
- Network security analysis and risk assessment
- Traffic monitoring and forensics
- Device discovery and network mapping
- Protocol analysis and troubleshooting

## Responsibility Split

### Open-Source Core Responsibilities
- **Data Processing Engine**: PCAP parsing, packet analysis, device discovery
- **Analysis Algorithms**: IEC 62443 zone classification, boundary detection, compliance checking
- **Data Models**: Core data structures for devices, flows, security zones, compliance results
- **Storage Layer**: Database abstraction, SQLite implementation, data persistence
- **CLI Interface**: Command-line tool for batch processing and automation
- **Library API**: Go interfaces and implementations for programmatic access
- **Industrial Protocol Support**: EtherNet/IP, OPC UA, Modbus, PROFINET, DNP3, IEC 61850

### Web Visualizer Responsibilities (Closed-Source)
- **Web Interface**: HTTP server, routing, authentication, session management
- **Visualization Engine**: Cytoscape.js integration, network topology rendering
- **User Experience**: File upload, progress tracking, interactive controls
- **Dashboard**: Device tables, filtering, search, data presentation
- **Report Generation**: PDF export, compliance reports, audit documentation
- **Commercial Features**: Advanced analytics, enterprise integrations, premium visualizations

### Integration Points
- **Library Dependency**: Web visualizer imports `github.com/InfraSecConsult/pcap-importer-go`
- **Shared Database**: Both components use the same SQLite schema and data models
- **API Compatibility**: Web visualizer calls open-source library functions for analysis
- **Data Flow**: Web visualizer handles UI/UX, delegates processing to open-source core

## IEC 62443 Implementation Roadmap

### Phase 1: Enhanced Device Classification
- **Priority Protocols**: EtherNet/IP and OPC UA detection and analysis
- Industrial device type identification via protocol usage and communication patterns
- Device role classification (PLCs, HMIs, SCADA systems, workstations)
- Asset inventory with security-relevant attributes

### Phase 2: Network Boundary Detection
- **Router-based boundaries**: Identify zone separations at Layer 3 routing points
- **Firewall boundaries**: Detect security enforcement points
- **VLAN boundaries**: Identify zone separations based on VLAN changes
- Communication path analysis between detected boundaries

### Phase 3: Security Requirements Inference
- Analyze device security requirements based on device type and role
- Map communication patterns to security criticality
- Infer security level requirements per device and communication path

### Phase 4: Security Zone Classification
- Zone classification per IEC 62443-3-2 Security Levels (SL 1-4)
- Combine network topology analysis with device type identification
- Validate zone boundaries against communication patterns
- Security level assessment based on inferred device requirements

### Phase 5: Compliance Reporting
- **PDF audit report generation** with findings and recommendations
- IEC 62443-2-1 security management compliance validation
- IEC 62443-3-3 system security requirements validation
- Zone-specific security recommendations

## Database Management

### Database Schema Evolution
The project uses **database regeneration** rather than migrations for schema changes. When database schema modifications are required:

- **Development**: Delete existing `database.sqlite` and regenerate with new schema
- **Production**: Export essential data, regenerate database with updated schema, re-import data if needed
- **Testing**: Always use fresh database generation for consistent test environments

This approach simplifies development and ensures clean schema consistency across all environments
