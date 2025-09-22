# Requirements Document

## Introduction

This bugfix addresses a critical issue in the current flow aggregation and protocol classification system where bidirectional network communications (request-response patterns) are incorrectly stored as separate flow records instead of being aggregated into a single bidirectional flow entry. This problem occurs when Device A initiates communication to Device B (e.g., HTTP request) and Device B responds back to Device A - the current system treats these as two distinct flows rather than recognizing them as two directions of the same communication session.

The fix will implement proper bidirectional flow aggregation logic in the repository layer while maintaining backward compatibility and ensuring accurate protocol classification based on the initiating communication direction.

## Problem Statement

**Current Behavior:**
- Device A (192.168.1.10) sends HTTP request → Device B (192.168.1.20) 
- System creates flow: `(source: 192.168.1.10, destination: 192.168.1.20, protocol: HTTP)`
- Device B (192.168.1.20) sends HTTP response → Device A (192.168.1.10)
- System creates separate flow: `(source: 192.168.1.20, destination: 192.168.1.10, protocol: HTTP)`

**Expected Behavior:**
- Both directions should be aggregated into single flow: `(source: 192.168.1.10, destination: 192.168.1.20, protocol: HTTP, first_seen: timestamp from initial request, last_seen: timestamp from last response packet)`

## Requirements

### Requirement 1: Bidirectional Flow Identification

**User Story:** As a network analyst, I want bidirectional communications to be recognized as a single flow session, so that I can accurately analyze communication patterns between devices.

#### Acceptance Criteria

1. WHEN a packet represents a response to a previous request THEN the system SHALL identify it as part of the existing bidirectional flow
2. WHEN determining flow direction THEN the system SHALL use the initiator as the source with sanity checks for well-known service ports
3. WHEN the destination port is 80 (HTTP) or 443 (HTTPS) THEN the system SHALL treat the device with the service port as the destination regardless of packet direction
4. WHEN the destination port is 4840 (OPC UA), 502 (Modbus), or other industrial service ports THEN the system SHALL treat the device with the service port as the destination
5. WHEN creating flow keys for lookup THEN the system SHALL normalize to canonical direction with initiator as source

### Requirement 2: Flow Aggregation Logic

**User Story:** As a network analyst, I want response packets to update the existing flow record, so that I have complete bidirectional communication statistics.

#### Acceptance Criteria

1. WHEN a packet matches an existing flow in reverse direction THEN the system SHALL update the existing flow record instead of creating a new flow
2. WHEN updating a flow with reverse-direction packet THEN the system SHALL increment bidirectional packet and byte counters
3. WHEN updating a flow with reverse-direction packet THEN the system SHALL update the last_seen timestamp while preserving first_seen from initial request
4. WHEN updating a flow with reverse-direction packet THEN the system SHALL preserve the original source/destination from the initiating direction
5. WHEN updating a flow with reverse-direction packet THEN the system SHALL aggregate port information while maintaining source/destination port mappings

### Requirement 3: Protocol Classification Consistency

**User Story:** As a network analyst, I want protocol classification to be based on the initiating communication, so that flows are consistently classified by their primary service.

#### Acceptance Criteria

1. WHEN a bidirectional flow is identified THEN the protocol classification SHALL be determined from the initial request packet
2. WHEN a response packet has different protocol indicators THEN the system SHALL maintain the original protocol classification from the initiating direction
3. WHEN protocol detection occurs on response packets THEN the system SHALL update the existing flow's protocol field only if it was previously unidentified
4. WHEN conflicting protocol information exists between directions THEN the system SHALL prioritize the initiating direction's protocol classification
5. WHEN storing flow data THEN the system SHALL ensure protocol field reflects the service being accessed from the initial request

### Requirement 4: Flow Lookup and Matching

**User Story:** As a developer, I want efficient flow lookup mechanisms, so that bidirectional flow aggregation performs well with large packet volumes.

#### Acceptance Criteria

1. WHEN looking up flows for aggregation THEN the system SHALL search using normalized flow keys (canonical direction with initiator as source)
2. WHEN a packet could match multiple flow patterns THEN the system SHALL prioritize exact matches over reverse-direction matches
3. WHEN implementing flow lookup THEN the system SHALL create indexed database queries for optimal performance
4. WHEN storing flows THEN the system SHALL maintain unique constraints on the canonical flow tuple (normalized source, destination, protocol)
5. WHEN flow lookup fails THEN the system SHALL create a new flow entry in canonical direction format with initiator as source

### Requirement 5: Database Schema Compatibility and Bidirectional Statistics

**User Story:** As a database administrator, I want the flow aggregation fix to work with existing database schemas while properly tracking bidirectional statistics, so that historical data remains accessible and statistics are accurate.

#### Acceptance Criteria

1. WHEN implementing bidirectional flow logic THEN the system SHALL maintain compatibility with existing flow table schema
2. WHEN updating existing flows THEN the system SHALL preserve all existing flow metadata (packet_refs, device_ids, etc.)
3. WHEN aggregating packet references THEN the system SHALL merge packet_refs arrays from both directions
4. WHEN tracking bidirectional statistics THEN the system SHALL add columns to aggregate byte and packet counts for both directions separately
5. WHEN working with existing databases THEN the system SHALL handle legacy separate-direction flows gracefully

### Requirement 6: Port and Service Management

**User Story:** As a network analyst, I want accurate port tracking that preserves source/destination relationships while prioritizing service identification, so that I can properly identify services and communication patterns.

#### Acceptance Criteria

1. WHEN storing port information THEN the system SHALL maintain source ports mapped to source devices and destination ports mapped to destination devices
2. WHEN HTTP traffic (port 80) is detected THEN the system SHALL ensure the device with port 80 is stored as the destination device
3. WHEN HTTPS traffic (port 443) is detected THEN the system SHALL ensure the device with port 443 is stored as the destination device  
4. WHEN industrial protocol traffic (ports 4840, 502, 44818, 2222, etc.) is detected THEN the system SHALL ensure the device with the service port is stored as the destination device
5. WHEN aggregating port information from both directions THEN the system SHALL merge source_ports and destination_ports sets appropriately while preserving service port mappings

### Requirement 7: Timestamp and Statistics Accuracy

**User Story:** As a network analyst, I want accurate bidirectional flow statistics and timestamps, so that I can properly analyze communication timing and bandwidth usage.

#### Acceptance Criteria

1. WHEN creating a new flow THEN the system SHALL set first_seen to the timestamp of the initial request packet
2. WHEN updating a flow with response packets THEN the system SHALL preserve first_seen and update last_seen to the latest packet timestamp
3. WHEN aggregating statistics THEN the system SHALL track separate byte and packet counts for both communication directions
4. WHEN tracking packet sizes THEN the system SHALL update min_packet_size and max_packet_size considering both directions
5. WHEN maintaining packet references THEN the system SHALL append new packet IDs to the packet_refs array while maintaining chronological order

### Requirement 8: Error Handling and Edge Cases

**User Story:** As a system administrator, I want robust error handling for flow aggregation edge cases, so that the system remains stable under various network conditions.

#### Acceptance Criteria

1. WHEN encountering malformed packets THEN the system SHALL handle flow lookup gracefully without corrupting existing flows
2. WHEN database constraints are violated THEN the system SHALL retry with conflict resolution logic
3. WHEN flow updates fail THEN the system SHALL log appropriate error messages and continue processing
4. WHEN memory usage becomes high THEN the system SHALL implement flow cache eviction strategies
5. WHEN processing very large flows THEN the system SHALL handle packet_refs array size limitations appropriately

## Implementation Notes

### Flow Canonicalization Algorithm
```
For all flows:
  1. Identify service ports using well-known port list:
     - HTTP: 80, 8080, 8000
     - HTTPS: 443, 8443
     - OPC UA: 4840
     - Modbus: 502
     - EtherNet/IP: 44818 (TCP), 2222 (UDP)
     - DNS: 53
     - SNMP: 161, 162
     - SSH: 22
     - Telnet: 23
     
  2. Determine canonical direction:
     IF either port is a known service port:
       canonical_source = client (device with ephemeral port)
       canonical_dest = server (device with service port)
     ELSE:
       canonical_source = min(source_ip:source_port, dest_ip:dest_port) lexicographically
       canonical_dest = max(source_ip:source_port, dest_ip:dest_port) lexicographically
       
  3. Protocol classification from initial request packet only
  4. Timestamps: first_seen from initial request, last_seen from latest packet
```

### Database Schema Extensions
```sql
-- Add columns for bidirectional statistics
ALTER TABLE flows ADD COLUMN bytes_client_to_server INTEGER DEFAULT 0;
ALTER TABLE flows ADD COLUMN bytes_server_to_client INTEGER DEFAULT 0;
ALTER TABLE flows ADD COLUMN packets_client_to_server INTEGER DEFAULT 0;
ALTER TABLE flows ADD COLUMN packets_server_to_client INTEGER DEFAULT 0;

-- Keep existing bytes and packets columns for backward compatibility (sum of both directions)
-- Add index for efficient bidirectional flow lookup
CREATE INDEX IF NOT EXISTS idx_flows_canonical ON flows(source, destination, protocol);
```

### Performance Considerations
- Implement flow caching to avoid repeated database lookups
- Use prepared statements for flow lookup and update operations
- Consider batch processing for high-volume packet streams
- Add database indexes for canonical flow tuple lookups

## Success Criteria

1. **Functional**: HTTP request-response pairs create only one flow record with correct service port mapping
2. **Performance**: Flow aggregation does not significantly impact processing speed
3. **Accuracy**: All bidirectional statistics are correctly aggregated with separate direction tracking
4. **Compatibility**: Existing flow data and database schema remain functional with new columns
5. **Service Identification**: HTTP/HTTPS and industrial protocol services are correctly identified as destination devices
6. **Reliability**: System handles edge cases without data corruption

## Dependencies

- Existing SQLite repository implementation
- Current Flow model and validation logic
- Packet processing pipeline in gopacket parser
- Database transaction handling infrastructure
- Database schema migration capability for new columns
