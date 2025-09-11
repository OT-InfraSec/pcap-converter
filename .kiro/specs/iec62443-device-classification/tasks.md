# Implementation Plan

- [x] 1. Set up industrial device data models and validation
  - Create IndustrialDeviceType, IndustrialDeviceRole, and SecurityLevel enums in lib/model/industrial_device.go
  - Implement IndustrialDeviceInfo struct with validation methods following existing patterns
  - Write comprehensive unit tests for all data model validation
  - _Requirements: 4.1, 4.2, 4.6_

- [x] 2. Implement EtherNet/IP protocol layer
  - Create lib/layers/ethernetip.go with EtherNetIP struct following existing layer patterns
  - Implement packet parsing for TCP port 44818 and UDP port 2222 detection
  - Add CIP (Common Industrial Protocol) data extraction methods
  - Write unit tests with mock packet data for EtherNet/IP parsing
  - _Requirements: 1.1, 1.2, 1.3, 1.4_

- [x] 3. Implement OPC UA protocol layer
  - Create lib/layers/opcua.go with OPCUA struct following existing layer patterns
  - Implement packet parsing for TCP port 4840 detection and handshake analysis
  - Add security policy and service call extraction methods
  - Write unit tests with mock packet data for OPC UA parsing
  - _Requirements: 2.1, 2.2, 2.3, 2.4_

- [ ] 4. Create industrial protocol parser interface and implementation
  - Define IndustrialProtocolParser interface in internal/parser/industrial_parser.go
  - Implement industrial protocol detection and parsing logic
  - Integrate with existing gopacket parsing pipeline in GopacketParser
  - Create mock implementation in internal/testutil/mock_industrial_parser.go
  - Write unit tests using London School TDD patterns
  - _Requirements: 1.5, 2.5, 7.1, 7.4_

- [x] 5. Implement device classifier component
  - Create DeviceClassifier interface in internal/iec62443/device_classifier.go
  - Implement device type classification logic based on protocol usage patterns
  - Add communication pattern analysis for producer-consumer and client-server relationships
  - Create mock implementation in internal/testutil/mock_device_classifier.go
  - Write unit tests for classification algorithms with various device scenarios
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 5.1, 5.2_

- [x] 6. Extend repository interface for industrial device data
  - Add industrial-specific methods to Repository interface in internal/repository/repository.go
  - Implement SQLite schema extensions for industrial_devices, protocol_usage_stats, and communication_patterns tables
  - Add new methods to SQLiteRepository for industrial device CRUD operations
  - Write repository tests for industrial device data persistence and retrieval
  - _Requirements: 4.5, 7.2_-

- [x] 7. Implement protocol usage statistics tracking
  - Create ProtocolUsageStats and CommunicationPattern structs in lib/model/industrial_device.go
  - Implement statistics collection logic in industrial protocol parser
  - Add database methods for storing and retrieving protocol usage statistics
  - Write unit tests for statistics tracking and aggregation
  - _Requirements: 4.5, 5.3, 5.4_

- [x] 8. Add error handling for industrial protocol parsing
  - Create IndustrialProtocolError type and ErrorHandler interface
  - Implement graceful error handling for malformed packets and incomplete data
  - Add error logging and recovery mechanisms in protocol parsers
  - Write unit tests for all error scenarios and recovery paths
  - _Requirements: 6.1, 6.2, 6.3, 6.5_

- [x] 9. Integrate industrial protocol parsing with existing GopacketParser
  - Modify GopacketParser to call industrial protocol detection on each packet
  - Add industrial device classification updates to packet processing pipeline
  - Ensure backward compatibility with existing packet processing
  - Write integration tests with mixed industrial and standard network traffic
  - _Requirements: 7.1, 7.4, 7.7_

- [x] 10. Implement device classification confidence and validation
  - Add confidence scoring algorithms for device type classification
  - Implement validation methods for industrial device data following existing patterns
  - Add uncertainty indicators for low-confidence classifications
  - Write unit tests for confidence calculation and validation logic
  - _Requirements: 3.6, 4.1, 6.4, 6.6_

- [x] 11. Add communication pattern analysis and criticality assessment
  - Implement periodic communication detection and frequency analysis
  - Add request-response pattern recognition for determining communication criticality
  - Create algorithms for updating device classifications based on pattern changes
  - Write unit tests for pattern analysis with various communication scenarios
  - _Requirements: 5.3, 5.4, 5.5_

- [x] 12. Create comprehensive integration tests with industrial PCAP data
  - Create test PCAP files with EtherNet/IP and OPC UA traffic (test_ethernetip.pcap, test_opcua.pcap)
  - Write end-to-end tests that process industrial PCAP files and verify device classification
  - Test mixed protocol scenarios with both industrial and standard network protocols
  - Verify database persistence and retrieval of industrial device information
  - _Requirements: 1.1-1.5, 2.1-2.5, 3.1-3.6_

- [x] 13. Add CLI support for industrial device analysis
  - Extend CLI commands to support industrial device classification reporting
  - Add command-line flags for enabling/disabling industrial protocol analysis
  - Implement output formatting for industrial device information
  - Write CLI integration tests for industrial device analysis workflows
  - _Requirements: 7.1, 7.2, 7.3_