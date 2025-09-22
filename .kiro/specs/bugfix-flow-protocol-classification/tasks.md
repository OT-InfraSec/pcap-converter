# Implementation Plan

- [x] 1. Create Flow Canonicalizer component
  - Create FlowCanonicalizer interface in lib/helper/flow_canonicalizer.go
  - Implement FlowCanonicalizerImpl with well-known service port detection
  - Add canonicalization algorithm for client-server direction determination
  - Define WellKnownServicePorts mapping (HTTP:80/8080/8000, HTTPS:443/8443, OPC UA:4840, Modbus:502, EtherNet/IP:44818/2222, DNS:53, SSH:22, etc.)
  - Write unit tests for canonicalization logic with various protocol scenarios
  - _Requirements: 1.2, 1.3, 1.4, 4.1, 6.2, 6.3, 6.4_

- [x] 2. Extend Flow model with bidirectional statistics
  - Add new fields to Flow struct in lib/model/packet.go: PacketsClientToServer, PacketsServerToClient, BytesClientToServer, BytesServerToClient
  - Update Flow validation methods to handle new bidirectional fields
  - Ensure backward compatibility with existing Packets and Bytes fields (as totals)
  - Write unit tests for Flow model validation with bidirectional data
  - Add JSON serialization tags for new fields
  - _Requirements: 5.1, 5.3, 5.4, 7.3_

- [ ] 3. Create database schema with bidirectional columns
  - Update SQLite schema in internal/repository/sqlite_repository.go with new flow columns
  - Add CREATE TABLE statement for flows with: packets_client_to_server, packets_server_to_client, bytes_client_to_server, bytes_server_to_client
  - Create database indexes for efficient canonical flow lookup: idx_flows_canonical, idx_flows_reverse_lookup
  - Implement database initialization with new schema (no migration needed - regeneration approach)
  - Write repository tests for new schema compatibility
  - _Requirements: 5.1, 5.4, 5.5, 4.4_

- [ ] 4. Implement address parsing utilities
  - Create parseAddress helper function to extract IP and port from flow addresses
  - Add validation for IPv4/IPv6 address formats with port numbers
  - Handle edge cases: IPv6 with brackets, missing ports, malformed addresses
  - Implement error handling for invalid address formats
  - Write unit tests for address parsing with various formats (192.168.1.1:80, [2001:db8::1]:443, etc.)
  - _Requirements: 4.1, 8.1, 8.3_

- [ ] 5. Enhance Repository with Flow Canonicalizer dependency
  - Add FlowCanonicalizer as dependency to SQLiteRepository struct
  - Create NewSQLiteRepositoryWithCanonicalizer constructor
  - Update existing NewSQLiteRepository to use default canonicalizer
  - Ensure dependency injection pattern follows existing architecture
  - Write tests for repository initialization with canonicalizer
  - _Requirements: 4.1, 4.2_

- [ ] 6. Implement canonical flow lookup logic
  - Create findFlowByCanonicalTuple method in SQLiteRepository
  - Implement bidirectional flow lookup using both forward and reverse direction queries
  - Add prepared statements for efficient flow lookup operations
  - Handle SQL errors and edge cases (flow not found, multiple matches)
  - Write unit tests for flow lookup with various canonical direction scenarios
  - _Requirements: 4.1, 4.2, 4.3, 8.2_

- [ ] 7. Implement bidirectional flow update logic
  - Create updateBidirectionalFlow method to merge statistics from both directions
  - Implement createCanonicalFlow method for new flows in canonical direction
  - Add logic to determine which direction (client-to-server vs server-to-client) packet belongs to
  - Update packet counters, byte counters, timestamps, and packet references appropriately
  - Handle port aggregation while preserving source/destination mappings
  - Write unit tests for flow update scenarios with request-response patterns
  - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 6.1, 6.5, 7.1, 7.2, 7.4, 7.5_

- [ ] 8. Enhance UpsertFlow method with bidirectional logic
  - Modify existing UpsertFlow method in SQLiteRepository to use canonicalization
  - Integrate flow canonicalizer to determine canonical direction
  - Implement reverse direction detection and flow aggregation
  - Add fallback to existing behavior when canonicalization fails
  - Preserve protocol classification from initial request packet only
  - Write comprehensive unit tests for UpsertFlow with bidirectional scenarios
  - _Requirements: 2.1, 3.1, 3.2, 3.3, 3.4, 3.5, 8.1, 8.4_

- [ ] 9. Implement service port management and validation
  - Add service port detection logic in flow canonicalizer
  - Ensure HTTP (port 80), HTTPS (port 443), and industrial protocols are correctly identified
  - Implement logic to ensure device with service port becomes destination
  - Add validation for port mapping consistency (source ports with source devices)
  - Handle edge cases where both or neither ports are service ports
  - Write unit tests for service port detection across various protocols
  - _Requirements: 1.3, 1.4, 6.1, 6.2, 6.3, 6.4, 6.5_

- [ ] 10. Add error handling and graceful degradation
  - Implement FlowProcessingError type for flow-specific errors
  - Add error handling for address parsing failures, canonicalization failures, database constraint violations
  - Implement fallback to lexicographic ordering when service port detection fails
  - Add retry logic with exponential backoff for database update failures
  - Ensure system continues processing when individual flows fail
  - Write unit tests for all error scenarios and recovery paths
  - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5_

- [ ] 11. Create mock FlowCanonicalizer for testing
  - Create MockFlowCanonicalizer in internal/testutil/mock_flow_canonicalizer.go
  - Implement all interface methods with testify/mock framework
  - Follow existing mock patterns used in the codebase
  - Ensure mock supports test scenarios for various canonicalization outcomes
  - Write example test cases using mock canonicalizer
  - _Requirements: Testing infrastructure_

- [ ] 12. Write comprehensive unit tests for flow aggregation
  - Create test cases for HTTP request-response pairs creating single flow
  - Test HTTPS, OPC UA, Modbus, and other industrial protocol scenarios
  - Test edge cases: simultaneous bidirectional flows, malformed packets, database errors
  - Test timestamp handling: first_seen from initial request, last_seen from latest packet
  - Test statistics aggregation: separate client-to-server and server-to-client counters
  - Achieve >90% test coverage for all new flow aggregation logic
  - _Requirements: All requirements validation through testing_

- [ ] 13. Implement integration tests with bidirectional packet sequences
  - Create test PCAP files with request-response patterns (test_http_bidirectional.pcap, test_https_bidirectional.pcap)
  - Write end-to-end tests that process bidirectional flows and verify single flow creation
  - Test mixed protocol scenarios with both standard and industrial protocols
  - Verify database persistence shows correct bidirectional statistics
  - Test performance impact of bidirectional logic on large PCAP files
  - _Requirements: Success criteria validation_

- [ ] 14. Update CLI and library integration
  - Ensure CLI commands work with enhanced flow processing
  - Update any flow-related output formatting to show bidirectional statistics
  - Test CLI integration with bidirectional flow processing
  - Verify library API compatibility for external consumers
  - Update documentation if needed for new flow statistics fields
  - _Requirements: Compatibility and integration_

- [ ] 15. Performance testing and optimization
  - Benchmark flow processing performance with bidirectional logic vs baseline
  - Ensure performance degradation stays within 5% of baseline
  - Profile memory usage during bidirectional flow processing
  - Optimize database queries for canonical flow lookup
  - Test with high-volume PCAP files to validate performance under load
  - _Requirements: Performance success criteria_

- [ ] 16. Create comprehensive documentation and examples
  - Document flow canonicalization algorithm in code comments
  - Add examples of bidirectional flow processing in protocol_stats_example.go
  - Update API documentation for new Flow model fields
  - Document service port detection logic and supported protocols
  - Create troubleshooting guide for flow aggregation issues
  - _Requirements: Documentation and maintainability_
