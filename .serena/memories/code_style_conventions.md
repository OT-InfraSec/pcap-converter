# Code Style and Conventions

## Go Code Style
- Follows standard Go conventions (gofmt formatting)
- Clear, descriptive variable and function names
- No "I" prefix for interfaces (e.g., `PacketParser` not `IPacketParser`)
- Implementation names include technology name (e.g., `SQLiteRepository`, `GopacketParser`)

## Naming Conventions
- **Interfaces**: Descriptive names without prefix (e.g., `PacketParser`, `Repository`, `DNSProcessor`)
- **Implementations**: Often include technology name (e.g., `SQLiteRepository`, `GopacketParser`, `NNativeDNSProcessor`)
- **Test files**: Use `*_test.go` suffix
- **Mock files**: Use `mock_*.go` pattern in `testutil/` directory

## Testing Approach
- London School TDD - mock-driven development
- Interfaces used to enable testing with mocks
- Mocks kept in `internal/testutil/` directory
- Comprehensive unit and integration tests expected

## File Organization
- **internal/**: Private application code
- **lib/**: Reusable, exportable code
- Protocol layers in `lib/layers/` with clear separation by protocol

## Documentation
- Interfaces and public APIs clearly documented
- Examples provided for library usage
- README focused on getting started
