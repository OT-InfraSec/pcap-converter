# Development Commands and Workflow

## Testing
```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run specific package tests
go test ./internal/parser
```

## Code Quality
```bash
# Format code
go fmt ./...

# Vet code for issues
go vet ./...

# Tidy dependencies
go mod tidy

# Download dependencies
go mod download
```

## Building
```bash
# Development build
go build -o pcap-importer ./cmd/importer

# Production build (optimized)
go build -ldflags="-s -w" -o pcap-importer ./cmd/importer
```

## Completion Checklist for Tasks
When completing a coding task:
1. Format code with `go fmt ./...`
2. Run `go vet ./...` to check for issues
3. Run `go mod tidy` to clean up dependencies
4. Run `go test ./...` to ensure tests pass
5. Run tests with coverage `go test -cover ./...`
6. Ensure mocks are in `internal/testutil/` for interfaces
7. Follow London School TDD patterns with mock-driven tests
