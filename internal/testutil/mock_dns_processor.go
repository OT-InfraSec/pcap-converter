package testutil

import (
	"github.com/InfraSecConsult/pcap-importer-go/internal/repository"
)

type MockDNSProcessor struct {
	ProcessCalled bool
	ProcessErr    error
}

func (m *MockDNSProcessor) Process(repo repository.Repository) error {
	m.ProcessCalled = true
	return m.ProcessErr
}
