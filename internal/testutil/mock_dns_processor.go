package testutil

import (
	"pcap-importer-golang/internal/repository"
)

type MockDNSProcessor struct {
	ProcessCalled bool
	ProcessErr    error
}

func (m *MockDNSProcessor) Process(repo repository.Repository) error {
	m.ProcessCalled = true
	return m.ProcessErr
}
