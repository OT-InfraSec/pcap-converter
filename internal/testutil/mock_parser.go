package testutil

import (
	"github.com/InfraSecConsult/pcap-importer-go/internal/repository"
)

type MockPacketParser struct {
	ParseFileCalled bool
	ParseFileErr    error
}

func (m *MockPacketParser) ParseFile(repo repository.Repository) error {
	m.ParseFileCalled = true
	return m.ParseFileErr
}
