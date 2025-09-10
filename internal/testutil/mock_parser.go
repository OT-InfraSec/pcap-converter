package testutil

import (
)

type MockPacketParser struct {
	ParseFileCalled bool
	ParseFileErr    error
}

func (m *MockPacketParser) ParseFile() error {
	m.ParseFileCalled = true
	return m.ParseFileErr
}
