package testutil

import (
	"github.com/stretchr/testify/mock"
)

// MockErrorHandler is a mock implementation of ErrorHandler
type MockErrorHandler struct {
	mock.Mock
}

func (m *MockErrorHandler) HandleProtocolError(err interface{}) error {
	args := m.Called(err)
	return args.Error(0)
}

func (m *MockErrorHandler) SetErrorThreshold(threshold int) {
	m.Called(threshold)
}

func (m *MockErrorHandler) GetErrorCount() int {
	args := m.Called()
	return args.Int(0)
}

func (m *MockErrorHandler) ThresholdExceeded() bool {
	args := m.Called()
	return args.Bool(0)
}

func (m *MockErrorHandler) Reset() {
	m.Called()
}
