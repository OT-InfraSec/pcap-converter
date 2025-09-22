package testutil

import (
	"github.com/stretchr/testify/mock"
)

// MockFlowCanonicalizer is a mock implementation of FlowCanonicalizer
type MockFlowCanonicalizer struct {
	mock.Mock
}

func (m *MockFlowCanonicalizer) CanonicalizeFlow(srcIP string, dstIP string, srcPort uint16, dstPort uint16, protocol string) (string, string, bool) {
	args := m.Called(srcIP, dstIP, srcPort, dstPort, protocol)
	return args.String(0), args.String(1), args.Bool(2)
}

func (m *MockFlowCanonicalizer) IsServicePort(port uint16, protocol string) bool {
	args := m.Called(port, protocol)
	return args.Bool(0)
}

func (m *MockFlowCanonicalizer) GetWellKnownPorts() map[uint16]string {
	args := m.Called()
	return args.Get(0).(map[uint16]string)
}

// Helper methods for test setup
func (m *MockFlowCanonicalizer) ExpectCanonicalizeFlow(srcIP, dstIP string, srcPort, dstPort uint16, protocol string, canonicalSrc, canonicalDst string, isReversed bool) *mock.Call {
	return m.On("CanonicalizeFlow", srcIP, dstIP, srcPort, dstPort, protocol).Return(canonicalSrc, canonicalDst, isReversed)
}

func (m *MockFlowCanonicalizer) ExpectIsServicePort(port uint16, protocol string, result bool) *mock.Call {
	return m.On("HasServicePort", port, protocol).Return(result)
}

func (m *MockFlowCanonicalizer) ExpectGetWellKnownPorts(ports map[uint16]string) *mock.Call {
	return m.On("GetWellKnownPorts").Return(ports)
}
