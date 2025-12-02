package testutil

import (
	model2 "github.com/InfraSecConsult/pcap-importer-go/lib/model"
	"github.com/stretchr/testify/mock"
)

// MockFlowCanonicalizer is a mock implementation of FlowCanonicalizer
type MockFlowCanonicalizer struct {
	mock.Mock
}

func (m *MockFlowCanonicalizer) CanonicalizeFlow(srcIP string, dstIP string, srcPorts model2.Set, dstPorts model2.Set, protocol string) (string, string, bool) {
	args := m.Called(srcIP, dstIP, srcPorts, dstPorts, protocol)
	return args.String(0), args.String(1), args.Bool(2)
}

func (m *MockFlowCanonicalizer) HasServicePort(ports model2.Set, protocol string) bool {
	args := m.Called(ports, protocol)
	return args.Bool(0)
}

func (m *MockFlowCanonicalizer) GetWellKnownPorts() map[uint16]string {
	args := m.Called()
	return args.Get(0).(map[uint16]string)
}

// Helper methods for test setup
func (m *MockFlowCanonicalizer) ExpectCanonicalizeFlow(srcIP, dstIP string, srcPorts, dstPorts model2.Set, protocol string, canonicalSrc, canonicalDst string, isReversed bool) *mock.Call {
	return m.On("CanonicalizeFlow", srcIP, dstIP, srcPorts, dstPorts, protocol).Return(canonicalSrc, canonicalDst, isReversed)
}

func (m *MockFlowCanonicalizer) ExpectHasServicePort(ports model2.Set, protocol string, result bool) *mock.Call {
	return m.On("HasServicePort", ports, protocol).Return(result)
}

func (m *MockFlowCanonicalizer) ExpectGetWellKnownPorts(ports map[uint16]string) *mock.Call {
	return m.On("GetWellKnownPorts").Return(ports)
}
