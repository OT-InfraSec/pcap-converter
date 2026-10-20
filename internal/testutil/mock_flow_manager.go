package testutil

import (
	"time"

	model "github.com/InfraSecConsult/pcap-importer-go/lib/model"
)

// MockFlowManager is a mock implementation of FlowManager for testing
type MockFlowManager struct {
	UpdateFlowFunc  func(src, dst, protocol string, srcPort, dstPort string, vlan model.VLANTag, timestamp time.Time, packetSize int, packetID int64) (*model.Flow, bool)
	GetFlowFunc     func(src, dst, protocol string, vlan model.VLANTag) *model.Flow
	GetAllFlowsFunc func() []*model.Flow
	ClearFunc       func()

	UpdateFlowCalls  []MockFlowManagerUpdateFlowCall
	GetFlowCalls     []MockFlowManagerGetFlowCall
	GetAllFlowsCalls int
	ClearCalls       int
}

type MockFlowManagerUpdateFlowCall struct {
	Src, Dst, Protocol string
	SrcPort, DstPort   string
	VLAN               model.VLANTag
	Timestamp          time.Time
	PacketSize         int
	PacketID           int64
}

type MockFlowManagerGetFlowCall struct {
	Src, Dst, Protocol string
	VLAN               model.VLANTag
}

func (m *MockFlowManager) UpdateFlow(src, dst, protocol string, srcPort, dstPort string, vlan model.VLANTag, timestamp time.Time, packetSize int, packetID int64) (*model.Flow, bool) {
	m.UpdateFlowCalls = append(m.UpdateFlowCalls, MockFlowManagerUpdateFlowCall{
		Src: src, Dst: dst, Protocol: protocol,
		SrcPort: srcPort, DstPort: dstPort, VLAN: vlan,
		Timestamp: timestamp, PacketSize: packetSize, PacketID: packetID,
	})

	if m.UpdateFlowFunc != nil {
		return m.UpdateFlowFunc(src, dst, protocol, srcPort, dstPort, vlan, timestamp, packetSize, packetID)
	}

	// Default implementation
	return &model.Flow{}, false
}

func (m *MockFlowManager) GetFlow(src, dst, protocol string, vlan model.VLANTag) *model.Flow {
	m.GetFlowCalls = append(m.GetFlowCalls, MockFlowManagerGetFlowCall{
		Src: src, Dst: dst, Protocol: protocol, VLAN: vlan,
	})

	if m.GetFlowFunc != nil {
		return m.GetFlowFunc(src, dst, protocol, vlan)
	}

	return nil
}

func (m *MockFlowManager) GetAllFlows() []*model.Flow {
	m.GetAllFlowsCalls++

	if m.GetAllFlowsFunc != nil {
		return m.GetAllFlowsFunc()
	}

	return []*model.Flow{}
}

func (m *MockFlowManager) Clear() {
	m.ClearCalls++

	if m.ClearFunc != nil {
		m.ClearFunc()
	}
}
