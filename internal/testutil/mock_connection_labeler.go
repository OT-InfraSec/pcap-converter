package testutil

import (
	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
	"github.com/google/gopacket"
)

// LabelCall is one call a MockConnectionLabeler received.
type LabelCall struct {
	SrcIP, DstIP string
	VLAN         model.VLANTag
}

// MockConnectionLabeler implements parser.ConnectionLabeler: it returns a fixed
// label and records the addresses and VLAN it was asked about.
type MockConnectionLabeler struct {
	Result string
	Calls  []LabelCall
}

func (m *MockConnectionLabeler) Label(_ gopacket.Packet, srcIP, dstIP string, vlan model.VLANTag) string {
	m.Calls = append(m.Calls, LabelCall{SrcIP: srcIP, DstIP: dstIP, VLAN: vlan})
	return m.Result
}
