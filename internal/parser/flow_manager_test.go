package parser

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	helper "github.com/InfraSecConsult/pcap-importer-go/lib/helper"
	model "github.com/InfraSecConsult/pcap-importer-go/lib/model"
)

func TestFlowManager_BidirectionalCounting(t *testing.T) {
	canonicalizer := helper.NewFlowCanonicalizer()
	fm := NewDefaultFlowManager("test-tenant", canonicalizer)

	clientIP := "192.168.1.10"
	serverIP := "192.168.1.100"
	clientPort := "54321"
	serverPort := "80"
	protocol := "tcp"
	timestamp := time.Now()

	// Client -> Server (canonical direction)
	flow1, _ := fm.UpdateFlow(clientIP, serverIP, protocol, clientPort, serverPort, model.VLANTag{}, timestamp, 100, 1)
	require.NotNil(t, flow1)
	assert.Equal(t, 1, flow1.PacketCountOut)
	assert.Equal(t, int64(100), flow1.ByteCountOut)
	assert.Equal(t, 0, flow1.PacketCountIn)
	assert.Equal(t, int64(0), flow1.ByteCountIn)

	// Server -> Client (reverse direction)
	flow2, _ := fm.UpdateFlow(serverIP, clientIP, protocol, serverPort, clientPort, model.VLANTag{}, timestamp.Add(10*time.Millisecond), 200, 2)
	assert.Equal(t, flow1, flow2, "Should be same flow")
	assert.Equal(t, 1, flow2.PacketCountOut)
	assert.Equal(t, int64(100), flow2.ByteCountOut)
	assert.Equal(t, 1, flow2.PacketCountIn)
	assert.Equal(t, int64(200), flow2.ByteCountIn)
}

func TestFlowManager_ProtocolCanonalization(t *testing.T) {
	tests := []struct {
		name             string
		srcPort          string
		dstPort          string
		expectedReversed bool
	}{
		{"HTTP to server", "54321", "80", false},
		{"HTTP from server", "80", "54321", true},
		{"OPC UA to server", "49152", "4840", false},
		{"OPC UA from server", "4840", "49152", true},
		{"Modbus to server", "55123", "502", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			canonicalizer := helper.NewFlowCanonicalizer()
			fm := NewDefaultFlowManager("test-tenant", canonicalizer)

			flow, _ := fm.UpdateFlow("10.0.0.1", "10.0.0.2", "tcp", tt.srcPort, tt.dstPort, model.VLANTag{}, time.Now(), 100, 1)

			if !tt.expectedReversed {
				assert.Equal(t, "10.0.0.1", flow.SrcIP.String())
				assert.Equal(t, "10.0.0.2", flow.DstIP.String())
			} else {
				assert.Equal(t, "10.0.0.2", flow.SrcIP.String())
				assert.Equal(t, "10.0.0.1", flow.DstIP.String())
			}
		})
	}
}

func TestFlowManager_GetAndClear(t *testing.T) {
	canonicalizer := helper.NewFlowCanonicalizer()
	fm := NewDefaultFlowManager("test-tenant", canonicalizer)

	assert.Empty(t, fm.GetAllFlows())

	fm.UpdateFlow("10.0.0.1", "10.0.0.2", "tcp", "12345", "80", model.VLANTag{}, time.Now(), 100, 1)
	fm.UpdateFlow("10.0.0.3", "10.0.0.4", "tcp", "54321", "443", model.VLANTag{}, time.Now(), 100, 2)

	flows := fm.GetAllFlows()
	assert.Len(t, flows, 2)

	fm.Clear()
	assert.Empty(t, fm.GetAllFlows())
}

func vlanTag(outer int, inner ...int) model.VLANTag {
	tag := model.VLANTag{Outer: &outer}
	if len(inner) > 0 {
		tag.Inner = &inner[0]
	}
	return tag
}

func TestFlowManager_SameTupleInDifferentVLANsIsSeparateFlows(t *testing.T) {
	fm := NewDefaultFlowManager("t", helper.NewFlowCanonicalizer())
	ts := time.Now()

	untagged, _ := fm.UpdateFlow("10.0.0.1", "10.0.0.2", "tcp", "40000", "80", model.VLANTag{}, ts, 100, 1)
	v10, _ := fm.UpdateFlow("10.0.0.1", "10.0.0.2", "tcp", "40000", "80", vlanTag(10), ts, 100, 2)
	v20, _ := fm.UpdateFlow("10.0.0.1", "10.0.0.2", "tcp", "40000", "80", vlanTag(20), ts, 100, 3)
	qinq, _ := fm.UpdateFlow("10.0.0.1", "10.0.0.2", "tcp", "40000", "80", vlanTag(10, 5), ts, 100, 4)
	v10again, _ := fm.UpdateFlow("10.0.0.1", "10.0.0.2", "tcp", "40000", "80", vlanTag(10), ts, 100, 5)

	if len(fm.GetAllFlows()) != 4 {
		t.Fatalf("expected 4 flows (untagged, 10, 20, 10.5), got %d", len(fm.GetAllFlows()))
	}
	if v10 != v10again || v10.PacketCountOut != 2 {
		t.Errorf("packets in the same VLAN must merge, got %d", v10.PacketCountOut)
	}
	if untagged.VlanID != nil || untagged.VlanInnerID != nil {
		t.Errorf("untagged flow must keep NULL VLAN fields")
	}
	if v20.VlanID == nil || *v20.VlanID != 20 || v20.VlanInnerID != nil {
		t.Errorf("unexpected VLAN fields on VLAN 20 flow: %v %v", v20.VlanID, v20.VlanInnerID)
	}
	if qinq.VlanInnerID == nil || *qinq.VlanInnerID != 5 {
		t.Errorf("QinQ flow must keep the inner VLAN")
	}
	if got := fm.GetFlow("10.0.0.1", "10.0.0.2", "tcp", vlanTag(20)); got != v20 {
		t.Errorf("GetFlow must look up by VLAN")
	}
}

func TestFlowManager_ReverseDirectionMergesWithinVLAN(t *testing.T) {
	fm := NewDefaultFlowManager("t", helper.NewFlowCanonicalizer())
	ts := time.Now()

	out, _ := fm.UpdateFlow("10.0.0.1", "10.0.0.2", "tcp", "40000", "80", vlanTag(10), ts, 100, 1)
	_, reversed := fm.UpdateFlow("10.0.0.2", "10.0.0.1", "tcp", "80", "40000", vlanTag(10), ts, 200, 2)

	if !reversed || out.PacketCountIn != 1 || len(fm.GetAllFlows()) != 1 {
		t.Errorf("reply in the same VLAN must count as IN on the same flow")
	}
}
