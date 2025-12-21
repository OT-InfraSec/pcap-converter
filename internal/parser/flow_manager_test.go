package parser

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	helper "github.com/InfraSecConsult/pcap-importer-go/lib/helper"
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
	flow1, _ := fm.UpdateFlow(clientIP, serverIP, protocol, clientPort, serverPort, timestamp, 100, 1)
	require.NotNil(t, flow1)
	assert.Equal(t, 1, flow1.PacketCountOut)
	assert.Equal(t, int64(100), flow1.ByteCountOut)
	assert.Equal(t, 0, flow1.PacketCountIn)
	assert.Equal(t, int64(0), flow1.ByteCountIn)

	// Server -> Client (reverse direction)
	flow2, _ := fm.UpdateFlow(serverIP, clientIP, protocol, serverPort, clientPort, timestamp.Add(10*time.Millisecond), 200, 2)
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

			flow, _ := fm.UpdateFlow("10.0.0.1", "10.0.0.2", "tcp", tt.srcPort, tt.dstPort, time.Now(), 100, 1)

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

	fm.UpdateFlow("10.0.0.1", "10.0.0.2", "tcp", "12345", "80", time.Now(), 100, 1)
	fm.UpdateFlow("10.0.0.3", "10.0.0.4", "tcp", "54321", "443", time.Now(), 100, 2)

	flows := fm.GetAllFlows()
	assert.Len(t, flows, 2)

	fm.Clear()
	assert.Empty(t, fm.GetAllFlows())
}
