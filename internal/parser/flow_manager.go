package parser

import (
	"fmt"
	"net"
	"strconv"
	"time"

	helper "github.com/InfraSecConsult/pcap-importer-go/lib/helper"
	model "github.com/InfraSecConsult/pcap-importer-go/lib/model"
)

// FlowManager handles flow creation, updates, and canonicalization
type FlowManager interface {
	// UpdateFlow updates or creates a flow with the given parameters
	// Returns the flow and whether it was reversed during canonicalization
	UpdateFlow(src, dst, protocol string, srcPort, dstPort string, timestamp time.Time, packetSize int, packetID int64) (*model.Flow, bool)

	// GetFlow retrieves a flow by its canonical key
	GetFlow(src, dst, protocol string) *model.Flow

	// GetAllFlows returns all tracked flows
	GetAllFlows() []*model.Flow

	// Clear removes all flows from tracking
	Clear()
}

// DefaultFlowManager implements FlowManager with flow canonicalization support
type DefaultFlowManager struct {
	flows             map[string]*model.Flow
	flowCanonicalizer helper.FlowCanonicalizer
	tenantID          string
}

// NewDefaultFlowManager creates a new flow manager with canonicalization
func NewDefaultFlowManager(tenantID string, flowCanonicalizer helper.FlowCanonicalizer) *DefaultFlowManager {
	if flowCanonicalizer == nil {
		flowCanonicalizer = helper.NewFlowCanonicalizer()
	}

	return &DefaultFlowManager{
		flows:             make(map[string]*model.Flow),
		flowCanonicalizer: flowCanonicalizer,
		tenantID:          tenantID,
	}
}

// UpdateFlow updates or creates a flow with proper canonicalization
func (fm *DefaultFlowManager) UpdateFlow(src, dst, protocol string, srcPort, dstPort string, timestamp time.Time, packetSize int, packetID int64) (*model.Flow, bool) {
	// Create port sets for canonicalization
	sourcePortsSet := model.NewSet()
	destinationPortsSet := model.NewSet()

	if srcPort != "" {
		sourcePortsSet.Add(srcPort)
	}
	if dstPort != "" {
		destinationPortsSet.Add(dstPort)
	}

	// Canonicalize flow direction based on service ports
	canonicalSrc, canonicalDst, isReversed := fm.flowCanonicalizer.CanonicalizeFlow(
		src, dst, *sourcePortsSet, *destinationPortsSet, protocol)

	// Create flow key using canonical direction
	flowKey := fmt.Sprintf("%s:%s:%s", canonicalSrc, canonicalDst, protocol)

	// Check if flow already exists
	flow, exists := fm.flows[flowKey]
	if !exists {
		// Create new flow in canonical direction
		flow = fm.createNewFlow(canonicalSrc, canonicalDst, protocol, srcPort, dstPort,
			packetSize, timestamp, packetID, sourcePortsSet, destinationPortsSet, isReversed)
		fm.flows[flowKey] = flow
	} else {
		// Update existing flow
		fm.updateExistingFlow(flow, packetSize, timestamp, packetID, srcPort, dstPort, isReversed)
	}

	return flow, isReversed
}

// createNewFlow creates a new flow record
func (fm *DefaultFlowManager) createNewFlow(canonicalSrc, canonicalDst, protocol, srcPort, dstPort string,
	packetSize int, timestamp time.Time, packetID int64,
	sourcePortsSet, destinationPortsSet *model.Set, isReversed bool) *model.Flow {

	// Parse port numbers
	srcPortNum, err := strconv.Atoi(srcPort)
	if err != nil {
		srcPortNum = 0
	}
	dstPortNum, err := strconv.Atoi(dstPort)
	if err != nil {
		dstPortNum = 0
	}

	// If reversed, we need to create the flow with swapped ports
	var flowSrcPort, flowDstPort int
	var flowSourcePorts, flowDestPorts *model.Set

	if isReversed {
		// Original packet was server->client, canonical is client->server
		// So swap the ports for the flow
		flowSrcPort = dstPortNum
		flowDstPort = srcPortNum
		flowSourcePorts = destinationPortsSet
		flowDestPorts = sourcePortsSet
	} else {
		// Normal direction
		flowSrcPort = srcPortNum
		flowDstPort = dstPortNum
		flowSourcePorts = sourcePortsSet
		flowDestPorts = destinationPortsSet
	}

	flow := &model.Flow{
		TenantID:         fm.tenantID,
		SrcIP:            net.ParseIP(canonicalSrc),
		DstIP:            net.ParseIP(canonicalDst),
		SrcPort:          flowSrcPort,
		DstPort:          flowDstPort,
		Protocol:         protocol,
		PacketCountOut:   1,
		ByteCountOut:     int64(packetSize),
		PacketCountIn:    0, // Always 0 per requirements
		ByteCountIn:      0, // Always 0 per requirements
		FirstSeen:        timestamp,
		LastSeen:         timestamp,
		PacketRefs:       []int64{packetID},
		MinPacketSize:    packetSize,
		MaxPacketSize:    packetSize,
		SourcePorts:      flowSourcePorts,
		DestinationPorts: flowDestPorts,
	}

	return flow
}

// updateExistingFlow updates an existing flow's counters
func (fm *DefaultFlowManager) updateExistingFlow(flow *model.Flow, packetSize int,
	timestamp time.Time, packetID int64, srcPort, dstPort string, isReversed bool) {

	// Always increment OUT counters (IN always stays 0 per requirements)
	flow.PacketCountOut++
	flow.ByteCountOut += int64(packetSize)

	// Update timestamps
	if timestamp.Before(flow.FirstSeen) {
		flow.FirstSeen = timestamp
	}
	if timestamp.After(flow.LastSeen) {
		flow.LastSeen = timestamp
	}

	// Add packet reference
	flow.PacketRefs = append(flow.PacketRefs, packetID)

	// Update min/max packet sizes
	if packetSize < flow.MinPacketSize {
		flow.MinPacketSize = packetSize
	}
	if packetSize > flow.MaxPacketSize {
		flow.MaxPacketSize = packetSize
	}

	// Add ports to existing sets (respecting canonical direction)
	if srcPort != "" {
		if isReversed {
			flow.DestinationPorts.Add(srcPort)
		} else {
			flow.SourcePorts.Add(srcPort)
		}
	}
	if dstPort != "" {
		if isReversed {
			flow.SourcePorts.Add(dstPort)
		} else {
			flow.DestinationPorts.Add(dstPort)
		}
	}
}

// GetFlow retrieves a flow by canonical key
func (fm *DefaultFlowManager) GetFlow(src, dst, protocol string) *model.Flow {
	// We need to canonicalize to get the right key
	emptyPorts := model.NewSet()
	canonicalSrc, canonicalDst, _ := fm.flowCanonicalizer.CanonicalizeFlow(
		src, dst, *emptyPorts, *emptyPorts, protocol)

	flowKey := fmt.Sprintf("%s:%s:%s", canonicalSrc, canonicalDst, protocol)
	return fm.flows[flowKey]
}

// GetAllFlows returns all tracked flows
func (fm *DefaultFlowManager) GetAllFlows() []*model.Flow {
	flows := make([]*model.Flow, 0, len(fm.flows))
	for _, flow := range fm.flows {
		flows = append(flows, flow)
	}
	return flows
}

// Clear removes all flows from tracking
func (fm *DefaultFlowManager) Clear() {
	fm.flows = make(map[string]*model.Flow)
}
