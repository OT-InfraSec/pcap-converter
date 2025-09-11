package parser

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
)

// Helper functions for creating common industrial protocol errors

// NewMalformedPacketError creates an error for malformed packets
func NewMalformedPacketError(protocol string, packet gopacket.Packet, err error, context string) *IndustrialProtocolError {
	var packetData []byte
	if packet != nil && packet.Data() != nil {
		// Copy packet data for debugging (limit to 256 bytes to avoid memory issues)
		dataLen := len(packet.Data())
		if dataLen > 256 {
			dataLen = 256
		}
		packetData = make([]byte, dataLen)
		copy(packetData, packet.Data()[:dataLen])
	}

	return &IndustrialProtocolError{
		Protocol:    protocol,
		Packet:      packet,
		Err:         err,
		Context:     context,
		Timestamp:   time.Now(),
		Recoverable: true, // Malformed packets are generally recoverable
		PacketData:  packetData,
	}
}

// NewIncompleteDataError creates an error for incomplete protocol data
func NewIncompleteDataError(protocol string, packet gopacket.Packet, expectedSize, actualSize int, context string) *IndustrialProtocolError {
	err := fmt.Errorf("incomplete data: expected %d bytes, got %d bytes", expectedSize, actualSize)

	return &IndustrialProtocolError{
		Protocol:    protocol,
		Packet:      packet,
		Err:         err,
		Context:     context,
		Timestamp:   time.Now(),
		Recoverable: true, // Incomplete data is generally recoverable
	}
}

// NewProtocolDetectionError creates an error for protocol detection failures
func NewProtocolDetectionError(protocol string, packet gopacket.Packet, err error, context string) *IndustrialProtocolError {
	return &IndustrialProtocolError{
		Protocol:    protocol,
		Packet:      packet,
		Err:         err,
		Context:     context,
		Timestamp:   time.Now(),
		Recoverable: true, // Detection failures are generally recoverable
	}
}

// NewParsingError creates a general parsing error
func NewParsingError(protocol string, packet gopacket.Packet, err error, context string, recoverable bool) *IndustrialProtocolError {
	return &IndustrialProtocolError{
		Protocol:    protocol,
		Packet:      packet,
		Err:         err,
		Context:     context,
		Timestamp:   time.Now(),
		Recoverable: recoverable,
	}
}
