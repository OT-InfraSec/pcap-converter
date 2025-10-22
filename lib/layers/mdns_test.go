package lib_layers

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
)

// Helper function to create a basic mDNS header
func createMDNSHeader(id uint16, qr bool, qdCount, anCount, nsCount, arCount uint16) []byte {
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], id)

	var flags uint16
	if qr {
		flags |= 0x8000 // QR bit
	}
	binary.BigEndian.PutUint16(header[2:4], flags)

	binary.BigEndian.PutUint16(header[4:6], qdCount)
	binary.BigEndian.PutUint16(header[6:8], anCount)
	binary.BigEndian.PutUint16(header[8:10], nsCount)
	binary.BigEndian.PutUint16(header[10:12], arCount)

	return header
}

// Helper function to encode a DNS name
func encodeDNSName(name string) []byte {
	if name == "" {
		return []byte{0}
	}

	parts := []byte(name)
	var encoded []byte
	start := 0

	for i, b := range parts {
		if b == '.' {
			length := i - start
			encoded = append(encoded, byte(length))
			encoded = append(encoded, parts[start:i]...)
			start = i + 1
		}
	}

	// Add the last part
	if start < len(parts) {
		length := len(parts) - start
		encoded = append(encoded, byte(length))
		encoded = append(encoded, parts[start:]...)
	}

	// Add null terminator
	encoded = append(encoded, 0)
	return encoded
}

// TestMDNS_DecodeFromBytes_BasicQuery tests decoding a basic mDNS query
func TestMDNS_DecodeFromBytes_BasicQuery(t *testing.T) {
	// Create a simple mDNS query packet
	data := createMDNSHeader(0x1234, false, 1, 0, 0, 0)

	// Add a question: "test.local" A IN
	data = append(data, encodeDNSName("test.local")...)
	data = append(data, 0x00, 0x01) // Type A
	data = append(data, 0x00, 0x01) // Class IN

	mdns := &MDNS{}
	err := mdns.DecodeFromBytes(data, gopacket.NilDecodeFeedback)

	assert.NoError(t, err)
	assert.Equal(t, uint16(0x1234), mdns.ID)
	assert.False(t, mdns.QR)
	assert.Equal(t, uint16(1), mdns.QDCount)
	assert.Equal(t, uint16(0), mdns.ANCount)
	assert.Equal(t, 1, len(mdns.Questions))
	assert.Equal(t, "test.local", string(mdns.Questions[0].Name))
	assert.Equal(t, layers.DNSTypeA, mdns.Questions[0].Type)
	assert.Equal(t, layers.DNSClassIN, mdns.Questions[0].Class)
	assert.False(t, mdns.Questions[0].UnicastResponse)
}

// TestMDNS_DecodeFromBytes_TooShort tests handling of packets that are too short
func TestMDNS_DecodeFromBytes_TooShort(t *testing.T) {
	data := []byte{0x00, 0x01, 0x02} // Only 3 bytes, need at least 12

	mdns := &MDNS{}
	err := mdns.DecodeFromBytes(data, gopacket.NilDecodeFeedback)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

// TestMDNS_DecodeFromBytes_WithUnicastResponse tests the UNICAST-RESPONSE bit
func TestMDNS_DecodeFromBytes_WithUnicastResponse(t *testing.T) {
	data := createMDNSHeader(0x5678, false, 1, 0, 0, 0)

	// Add a question with UNICAST-RESPONSE bit set
	data = append(data, encodeDNSName("service.local")...)
	data = append(data, 0x00, 0x0C) // Type PTR
	data = append(data, 0x80, 0x01) // Class IN with UNICAST-RESPONSE bit (0x8000)

	mdns := &MDNS{}
	err := mdns.DecodeFromBytes(data, gopacket.NilDecodeFeedback)

	assert.NoError(t, err)
	assert.Equal(t, 1, len(mdns.Questions))
	assert.True(t, mdns.Questions[0].UnicastResponse)
	assert.Equal(t, layers.DNSClassIN, mdns.Questions[0].Class)
}

// TestMDNS_DecodeFromBytes_ResponseWithAnswer tests decoding an mDNS response with an answer
func TestMDNS_DecodeFromBytes_ResponseWithAnswer(t *testing.T) {
	data := createMDNSHeader(0x9ABC, true, 0, 1, 0, 0)

	// Add an A record answer: "host.local" -> 192.168.1.1
	data = append(data, encodeDNSName("host.local")...)
	data = append(data, 0x00, 0x01)             // Type A
	data = append(data, 0x00, 0x01)             // Class IN (no CACHE-FLUSH)
	data = append(data, 0x00, 0x00, 0x00, 0x78) // TTL: 120 seconds
	data = append(data, 0x00, 0x04)             // Data length: 4 bytes
	data = append(data, 192, 168, 1, 1)         // IP address

	mdns := &MDNS{}
	err := mdns.DecodeFromBytes(data, gopacket.NilDecodeFeedback)

	assert.NoError(t, err)
	assert.True(t, mdns.QR)
	assert.Equal(t, uint16(1), mdns.ANCount)
	assert.Equal(t, 1, len(mdns.Answers))
	assert.Equal(t, "host.local", string(mdns.Answers[0].Name))
	assert.Equal(t, layers.DNSTypeA, mdns.Answers[0].Type)
	assert.Equal(t, uint32(120), mdns.Answers[0].TTL)
	assert.False(t, mdns.Answers[0].CacheFlush)
	assert.True(t, mdns.Answers[0].IP.Equal(net.IPv4(192, 168, 1, 1)))
}

// TestMDNS_DecodeFromBytes_WithCacheFlush tests the CACHE-FLUSH bit
func TestMDNS_DecodeFromBytes_WithCacheFlush(t *testing.T) {
	data := createMDNSHeader(0xDEF0, true, 0, 1, 0, 0)

	// Add an A record with CACHE-FLUSH bit set
	data = append(data, encodeDNSName("device.local")...)
	data = append(data, 0x00, 0x01)             // Type A
	data = append(data, 0x80, 0x01)             // Class IN with CACHE-FLUSH bit (0x8000)
	data = append(data, 0x00, 0x00, 0x00, 0x3C) // TTL: 60 seconds
	data = append(data, 0x00, 0x04)             // Data length: 4 bytes
	data = append(data, 10, 0, 0, 1)            // IP address

	mdns := &MDNS{}
	err := mdns.DecodeFromBytes(data, gopacket.NilDecodeFeedback)

	assert.NoError(t, err)
	assert.Equal(t, 1, len(mdns.Answers))
	assert.True(t, mdns.Answers[0].CacheFlush)
	assert.Equal(t, layers.DNSClassIN, mdns.Answers[0].Class)
}

// TestMDNS_DecodeFromBytes_AAAARecord tests decoding an AAAA (IPv6) record
func TestMDNS_DecodeFromBytes_AAAARecord(t *testing.T) {
	data := createMDNSHeader(0x1111, true, 0, 1, 0, 0)

	// Add an AAAA record: "ipv6.local" -> 2001:db8::1
	data = append(data, encodeDNSName("ipv6.local")...)
	data = append(data, 0x00, 0x1C)             // Type AAAA
	data = append(data, 0x00, 0x01)             // Class IN
	data = append(data, 0x00, 0x00, 0x00, 0x78) // TTL: 120 seconds
	data = append(data, 0x00, 0x10)             // Data length: 16 bytes
	// IPv6 address: 2001:0db8:0000:0000:0000:0000:0000:0001
	data = append(data, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)

	mdns := &MDNS{}
	err := mdns.DecodeFromBytes(data, gopacket.NilDecodeFeedback)

	assert.NoError(t, err)
	assert.Equal(t, 1, len(mdns.Answers))
	assert.Equal(t, layers.DNSTypeAAAA, mdns.Answers[0].Type)
	assert.Equal(t, net.ParseIP("2001:db8::1"), mdns.Answers[0].IP)
}

// TestMDNS_DecodeFromBytes_PTRRecord tests decoding a PTR record
func TestMDNS_DecodeFromBytes_PTRRecord(t *testing.T) {
	data := createMDNSHeader(0x2222, true, 0, 1, 0, 0)

	// Add a PTR record: "_http._tcp.local" -> "webserver.local"
	serviceName := encodeDNSName("_http._tcp.local")
	targetName := encodeDNSName("webserver.local")

	data = append(data, serviceName...)
	data = append(data, 0x00, 0x0C)             // Type PTR
	data = append(data, 0x00, 0x01)             // Class IN
	data = append(data, 0x00, 0x00, 0x11, 0x94) // TTL: 4500 seconds

	// Data length
	data = append(data, 0x00, byte(len(targetName)))
	data = append(data, targetName...)

	mdns := &MDNS{}
	err := mdns.DecodeFromBytes(data, gopacket.NilDecodeFeedback)

	assert.NoError(t, err)
	assert.Equal(t, 1, len(mdns.Answers))
	assert.Equal(t, layers.DNSTypePTR, mdns.Answers[0].Type)
	assert.Equal(t, "webserver.local", string(mdns.Answers[0].PTR))
}

// TestMDNS_DecodeFromBytes_TXTRecord tests decoding a TXT record
func TestMDNS_DecodeFromBytes_TXTRecord(t *testing.T) {
	data := createMDNSHeader(0x3333, true, 0, 1, 0, 0)

	// Add a TXT record with multiple strings
	data = append(data, encodeDNSName("service.local")...)
	data = append(data, 0x00, 0x10)             // Type TXT
	data = append(data, 0x00, 0x01)             // Class IN
	data = append(data, 0x00, 0x00, 0x00, 0x78) // TTL: 120 seconds

	// TXT data: "key1=value1" and "key2=value2"
	txtData := []byte{
		11, 'k', 'e', 'y', '1', '=', 'v', 'a', 'l', 'u', 'e', '1',
		11, 'k', 'e', 'y', '2', '=', 'v', 'a', 'l', 'u', 'e', '2',
	}
	data = append(data, 0x00, byte(len(txtData))) // Data length
	data = append(data, txtData...)

	mdns := &MDNS{}
	err := mdns.DecodeFromBytes(data, gopacket.NilDecodeFeedback)

	assert.NoError(t, err)
	assert.Equal(t, 1, len(mdns.Answers))
	assert.Equal(t, layers.DNSTypeTXT, mdns.Answers[0].Type)
	assert.Equal(t, 2, len(mdns.Answers[0].TXT))
	assert.Equal(t, "key1=value1", string(mdns.Answers[0].TXT[0]))
	assert.Equal(t, "key2=value2", string(mdns.Answers[0].TXT[1]))
}

// TestMDNS_DecodeFromBytes_SRVRecord tests decoding an SRV record
func TestMDNS_DecodeFromBytes_SRVRecord(t *testing.T) {
	data := createMDNSHeader(0x4444, true, 0, 1, 0, 0)

	// Add an SRV record
	serviceName := encodeDNSName("_http._tcp.local")
	targetName := encodeDNSName("server.local")

	data = append(data, serviceName...)
	data = append(data, 0x00, 0x21)             // Type SRV
	data = append(data, 0x00, 0x01)             // Class IN
	data = append(data, 0x00, 0x00, 0x00, 0x78) // TTL: 120 seconds

	// SRV data
	srvData := make([]byte, 6)
	binary.BigEndian.PutUint16(srvData[0:2], 10)   // Priority
	binary.BigEndian.PutUint16(srvData[2:4], 5)    // Weight
	binary.BigEndian.PutUint16(srvData[4:6], 8080) // Port
	srvData = append(srvData, targetName...)

	data = append(data, 0x00, byte(len(srvData))) // Data length
	data = append(data, srvData...)

	mdns := &MDNS{}
	err := mdns.DecodeFromBytes(data, gopacket.NilDecodeFeedback)

	assert.NoError(t, err)
	assert.Equal(t, 1, len(mdns.Answers))
	assert.Equal(t, layers.DNSTypeSRV, mdns.Answers[0].Type)
	assert.Equal(t, uint16(10), mdns.Answers[0].SRV.Priority)
	assert.Equal(t, uint16(5), mdns.Answers[0].SRV.Weight)
	assert.Equal(t, uint16(8080), mdns.Answers[0].SRV.Port)
	assert.Equal(t, "server.local", string(mdns.Answers[0].SRV.Name))
}

// TestMDNS_DecodeFromBytes_MultipleQuestions tests multiple questions in one packet
func TestMDNS_DecodeFromBytes_MultipleQuestions(t *testing.T) {
	data := createMDNSHeader(0x5555, false, 2, 0, 0, 0)

	// Question 1: "test1.local" A
	data = append(data, encodeDNSName("test1.local")...)
	data = append(data, 0x00, 0x01) // Type A
	data = append(data, 0x00, 0x01) // Class IN

	// Question 2: "test2.local" AAAA
	data = append(data, encodeDNSName("test2.local")...)
	data = append(data, 0x00, 0x1C) // Type AAAA
	data = append(data, 0x00, 0x01) // Class IN

	mdns := &MDNS{}
	err := mdns.DecodeFromBytes(data, gopacket.NilDecodeFeedback)

	assert.NoError(t, err)
	assert.Equal(t, uint16(2), mdns.QDCount)
	assert.Equal(t, 2, len(mdns.Questions))
	assert.Equal(t, "test1.local", string(mdns.Questions[0].Name))
	assert.Equal(t, layers.DNSTypeA, mdns.Questions[0].Type)
	assert.Equal(t, "test2.local", string(mdns.Questions[1].Name))
	assert.Equal(t, layers.DNSTypeAAAA, mdns.Questions[1].Type)
}

// TestMDNS_LayerType tests the LayerType method
func TestMDNS_LayerType(t *testing.T) {
	mdns := &MDNS{}
	assert.Equal(t, LayerTypeMDNS, mdns.LayerType())
}

// TestMDNS_CanDecode tests the CanDecode method
func TestMDNS_CanDecode(t *testing.T) {
	mdns := &MDNS{}
	assert.Equal(t, LayerTypeMDNS, mdns.CanDecode())
}

// TestMDNS_NextLayerType tests the NextLayerType method
func TestMDNS_NextLayerType(t *testing.T) {
	mdns := &MDNS{}
	assert.Equal(t, gopacket.LayerTypePayload, mdns.NextLayerType())
}

// TestMDNS_String_Query tests the String method for queries
func TestMDNS_String_Query(t *testing.T) {
	mdns := &MDNS{
		ID:      0x1234,
		QR:      false,
		QDCount: 2,
	}
	result := mdns.String()
	assert.Contains(t, result, "mDNS Query")
	assert.Contains(t, result, "4660") // 0x1234 in decimal
	assert.Contains(t, result, "Questions:2")
}

// TestMDNS_String_Response tests the String method for responses
func TestMDNS_String_Response(t *testing.T) {
	mdns := &MDNS{
		ID:      0x5678,
		QR:      true,
		QDCount: 1,
		ANCount: 3,
	}
	result := mdns.String()
	assert.Contains(t, result, "mDNS Response")
	assert.Contains(t, result, "22136") // 0x5678 in decimal
	assert.Contains(t, result, "Questions:1")
	assert.Contains(t, result, "Answers:3")
}

// TestMDNS_IsQuery tests the IsQuery method
func TestMDNS_IsQuery(t *testing.T) {
	mdns := &MDNS{QR: false}
	assert.True(t, mdns.IsQuery())

	mdns.QR = true
	assert.False(t, mdns.IsQuery())
}

// TestMDNS_IsResponse tests the IsResponse method
func TestMDNS_IsResponse(t *testing.T) {
	mdns := &MDNS{QR: true}
	assert.True(t, mdns.IsResponse())

	mdns.QR = false
	assert.False(t, mdns.IsResponse())
}

// TestMDNS_IsMulticast tests the IsMulticast method
func TestMDNS_IsMulticast(t *testing.T) {
	mdns := &MDNS{}

	// IPv4 multicast address
	assert.True(t, mdns.IsMulticast(net.IPv4(224, 0, 0, 251)))

	// IPv6 multicast address
	assert.True(t, mdns.IsMulticast(net.ParseIP("ff02::fb")))

	// Non-multicast addresses
	assert.False(t, mdns.IsMulticast(net.IPv4(192, 168, 1, 1)))
	assert.False(t, mdns.IsMulticast(net.ParseIP("2001:db8::1")))
}

// TestMDNSQuestion_GetServiceType tests the GetServiceType method
func TestMDNSQuestion_GetServiceType(t *testing.T) {
	tests := []struct {
		name     string
		question MDNSQuestion
		expected string
	}{
		{
			name:     "Valid service type",
			question: MDNSQuestion{Name: []byte("_http._tcp.local")},
			expected: "_http._tcp.local",
		},
		{
			name:     "Valid printer service",
			question: MDNSQuestion{Name: []byte("_printer._tcp.local")},
			expected: "_printer._tcp.local",
		},
		{
			name:     "Not a service (no underscore)",
			question: MDNSQuestion{Name: []byte("device.local")},
			expected: "",
		},
		{
			name:     "Not local domain",
			question: MDNSQuestion{Name: []byte("_http._tcp.example.com")},
			expected: "",
		},
		{
			name:     "Empty name",
			question: MDNSQuestion{Name: []byte("")},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.question.GetServiceType()
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestMDNS_DecodeFromBytes_FlagParsing tests parsing of various DNS flags
func TestMDNS_DecodeFromBytes_FlagParsing(t *testing.T) {
	// Create header with various flags set
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], 0xABCD) // ID

	// Set flags: QR=1, OpCode=2, AA=1, TC=1, RD=1, RA=1, Z=3, ResponseCode=5
	flags := uint16(0)
	flags |= 0x8000    // QR
	flags |= (2 << 11) // OpCode
	flags |= 0x0400    // AA
	flags |= 0x0200    // TC
	flags |= 0x0100    // RD
	flags |= 0x0080    // RA
	flags |= (3 << 4)  // Z
	flags |= 5         // ResponseCode
	binary.BigEndian.PutUint16(header[2:4], flags)

	// No questions or answers
	binary.BigEndian.PutUint16(header[4:6], 0)
	binary.BigEndian.PutUint16(header[6:8], 0)
	binary.BigEndian.PutUint16(header[8:10], 0)
	binary.BigEndian.PutUint16(header[10:12], 0)

	mdns := &MDNS{}
	err := mdns.DecodeFromBytes(header, gopacket.NilDecodeFeedback)

	assert.NoError(t, err)
	assert.Equal(t, uint16(0xABCD), mdns.ID)
	assert.True(t, mdns.QR)
	assert.Equal(t, uint8(2), mdns.OpCode)
	assert.True(t, mdns.AA)
	assert.True(t, mdns.TC)
	assert.True(t, mdns.RD)
	assert.True(t, mdns.RA)
	assert.Equal(t, uint8(3), mdns.Z)
	assert.Equal(t, uint8(5), mdns.ResponseCode)
}

// TestMDNS_DecodeFromBytes_InsufficientDataForQuestion tests error handling
func TestMDNS_DecodeFromBytes_InsufficientDataForQuestion(t *testing.T) {
	data := createMDNSHeader(0x1234, false, 1, 0, 0, 0)
	// Add incomplete question (no type/class)
	data = append(data, encodeDNSName("test.local")...)
	// Missing type and class fields

	mdns := &MDNS{}
	err := mdns.DecodeFromBytes(data, gopacket.NilDecodeFeedback)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "insufficient data")
}

// TestMDNS_DecodeFromBytes_EmptyName tests handling of empty DNS names
func TestMDNS_DecodeFromBytes_EmptyName(t *testing.T) {
	data := createMDNSHeader(0x7890, false, 1, 0, 0, 0)

	// Add a question with empty name (just null terminator)
	data = append(data, 0x00)       // Empty name
	data = append(data, 0x00, 0x01) // Type A
	data = append(data, 0x00, 0x01) // Class IN

	mdns := &MDNS{}
	err := mdns.DecodeFromBytes(data, gopacket.NilDecodeFeedback)

	assert.NoError(t, err)
	assert.Equal(t, 1, len(mdns.Questions))
	assert.Equal(t, "", string(mdns.Questions[0].Name))
}

// TestMDNS_DecodeMDNS tests the decoder function
func TestMDNS_DecodeMDNS(t *testing.T) {
	data := createMDNSHeader(0x9999, false, 1, 0, 0, 0)
	data = append(data, encodeDNSName("test.local")...)
	data = append(data, 0x00, 0x01) // Type A
	data = append(data, 0x00, 0x01) // Class IN

	// Create a mock packet builder
	packet := gopacket.NewPacket(data, LayerTypeMDNS, gopacket.Default)

	// The packet should have an MDNS layer
	mdnsLayer := packet.Layer(LayerTypeMDNS)
	assert.NotNil(t, mdnsLayer)

	mdns, ok := mdnsLayer.(*MDNS)
	assert.True(t, ok)
	assert.Equal(t, uint16(0x9999), mdns.ID)
}

// TestMDNS_parseTXT_EdgeCases tests edge cases in TXT record parsing
func TestMDNS_parseTXT_EdgeCases(t *testing.T) {
	mdns := &MDNS{}

	// Empty TXT data
	result := mdns.parseTXT([]byte{})
	assert.Empty(t, result)

	// Single empty string
	result = mdns.parseTXT([]byte{0})
	assert.Equal(t, 1, len(result))
	assert.Empty(t, result[0])

	// Truncated data (length extends beyond data)
	result = mdns.parseTXT([]byte{10, 'h', 'e', 'l', 'l', 'o'}) // Says 10 bytes but only has 5
	assert.Equal(t, 0, len(result))                             // Should stop parsing
}

// TestMDNS_DecodeFromBytes_AuthorityAndAdditional tests parsing authority and additional sections
func TestMDNS_DecodeFromBytes_AuthorityAndAdditional(t *testing.T) {
	data := createMDNSHeader(0xAAAA, true, 0, 0, 1, 1)

	// Add authority record
	data = append(data, encodeDNSName("authority.local")...)
	data = append(data, 0x00, 0x02)             // Type NS
	data = append(data, 0x00, 0x01)             // Class IN
	data = append(data, 0x00, 0x00, 0x00, 0x78) // TTL
	nsName := encodeDNSName("ns.local")
	data = append(data, 0x00, byte(len(nsName))) // Data length
	data = append(data, nsName...)

	// Add additional record
	data = append(data, encodeDNSName("additional.local")...)
	data = append(data, 0x00, 0x01)             // Type A
	data = append(data, 0x00, 0x01)             // Class IN
	data = append(data, 0x00, 0x00, 0x00, 0x3C) // TTL
	data = append(data, 0x00, 0x04)             // Data length
	data = append(data, 10, 0, 0, 2)            // IP

	mdns := &MDNS{}
	err := mdns.DecodeFromBytes(data, gopacket.NilDecodeFeedback)

	assert.NoError(t, err)
	assert.Equal(t, uint16(1), mdns.NSCount)
	assert.Equal(t, uint16(1), mdns.ARCount)
	assert.Equal(t, 1, len(mdns.Authorities))
	assert.Equal(t, 1, len(mdns.Additionals))
	assert.Equal(t, "authority.local", string(mdns.Authorities[0].Name))
	assert.Equal(t, "additional.local", string(mdns.Additionals[0].Name))
}
