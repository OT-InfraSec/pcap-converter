package lib_layers

import (
	"testing"

	"github.com/InfraSecConsult/pcap-importer-go/lib/helper"
	"github.com/google/gopacket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSSDP_DecodeFromBytes_MSearchRequest tests decoding an M-SEARCH request
func TestSSDP_DecodeFromBytes_MSearchRequest(t *testing.T) {
	data := []byte("M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 3\r\n" +
		"ST: ssdp:all\r\n" +
		"\r\n")

	ssdp := &SSDP{}
	err := ssdp.DecodeFromBytes(data, nil)

	require.NoError(t, err)
	assert.False(t, ssdp.IsResponse)
	assert.Equal(t, "M-SEARCH", ssdp.Method)
	assert.Equal(t, "*", ssdp.RequestURI)
	assert.Equal(t, "HTTP/1.1", ssdp.Version)
	assert.Equal(t, "239.255.255.250:1900", ssdp.Headers["HOST"])
	assert.Equal(t, "\"ssdp:discover\"", ssdp.Headers["MAN"])
	assert.Equal(t, "3", ssdp.Headers["MX"])
	assert.Equal(t, "ssdp:all", ssdp.Headers["ST"])
	assert.True(t, ssdp.IsSearch())
	assert.False(t, ssdp.IsNotify())
}

// TestSSDP_DecodeFromBytes_NotifyAlive tests decoding a NOTIFY ssdp:alive request
func TestSSDP_DecodeFromBytes_NotifyAlive(t *testing.T) {
	data := []byte("NOTIFY * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"CACHE-CONTROL: max-age=1800\r\n" +
		"LOCATION: http://192.168.1.1:80/description.xml\r\n" +
		"NT: upnp:rootdevice\r\n" +
		"NTS: ssdp:alive\r\n" +
		"SERVER: OS/1.0 UPnP/1.0 Product/1.0\r\n" +
		"USN: uuid:12345678-1234-1234-1234-123456789012::upnp:rootdevice\r\n" +
		"\r\n")

	ssdp := &SSDP{}
	err := ssdp.DecodeFromBytes(data, nil)

	require.NoError(t, err)
	assert.False(t, ssdp.IsResponse)
	assert.Equal(t, "NOTIFY", ssdp.Method)
	assert.Equal(t, "*", ssdp.RequestURI)
	assert.Equal(t, "HTTP/1.1", ssdp.Version)
	assert.Equal(t, "ssdp:alive", ssdp.Headers["NTS"])
	assert.True(t, ssdp.IsAlive())
	assert.False(t, ssdp.IsByeBye())
	assert.True(t, ssdp.IsNotify())
	assert.False(t, ssdp.IsSearch())
}

// TestSSDP_DecodeFromBytes_NotifyByeBye tests decoding a NOTIFY ssdp:byebye request
func TestSSDP_DecodeFromBytes_NotifyByeBye(t *testing.T) {
	data := []byte("NOTIFY * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"NT: upnp:rootdevice\r\n" +
		"NTS: ssdp:byebye\r\n" +
		"USN: uuid:12345678-1234-1234-1234-123456789012::upnp:rootdevice\r\n" +
		"\r\n")

	ssdp := &SSDP{}
	err := ssdp.DecodeFromBytes(data, nil)

	require.NoError(t, err)
	assert.False(t, ssdp.IsResponse)
	assert.Equal(t, "NOTIFY", ssdp.Method)
	assert.Equal(t, "ssdp:byebye", ssdp.Headers["NTS"])
	assert.False(t, ssdp.IsAlive())
	assert.True(t, ssdp.IsByeBye())
}

// TestSSDP_DecodeFromBytes_HTTPResponse tests decoding an HTTP response
func TestSSDP_DecodeFromBytes_HTTPResponse(t *testing.T) {
	data := []byte("HTTP/1.1 200 OK\r\n" +
		"CACHE-CONTROL: max-age=1800\r\n" +
		"EXT:\r\n" +
		"LOCATION: http://192.168.1.1:80/description.xml\r\n" +
		"SERVER: OS/1.0 UPnP/1.0 Product/1.0\r\n" +
		"ST: upnp:rootdevice\r\n" +
		"USN: uuid:12345678-1234-1234-1234-123456789012::upnp:rootdevice\r\n" +
		"\r\n")

	ssdp := &SSDP{}
	err := ssdp.DecodeFromBytes(data, nil)

	require.NoError(t, err)
	assert.True(t, ssdp.IsResponse)
	assert.Equal(t, "HTTP/1.1", ssdp.Version)
	assert.Equal(t, 200, ssdp.StatusCode)
	assert.Equal(t, "OK", ssdp.StatusMsg)
	assert.Equal(t, "max-age=1800", ssdp.Headers["CACHE-CONTROL"])
	assert.Equal(t, "http://192.168.1.1:80/description.xml", ssdp.Headers["LOCATION"])
}

// TestSSDP_DecodeFromBytes_EmptyPacket tests handling of an empty packet
func TestSSDP_DecodeFromBytes_EmptyPacket(t *testing.T) {
	data := []byte{}

	ssdp := &SSDP{}
	err := ssdp.DecodeFromBytes(data, nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

// TestSSDP_DecodeFromBytes_EmptyFirstLine tests handling of an empty first line
func TestSSDP_DecodeFromBytes_EmptyFirstLine(t *testing.T) {
	data := []byte("\r\nHOST: 239.255.255.250:1900\r\n")

	ssdp := &SSDP{}
	err := ssdp.DecodeFromBytes(data, nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty first line")
}

// TestSSDP_DecodeFromBytes_OnlyNewlines tests handling of packet with only newlines
func TestSSDP_DecodeFromBytes_OnlyNewlines(t *testing.T) {
	data := []byte("\n\n\n")

	ssdp := &SSDP{}
	err := ssdp.DecodeFromBytes(data, nil)

	assert.Error(t, err)
}

// TestSSDP_DecodeFromBytes_MalformedStatusCode tests handling of malformed status code
func TestSSDP_DecodeFromBytes_MalformedStatusCode(t *testing.T) {
	data := []byte("HTTP/1.1 ABC OK\r\n\r\n")

	ssdp := &SSDP{}
	err := ssdp.DecodeFromBytes(data, nil)

	require.NoError(t, err)
	assert.True(t, ssdp.IsResponse)
	assert.Equal(t, 0, ssdp.StatusCode) // Should default to 0 when parsing fails
}

// TestSSDP_DecodeFromBytes_ResponseWithoutStatusMsg tests response without status message
func TestSSDP_DecodeFromBytes_ResponseWithoutStatusMsg(t *testing.T) {
	data := []byte("HTTP/1.1 200\r\n\r\n")

	ssdp := &SSDP{}
	err := ssdp.DecodeFromBytes(data, nil)

	require.NoError(t, err)
	assert.True(t, ssdp.IsResponse)
	assert.Equal(t, 200, ssdp.StatusCode)
	assert.Equal(t, "", ssdp.StatusMsg)
}

// TestSSDP_DecodeFromBytes_RequestWithoutURI tests request without URI
func TestSSDP_DecodeFromBytes_RequestWithoutURI(t *testing.T) {
	data := []byte("M-SEARCH\r\n\r\n")

	ssdp := &SSDP{}
	err := ssdp.DecodeFromBytes(data, nil)

	require.NoError(t, err)
	assert.False(t, ssdp.IsResponse)
	assert.Equal(t, "M-SEARCH", ssdp.Method)
	assert.Equal(t, "", ssdp.RequestURI)
	assert.Equal(t, "", ssdp.Version)
}

// TestSSDP_DecodeFromBytes_HeadersWithSpaces tests headers with various spacing
func TestSSDP_DecodeFromBytes_HeadersWithSpaces(t *testing.T) {
	data := []byte("NOTIFY * HTTP/1.1\r\n" +
		"HOST:  239.255.255.250:1900  \r\n" +
		"  NTS  :  ssdp:alive  \r\n" +
		"\r\n")

	ssdp := &SSDP{}
	err := ssdp.DecodeFromBytes(data, nil)

	require.NoError(t, err)
	assert.Equal(t, "239.255.255.250:1900", ssdp.Headers["HOST"])
	assert.Equal(t, "ssdp:alive", ssdp.Headers["NTS"])
}

// TestSSDP_DecodeFromBytes_CaseInsensitiveHeaders tests that headers are stored in uppercase
func TestSSDP_DecodeFromBytes_CaseInsensitiveHeaders(t *testing.T) {
	data := []byte("NOTIFY * HTTP/1.1\r\n" +
		"host: 239.255.255.250:1900\r\n" +
		"Host: 239.255.255.250:1900\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"\r\n")

	ssdp := &SSDP{}
	err := ssdp.DecodeFromBytes(data, nil)

	require.NoError(t, err)
	// All should be stored under "HOST" key
	assert.Equal(t, "239.255.255.250:1900", ssdp.Headers["HOST"])
}

// TestSSDP_DecodeFromBytes_UnixNewlines tests handling of Unix-style newlines
func TestSSDP_DecodeFromBytes_UnixNewlines(t *testing.T) {
	data := []byte("M-SEARCH * HTTP/1.1\n" +
		"HOST: 239.255.255.250:1900\n" +
		"ST: ssdp:all\n" +
		"\n")

	ssdp := &SSDP{}
	err := ssdp.DecodeFromBytes(data, nil)

	require.NoError(t, err)
	assert.False(t, ssdp.IsResponse)
	assert.Equal(t, "M-SEARCH", ssdp.Method)
	// Note: The textproto reader may not parse headers correctly with Unix newlines
	// This test verifies that at minimum the first line is parsed without errors
}

// TestSSDP_DecodeFromBytes_MalformedHeader tests handling of malformed headers
func TestSSDP_DecodeFromBytes_MalformedHeader(t *testing.T) {
	data := []byte("NOTIFY * HTTP/1.1\r\n" +
		"ValidHeader: value\r\n" +
		"MalformedHeaderWithoutColon\r\n" +
		"AnotherValid: value2\r\n" +
		"\r\n")

	ssdp := &SSDP{}
	err := ssdp.DecodeFromBytes(data, nil)

	require.NoError(t, err)
	// Malformed header should be skipped
	assert.Equal(t, "value", ssdp.Headers["VALIDHEADER"])
	assert.Equal(t, "value2", ssdp.Headers["ANOTHERVALID"])
	assert.NotContains(t, ssdp.Headers, "MALFORMEDHEADERWITHOUTCOLON")
}

// TestSSDP_String_Request tests string representation of a request
func TestSSDP_String_Request(t *testing.T) {
	ssdp := &SSDP{
		IsResponse: false,
		Method:     "M-SEARCH",
		RequestURI: "*",
	}

	str := ssdp.String()
	assert.Equal(t, "SSDP Request M-SEARCH *", str)
}

// TestSSDP_String_Response tests string representation of a response
func TestSSDP_String_Response(t *testing.T) {
	ssdp := &SSDP{
		IsResponse: true,
		StatusCode: 200,
		StatusMsg:  "OK",
	}

	str := ssdp.String()
	assert.Equal(t, "SSDP Response 200 OK", str)
}

// TestSSDP_GetHeader_CaseInsensitive tests case-insensitive header retrieval
func TestSSDP_GetHeader_CaseInsensitive(t *testing.T) {
	ssdp := &SSDP{
		Headers: map[string]string{
			"HOST": "239.255.255.250:1900",
			"NTS":  "ssdp:alive",
		},
	}

	// Test various cases
	value, exists := ssdp.GetHeader("host")
	assert.True(t, exists)
	assert.Equal(t, "239.255.255.250:1900", value)

	value, exists = ssdp.GetHeader("Host")
	assert.True(t, exists)
	assert.Equal(t, "239.255.255.250:1900", value)

	value, exists = ssdp.GetHeader("HOST")
	assert.True(t, exists)
	assert.Equal(t, "239.255.255.250:1900", value)

	value, exists = ssdp.GetHeader("nts")
	assert.True(t, exists)
	assert.Equal(t, "ssdp:alive", value)
}

// TestSSDP_GetHeader_NotFound tests retrieving non-existent header
func TestSSDP_GetHeader_NotFound(t *testing.T) {
	ssdp := &SSDP{
		Headers: map[string]string{},
	}

	value, exists := ssdp.GetHeader("NonExistent")
	assert.False(t, exists)
	assert.Equal(t, "", value)
}

// TestSSDP_IsAlive_Various tests IsAlive with various NTS values
func TestSSDP_IsAlive_Various(t *testing.T) {
	tests := []struct {
		name     string
		ntsValue string
		expected bool
	}{
		{"alive lowercase", "ssdp:alive", true},
		{"alive uppercase", "SSDP:ALIVE", true},
		{"alive mixed case", "SsDp:AlIvE", true},
		{"byebye", "ssdp:byebye", false},
		{"other value", "ssdp:update", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ssdp := &SSDP{
				Headers: map[string]string{
					"NTS": tt.ntsValue,
				},
			}
			assert.Equal(t, tt.expected, ssdp.IsAlive())
		})
	}
}

// TestSSDP_IsAlive_NoHeader tests IsAlive when NTS header is missing
func TestSSDP_IsAlive_NoHeader(t *testing.T) {
	ssdp := &SSDP{
		Headers: map[string]string{},
	}
	assert.False(t, ssdp.IsAlive())
}

// TestSSDP_IsByeBye_Various tests IsByeBye with various NTS values
func TestSSDP_IsByeBye_Various(t *testing.T) {
	tests := []struct {
		name     string
		ntsValue string
		expected bool
	}{
		{"byebye lowercase", "ssdp:byebye", true},
		{"byebye uppercase", "SSDP:BYEBYE", true},
		{"byebye mixed case", "SsDp:ByEbYe", true},
		{"alive", "ssdp:alive", false},
		{"other value", "ssdp:update", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ssdp := &SSDP{
				Headers: map[string]string{
					"NTS": tt.ntsValue,
				},
			}
			assert.Equal(t, tt.expected, ssdp.IsByeBye())
		})
	}
}

// TestSSDP_IsByeBye_NoHeader tests IsByeBye when NTS header is missing
func TestSSDP_IsByeBye_NoHeader(t *testing.T) {
	ssdp := &SSDP{
		Headers: map[string]string{},
	}
	assert.False(t, ssdp.IsByeBye())
}

// TestSSDP_IsSearch_Various tests IsSearch with various methods
func TestSSDP_IsSearch_Various(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		isResponse bool
		expected   bool
	}{
		{"M-SEARCH request uppercase", "M-SEARCH", false, true},
		{"m-search request lowercase", "m-search", false, true},
		{"M-Search request mixed case", "M-Search", false, true},
		{"NOTIFY request", "NOTIFY", false, false},
		{"M-SEARCH response", "M-SEARCH", true, false},
		{"GET request", "GET", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ssdp := &SSDP{
				Method:     tt.method,
				IsResponse: tt.isResponse,
			}
			assert.Equal(t, tt.expected, ssdp.IsSearch())
		})
	}
}

// TestSSDP_IsNotify_Various tests IsNotify with various methods
func TestSSDP_IsNotify_Various(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		isResponse bool
		expected   bool
	}{
		{"NOTIFY request uppercase", "NOTIFY", false, true},
		{"notify request lowercase", "notify", false, true},
		{"Notify request mixed case", "Notify", false, true},
		{"M-SEARCH request", "M-SEARCH", false, false},
		{"NOTIFY response", "NOTIFY", true, false},
		{"GET request", "GET", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ssdp := &SSDP{
				Method:     tt.method,
				IsResponse: tt.isResponse,
			}
			assert.Equal(t, tt.expected, ssdp.IsNotify())
		})
	}
}

// TestSSDP_LayerType tests LayerType method
func TestSSDP_LayerType(t *testing.T) {
	ssdp := &SSDP{}
	assert.Equal(t, LayerTypeSSDP, ssdp.LayerType())
}

// TestSSDP_CanDecode tests CanDecode method
func TestSSDP_CanDecode(t *testing.T) {
	ssdp := &SSDP{}
	assert.Equal(t, LayerTypeSSDP, ssdp.CanDecode())
}

// TestSSDP_NextLayerType tests NextLayerType method
func TestSSDP_NextLayerType(t *testing.T) {
	ssdp := &SSDP{}
	assert.Equal(t, gopacket.LayerTypePayload, ssdp.NextLayerType())
}

// TestSSDP_BaseLayer tests that BaseLayer is properly set
func TestSSDP_BaseLayer(t *testing.T) {
	data := []byte("M-SEARCH * HTTP/1.1\r\n\r\n")
	ssdp := &SSDP{}
	err := ssdp.DecodeFromBytes(data, nil)

	require.NoError(t, err)
	assert.Equal(t, data, ssdp.BaseLayer.Contents)
	assert.Nil(t, ssdp.BaseLayer.Payload)
}

// TestSSDP_DecodeSSDP tests the decodeSSDP function
func TestSSDP_DecodeSSDP(t *testing.T) {
	data := []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\r\n")

	mockBuilder := &helper.TestPacketBuilder{
		Layers: []gopacket.Layer{},
	}

	err := decodeSSDP(data, mockBuilder)
	require.NoError(t, err)

	// Check that the layer was added
	assert.Len(t, mockBuilder.Layers, 1)

	// Check that NextDecoder was called with the right layer type
	assert.Equal(t, gopacket.LayerTypePayload, mockBuilder.NextDecoderType)
}

// TestSSDP_DecodeSSDP_Error tests decodeSSDP with invalid data
func TestSSDP_DecodeSSDP_Error(t *testing.T) {
	data := []byte{} // Empty data should cause error

	mockBuilder := &helper.TestPacketBuilder{
		Layers: []gopacket.Layer{},
	}

	err := decodeSSDP(data, mockBuilder)
	assert.Error(t, err)
}

// TestSSDP_CompletePacketWithMultipleHeaders tests a complete packet with many headers
func TestSSDP_CompletePacketWithMultipleHeaders(t *testing.T) {
	data := []byte("HTTP/1.1 200 OK\r\n" +
		"CACHE-CONTROL: max-age=1800\r\n" +
		"DATE: Mon, 01 Jan 2024 00:00:00 GMT\r\n" +
		"EXT:\r\n" +
		"LOCATION: http://192.168.1.1:80/description.xml\r\n" +
		"SERVER: Linux/3.x UPnP/1.1 MyDevice/1.0\r\n" +
		"ST: urn:schemas-upnp-org:device:MediaRenderer:1\r\n" +
		"USN: uuid:12345678-1234-1234-1234-123456789012::urn:schemas-upnp-org:device:MediaRenderer:1\r\n" +
		"BOOTID.UPNP.ORG: 1\r\n" +
		"CONFIGID.UPNP.ORG: 1337\r\n" +
		"\r\n")

	ssdp := &SSDP{}
	err := ssdp.DecodeFromBytes(data, nil)

	require.NoError(t, err)
	assert.True(t, ssdp.IsResponse)
	assert.Equal(t, 200, ssdp.StatusCode)
	assert.Equal(t, "OK", ssdp.StatusMsg)
	assert.Equal(t, "max-age=1800", ssdp.Headers["CACHE-CONTROL"])
	assert.Equal(t, "Mon, 01 Jan 2024 00:00:00 GMT", ssdp.Headers["DATE"])
	assert.Equal(t, "", ssdp.Headers["EXT"])
	assert.Equal(t, "http://192.168.1.1:80/description.xml", ssdp.Headers["LOCATION"])
	assert.Equal(t, "Linux/3.x UPnP/1.1 MyDevice/1.0", ssdp.Headers["SERVER"])
	assert.Equal(t, "urn:schemas-upnp-org:device:MediaRenderer:1", ssdp.Headers["ST"])
	assert.Equal(t, "1", ssdp.Headers["BOOTID.UPNP.ORG"])
	assert.Equal(t, "1337", ssdp.Headers["CONFIGID.UPNP.ORG"])
}
