// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package lib_layers

import (
	"bufio"
	"errors"
	"fmt"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// HTTPMethod represents HTTP methods
type HTTPMethod string

const (
	HTTPMethodGET      HTTPMethod = "GET"
	HTTPMethodPOST     HTTPMethod = "POST"
	HTTPMethodPUT      HTTPMethod = "PUT"
	HTTPMethodDELETE   HTTPMethod = "DELETE"
	HTTPMethodHEAD     HTTPMethod = "HEAD"
	HTTPMethodOPTIONS  HTTPMethod = "OPTIONS"
	HTTPMethodPATCH    HTTPMethod = "PATCH"
	HTTPMethodTRACE    HTTPMethod = "TRACE"
	HTTPMethodCONNECT  HTTPMethod = "CONNECT"
	HTTPMethodCCM_POST HTTPMethod = "CCM_POST"
)

// HTTPVersion represents HTTP versions
type HTTPVersion string

const (
	HTTPVersion09 HTTPVersion = "HTTP/0.9"
	HTTPVersion10 HTTPVersion = "HTTP/1.0"
	HTTPVersion11 HTTPVersion = "HTTP/1.1"
	HTTPVersion20 HTTPVersion = "HTTP/2.0"
)

// HTTP represents an HTTP packet (request or response)
type HTTP struct {
	BaseLayer

	// Common fields
	Version   HTTPVersion       // HTTP version
	Headers   map[string]string // HTTP headers
	Body      []byte            // HTTP body/payload
	IsRequest bool              // true if this is a request, false if response

	// Request-specific fields
	Method     HTTPMethod // HTTP method (GET, POST, etc.)
	RequestURI string     // Request URI
	URL        *url.URL   // Parsed URL (for requests)

	// Response-specific fields
	StatusCode int    // HTTP status code (for responses)
	StatusMsg  string // HTTP status message (for responses)

	// Additional parsed data
	ContentLength    int64             // Content-Length header value
	ContentType      string            // Content-Type header value
	TransferEncoding []string          // Transfer-Encoding header values
	Connection       string            // Connection header value
	UserAgent        string            // User-Agent header value
	Host             string            // Host header value
	Cookies          map[string]string // Parsed cookies
	QueryParams      map[string]string // Parsed query parameters (for requests)
	Accept           []string          // Accept header values

	Identifier string // Unique identifier for the HTTP request/response used for response matching
}

// LayerType returns the layer type for HTTP
func (h *HTTP) LayerType() gopacket.LayerType {
	return LayerTypeHTTP
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (h *HTTP) CanDecode() gopacket.LayerClass {
	return LayerTypeHTTP
}

// NextLayerType returns the layer type contained by this DecodingLayer
func (h *HTTP) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes the given bytes into this layer
func (h *HTTP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	_ = df // Suppress unused parameter warning

	if len(data) == 0 {
		return errors.New("HTTP packet is empty")
	}

	// Convert bytes to string for initial analysis
	content := string(data)

	// Check if this looks like HTTP data by examining the beginning
	if !h.looksLikeHTTP(content) {
		return errors.New("data does not appear to be HTTP")
	}

	h.BaseLayer = BaseLayer{
		Contents: data,
		Payload:  nil,
	}

	// Initialize maps
	h.Headers = make(map[string]string)
	h.Cookies = make(map[string]string)
	h.QueryParams = make(map[string]string)

	// Split headers and body
	headerEndIndex := strings.Index(content, "\r\n\r\n")
	if headerEndIndex == -1 {
		headerEndIndex = strings.Index(content, "\n\n")
		if headerEndIndex == -1 {
			// No body separator found, treat entire content as headers
			headerEndIndex = len(content)
		} else {
			headerEndIndex += 2 // "\n\n"
		}
	} else {
		headerEndIndex += 4 // "\r\n\r\n"
	}

	headerSection := content[:headerEndIndex]
	if headerEndIndex < len(content) {
		h.Body = []byte(content[headerEndIndex:])
	}

	// Split into lines
	lines := strings.Split(headerSection, "\r\n")
	if len(lines) == 1 && strings.Contains(headerSection, "\n") {
		lines = strings.Split(headerSection, "\n")
	}

	if len(lines) < 1 {
		return errors.New("HTTP packet has no content")
	}

	// Parse first line to determine if it's a request or response
	firstLine := strings.TrimSpace(lines[0])
	if firstLine == "" {
		return errors.New("HTTP packet has empty first line")
	}

	// Check if it's a response (starts with HTTP/)
	if strings.HasPrefix(firstLine, "HTTP/") {
		h.IsRequest = false
		if err := h.parseResponseLine(firstLine); err != nil {
			return err
		}
	} else {
		// It's a request
		h.IsRequest = true
		if err := h.parseRequestLine(firstLine); err != nil {
			return err
		}
	}

	// Parse headers
	if err := h.parseHeaders(lines[1:]); err != nil {
		return err
	}

	// Parse additional fields from headers
	h.parseAdditionalFields()

	return nil
}

// looksLikeHTTP checks if the data appears to be HTTP by examining common patterns
func (h *HTTP) looksLikeHTTP(content string) bool {
	if len(content) < 4 {
		return false
	}

	// Check for HTTP request methods at the beginning
	httpMethods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "TRACE ", "CONNECT "}
	for _, method := range httpMethods {
		if strings.HasPrefix(content, method) {
			return true
		}
	}

	// Check for HTTP response
	if strings.HasPrefix(content, "HTTP/") {
		return true
	}

	return false
}

// parseRequestLine parses the HTTP request line (e.g., "GET /path HTTP/1.1")
func (h *HTTP) parseRequestLine(line string) error {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return errors.New("invalid HTTP request line")
	}

	h.Method = HTTPMethod(strings.ToUpper(parts[0]))
	h.RequestURI = parts[1]

	if len(parts) >= 3 {
		h.Version = HTTPVersion(parts[2])
	} else {
		h.Version = HTTPVersion09 // Default for HTTP/0.9
	}

	// Parse URL and query parameters
	if parsedURL, err := url.Parse(h.RequestURI); err == nil {
		h.URL = parsedURL
		// Parse query parameters
		for key, values := range parsedURL.Query() {
			if len(values) > 0 {
				h.QueryParams[key] = values[0] // Take first value if multiple
			}
		}
	}

	return nil
}

// parseResponseLine parses the HTTP response line (e.g., "HTTP/1.1 200 OK")
func (h *HTTP) parseResponseLine(line string) error {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return errors.New("invalid HTTP response line")
	}

	h.Version = HTTPVersion(parts[0])

	if statusCode, err := strconv.Atoi(parts[1]); err == nil {
		h.StatusCode = statusCode
	} else {
		return fmt.Errorf("invalid status code: %s", parts[1])
	}

	if len(parts) >= 3 {
		h.StatusMsg = parts[2]
	}

	return nil
}

// parseHeaders parses HTTP headers
func (h *HTTP) parseHeaders(headerLines []string) error {
	reader := strings.NewReader(strings.Join(headerLines, "\r\n"))
	tp := textproto.NewReader(bufio.NewReader(reader))

	for {
		line, err := tp.ReadLine()
		if err != nil || line == "" {
			break
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			h.Headers[strings.ToLower(key)] = value
		}
	}

	return nil
}

// parseAdditionalFields extracts commonly used fields from headers
func (h *HTTP) parseAdditionalFields() {
	// Content-Length
	if cl, exists := h.Headers["content-length"]; exists {
		if length, err := strconv.ParseInt(cl, 10, 64); err == nil {
			h.ContentLength = length
		}
	}

	// Content-Type
	if ct, exists := h.Headers["content-type"]; exists {
		h.ContentType = ct
	}

	// Transfer-Encoding
	if te, exists := h.Headers["transfer-encoding"]; exists {
		h.TransferEncoding = strings.Split(te, ",")
		for i := range h.TransferEncoding {
			h.TransferEncoding[i] = strings.TrimSpace(h.TransferEncoding[i])
		}
	}

	// Connection
	if conn, exists := h.Headers["connection"]; exists {
		h.Connection = conn
	}

	// User-Agent
	if ua, exists := h.Headers["user-agent"]; exists {
		h.UserAgent = ua
	}

	// Host
	if host, exists := h.Headers["host"]; exists {
		h.Host = host
	}

	// Parse cookies
	if cookie, exists := h.Headers["cookie"]; exists {
		h.parseCookies(cookie)
	}
	if setCookie, exists := h.Headers["set-cookie"]; exists {
		h.parseSetCookies(setCookie)
	}

	// Parse Accept header
	if accept, exists := h.Headers["accept"]; exists {
		h.Accept = strings.Split(accept, ",")
		for i := range h.Accept {
			h.Accept[i] = strings.TrimSpace(h.Accept[i])
		}
	}
}

// parseCookies parses the Cookie header
func (h *HTTP) parseCookies(cookieHeader string) {
	cookies := strings.Split(cookieHeader, ";")
	for _, cookie := range cookies {
		parts := strings.SplitN(strings.TrimSpace(cookie), "=", 2)
		if len(parts) == 2 {
			h.Cookies[parts[0]] = parts[1]
		}
	}
}

// parseSetCookies parses the Set-Cookie header
func (h *HTTP) parseSetCookies(setCookieHeader string) {
	// Set-Cookie can have multiple values, but we'll parse the main name=value pair
	parts := strings.SplitN(setCookieHeader, "=", 2)
	if len(parts) == 2 {
		cookieName := parts[0]
		cookieValue := strings.Split(parts[1], ";")[0] // Take value before first semicolon
		h.Cookies[cookieName] = cookieValue
	}
}

// String returns a string representation of the HTTP packet
func (h *HTTP) String() string {
	if h.IsRequest {
		return fmt.Sprintf("HTTP Request %s %s %s", h.Method, h.RequestURI, h.Version)
	}
	return fmt.Sprintf("HTTP Response %s %d %s", h.Version, h.StatusCode, h.StatusMsg)
}

// IsResponse returns true if this is an HTTP response
func (h *HTTP) IsResponse() bool {
	return !h.IsRequest
}

// GetHeader returns the value of a header (case-insensitive)
func (h *HTTP) GetHeader(name string) (string, bool) {
	value, exists := h.Headers[strings.ToLower(name)]
	return value, exists
}

// GetCookie returns the value of a cookie
func (h *HTTP) GetCookie(name string) (string, bool) {
	value, exists := h.Cookies[name]
	return value, exists
}

// GetQueryParam returns the value of a query parameter
func (h *HTTP) GetQueryParam(name string) (string, bool) {
	value, exists := h.QueryParams[name]
	return value, exists
}

// IsKeepAlive returns true if the connection should be kept alive
func (h *HTTP) IsKeepAlive() bool {
	if conn, exists := h.GetHeader("connection"); exists {
		return strings.ToLower(conn) == "keep-alive"
	}
	// HTTP/1.1 defaults to keep-alive
	return h.Version == HTTPVersion11
}

// IsChunked returns true if the response uses chunked transfer encoding
func (h *HTTP) IsChunked() bool {
	for _, encoding := range h.TransferEncoding {
		if strings.ToLower(encoding) == "chunked" {
			return true
		}
	}
	return false
}

func (h *HTTP) IsProxyRequest() bool {
	// Check if the request is a CONNECT method, which is used for proxying
	return h.IsRequest && h.Method == HTTPMethodCONNECT
}

func (h *HTTP) IsProxyDiscoveryResponse(request *HTTP) bool {
	// Check if the response is a proxy discovery response
	if !h.IsResponse() {
		return false
	}
	if request != nil && request.URL != nil && request.URL.Path != "" && (strings.Contains(request.URL.Path, "/proxy.pac") || strings.Contains(request.URL.Path, "/wpad.dat")) {
		return true
	}
	return false
}

// IsMSCCMPost Is a Microsoft System Center Configuration Manager (CCM) POST request
func (h *HTTP) IsMSCCMPost() bool {
	// Check if the request is a POST to the CCM endpoint
	if !h.IsRequest || h.Method != HTTPMethodCCM_POST {
		return false
	}
	if strings.Contains(h.RequestURI, "/ccm_system") || strings.Contains(h.RequestURI, "/ccm_client") {
		return true
	}
	return false
}

func (h *HTTP) IsWebSocketUpgrade() bool {
	// Check if the request is an upgrade to WebSocket
	if !h.IsRequest {
		return false
	}
	if upgrade, exists := h.Headers["upgrade"]; exists && strings.ToLower(upgrade) == "websocket" {
		return true
	}
	if connection, exists := h.Headers["connection"]; exists && strings.Contains(strings.ToLower(connection), "upgrade") {
		return true
	}
	return false
}

// LayerTypeHTTP is the layer type for HTTP packets
var LayerTypeHTTP = gopacket.RegisterLayerType(
	1003, // Layer type number - using a high number to avoid conflicts
	gopacket.LayerTypeMetadata{
		Name:    "HTTP",
		Decoder: gopacket.DecodeFunc(decodeHTTP),
	},
)

// decodeHTTP is the decoder function for HTTP packets
func decodeHTTP(data []byte, p gopacket.PacketBuilder) error {
	http := &HTTP{}
	err := http.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(http)
	return p.NextDecoder(http.NextLayerType())
}

// RegisterHTTP registers the HTTP protocol with common TCP ports
func RegisterHTTP() {
	// Register HTTP on common ports
	layers.RegisterTCPPortLayerType(80, LayerTypeHTTP)   // Standard HTTP
	layers.RegisterTCPPortLayerType(8080, LayerTypeHTTP) // Alternative HTTP
	layers.RegisterTCPPortLayerType(8000, LayerTypeHTTP) // Development HTTP
	layers.RegisterTCPPortLayerType(3000, LayerTypeHTTP) // Development HTTP
	layers.RegisterTCPPortLayerType(8888, LayerTypeHTTP) // Alternative HTTP
}

// InitLayerHTTP initializes the HTTP layer for gopacket
func InitLayerHTTP() {
	RegisterHTTP()
}
