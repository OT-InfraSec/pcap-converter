package parser

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	helper2 "github.com/InfraSecConsult/pcap-importer-go/lib/helper"
	model2 "github.com/InfraSecConsult/pcap-importer-go/lib/model"

	"github.com/InfraSecConsult/pcap-importer-go/internal/repository"

	liblayers "github.com/InfraSecConsult/pcap-importer-go/lib/layers"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type SSDPQuery struct {
	QueryingDeviceIP string
	QueryType        string
	ST               string
	UserAgent        string
	Timestamp        time.Time
}

type DNSQuery struct {
	QueryingDeviceIP  string
	AnsweringDeviceIP string
	QueryName         string
	QueryType         string
	Questions         map[string]interface{}
	Answers           map[string]interface{}
	Timestamp         time.Time
}

type GopacketParser struct {
	PcapFile string
	TenantID string // Tenant ID for multi-tenant support

	// Managers for different entity types
	flowManager    FlowManager
	deviceManager  DeviceManager
	serviceManager ServiceManager

	// SSDP queries
	ssdpQueries map[string]*SSDPQuery
	// DNS queries
	dnsQueries map[string]*DNSQuery

	httpRingBuffer *helper2.RingBuffer[*liblayers.HTTP]

	// Collect protocol usage stats during parsing to defer DB writes
	protocolUsageStats []*model2.ProtocolUsageStats

	repo             repository.Repository
	industrialParser IndustrialProtocolParser
}

func NewGopacketParser(pcapFile string, repo repository.Repository, tenantID string) *GopacketParser {
	// Initialize device counter from existing devices
	initialDeviceCounter := int64(0)
	devices, err := repo.GetDevices(tenantID, nil)
	if err == nil {
		for _, device := range devices {
			if device.ID >= initialDeviceCounter {
				initialDeviceCounter = device.ID + 1
			}
		}
	}

	// Create managers
	flowManager := NewDefaultFlowManager(tenantID, helper2.NewFlowCanonicalizer())
	deviceManager := NewDefaultDeviceManager(tenantID, initialDeviceCounter)
	serviceManager := NewDefaultServiceManager(tenantID)

	parser := &GopacketParser{
		PcapFile:           pcapFile,
		TenantID:           tenantID,
		flowManager:        flowManager,
		deviceManager:      deviceManager,
		serviceManager:     serviceManager,
		dnsQueries:         make(map[string]*DNSQuery),
		ssdpQueries:        make(map[string]*SSDPQuery),
		httpRingBuffer:     helper2.NewRingBuffer[*liblayers.HTTP](100), // Adjust size as needed
		protocolUsageStats: make([]*model2.ProtocolUsageStats, 0),       // Collect stats for deferred writing
		repo:               repo,
		industrialParser:   NewIndustrialProtocolParser(),
	}

	// Import existing devices from repository into manager
	if err == nil {
		for _, device := range devices {
			deviceKey := device.AddressType + ":" + device.Address
			// Directly insert into manager's internal map
			// This is a temporary workaround; ideally managers should handle loading
			if defaultMgr, ok := parser.deviceManager.(*DefaultDeviceManager); ok {
				defaultMgr.devices[deviceKey] = device
			}
		}
	}

	// Import existing DNS queries from repository
	dnsQueries, err := repo.GetDNSQueries(tenantID, nil, nil)
	if err == nil {
		for _, query := range dnsQueries {
			// We need to find the corresponding devices for these DNS queries
			var queryingDeviceIP, answeringDeviceIP string

			// Find querying device
			for _, device := range devices {
				if device.ID == query.QueryingDeviceID {
					queryingDeviceIP = device.Address
					break
				}
			}

			// Find answering device
			for _, device := range devices {
				if device.ID == query.AnsweringDeviceID {
					answeringDeviceIP = device.Address
					break
				}
			}

			if queryingDeviceIP != "" && answeringDeviceIP != "" {
				queryKey := fmt.Sprintf("%s:%s:%s:%s", queryingDeviceIP, answeringDeviceIP, query.QueryName, query.QueryType)

				// Extract questions and answers from QueryResult
				var questions, answers map[string]interface{}
				if query.QueryResult != nil {
					if q, ok := query.QueryResult["questions"].(map[string]interface{}); ok {
						questions = q
					}
					if a, ok := query.QueryResult["answers"].(map[string]interface{}); ok {
						answers = a
					}
				}

				parser.dnsQueries[queryKey] = &DNSQuery{
					QueryingDeviceIP:  queryingDeviceIP,
					AnsweringDeviceIP: answeringDeviceIP,
					QueryName:         query.QueryName,
					QueryType:         query.QueryType,
					Questions:         questions,
					Answers:           answers,
					Timestamp:         query.Timestamp,
				}
			}
		}
	}

	return parser
}

// Helper functions for type conversion
func getString(m map[string]interface{}, key string) string {
	if val, ok := m[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

func getBool(m map[string]interface{}, key string) bool {
	if val, ok := m[key]; ok {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return false
}

func getFloat64(m map[string]interface{}, key string) float64 {
	if val, ok := m[key]; ok {
		if f, ok := val.(float64); ok {
			return f
		}
	}
	return 0.0
}

// Helper methods for enhanced device classification

// calculateDeviceClassificationConfidence calculates confidence score for device classification
func (p *GopacketParser) calculateDeviceClassificationConfidence(device model2.Device, protocols []model2.IndustrialProtocolInfo, flows []model2.Flow) float64 {
	if len(protocols) == 0 {
		return 0.0
	}

	// Calculate average protocol confidence
	totalConfidence := 0.0
	for _, protocol := range protocols {
		totalConfidence += protocol.Confidence
	}
	avgProtocolConfidence := totalConfidence / float64(len(protocols))

	// Factor in number of protocols (more protocols = higher confidence)
	protocolFactor := 1.0
	if len(protocols) > 1 {
		protocolFactor = 1.2
	}
	if len(protocols) > 3 {
		protocolFactor = 1.5
	}

	// Factor in communication patterns (more flows = higher confidence)
	flowFactor := 1.0
	if len(flows) > 5 {
		flowFactor = 1.1
	}
	if len(flows) > 20 {
		flowFactor = 1.3
	}

	// Factor in device identity information
	identityFactor := 1.0
	for _, protocol := range protocols {
		if len(protocol.DeviceIdentity) > 0 {
			identityFactor = 1.2
			break
		}
	}

	confidence := avgProtocolConfidence * protocolFactor * flowFactor * identityFactor

	// Cap at 1.0
	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// serializeCommunicationPatterns converts communication patterns to serializable format
func (p *GopacketParser) serializeCommunicationPatterns(patterns []model2.CommunicationPattern) []map[string]interface{} {
	var serialized []map[string]interface{}
	for _, pattern := range patterns {
		patternMap := map[string]interface{}{
			"source_device":      pattern.SourceDevice,
			"destination_device": pattern.DestinationDevice,
			"protocol":           pattern.Protocol,
			"frequency_ms":       pattern.Frequency.Milliseconds(),
			"data_volume":        pattern.DataVolume,
			"pattern_type":       pattern.PatternType,
			"criticality":        pattern.Criticality,
		}
		serialized = append(serialized, patternMap)
	}
	return serialized
}

// extractProtocolNames extracts protocol names from protocol info list
func (p *GopacketParser) extractProtocolNames(protocols []model2.IndustrialProtocolInfo) []string {
	var names []string
	seen := make(map[string]bool)
	for _, protocol := range protocols {
		if !seen[protocol.Protocol] {
			names = append(names, protocol.Protocol)
			seen[protocol.Protocol] = true
		}
	}
	return names
}

// determinePrimaryProtocol determines the primary protocol based on usage patterns
func (p *GopacketParser) determinePrimaryProtocol(protocols []model2.IndustrialProtocolInfo) string {
	if len(protocols) == 0 {
		return ""
	}

	// Count protocol occurrences and find highest confidence
	protocolCounts := make(map[string]int)
	protocolConfidence := make(map[string]float64)

	for _, protocol := range protocols {
		protocolCounts[protocol.Protocol]++
		if protocol.Confidence > protocolConfidence[protocol.Protocol] {
			protocolConfidence[protocol.Protocol] = protocol.Confidence
		}
	}

	// Find protocol with highest combined score (count * confidence)
	var primaryProtocol string
	var highestScore float64

	for protocol, count := range protocolCounts {
		score := float64(count) * protocolConfidence[protocol]
		if score > highestScore {
			highestScore = score
			primaryProtocol = protocol
		}
	}

	return primaryProtocol
}

// hasRealTimeData checks if any protocol has real-time data
func (p *GopacketParser) hasRealTimeData(protocols []model2.IndustrialProtocolInfo) bool {
	for _, protocol := range protocols {
		if protocol.IsRealTimeData {
			return true
		}
	}
	return false
}

// hasDiscovery checks if any protocol has discovery messages
func (p *GopacketParser) hasDiscovery(protocols []model2.IndustrialProtocolInfo) bool {
	for _, protocol := range protocols {
		if protocol.IsDiscovery {
			return true
		}
	}
	return false
}

// hasConfiguration checks if any protocol has configuration messages
func (p *GopacketParser) hasConfiguration(protocols []model2.IndustrialProtocolInfo) bool {
	for _, protocol := range protocols {
		if protocol.IsConfiguration {
			return true
		}
	}
	return false
}

// updateDNSQuery updates or adds a DNS query to the parser's dnsQueries map
func (p *GopacketParser) updateDNSQuery(dnsQuery DNSQuery) {
	queryingDevice := p.deviceManager.GetDevice(dnsQuery.QueryingDeviceIP, "IP")
	answeringDevice := p.deviceManager.GetDevice(dnsQuery.AnsweringDeviceIP, "IP")
	if queryingDevice == nil {
		addressSubType := GetAddressSubTypeForIP(dnsQuery.QueryingDeviceIP)
		queryingDevice = p.deviceManager.UpsertDevice(dnsQuery.QueryingDeviceIP, "IP", dnsQuery.Timestamp, addressSubType, "", "", false)
	}
	if answeringDevice == nil {
		addressSubType := GetAddressSubTypeForIP(dnsQuery.AnsweringDeviceIP)
		answeringDevice = p.deviceManager.UpsertDevice(dnsQuery.AnsweringDeviceIP, "IP", dnsQuery.Timestamp, addressSubType, "", "", true)
	}

	queryKey := fmt.Sprintf("%d:%d:%s:%s", queryingDevice.ID, answeringDevice.ID, dnsQuery.QueryName, dnsQuery.QueryType)
	if existingQuery, exists := p.dnsQueries[queryKey]; exists {
		// Update existing query - merge questions and answers
		if dnsQuery.Questions != nil {
			if existingQuery.Questions != nil {
				for key, value := range dnsQuery.Questions {
					if existingQuery.Questions[key] == nil {
						existingQuery.Questions[key] = value
					} else {
						// If the key already exists, we can merge or update as needed
						switch v := existingQuery.Questions[key].(type) {
						case []string:
							if newValue, ok := value.([]string); ok {
								existingQuery.Questions[key] = append(v, newValue...)
							}
						default:
							existingQuery.Questions[key] = value // Overwrite with new value
						}
					}
				}
			} else {
				existingQuery.Questions = dnsQuery.Questions
			}
		}
		if len(dnsQuery.Answers) > 0 {
			if len(existingQuery.Answers) > 0 {
				for key, value := range dnsQuery.Answers {
					if existingQuery.Answers[key] == nil {
						existingQuery.Answers[key] = value
					} else {
						// If the key already exists, we can merge or update as needed
						switch v := existingQuery.Answers[key].(type) {
						case []string:
							if newValue, ok := value.([]string); ok {
								existingQuery.Answers[key] = append(v, newValue...)
							}
						case map[string]interface{}:
							if newValue, ok := value.(map[string]interface{}); ok {
								// Merge maps
								for subKey, subValue := range newValue {
									if existingSubValue, exists := v[subKey]; !exists {
										v[subKey] = subValue // Add new key
									} else {
										// If the subkey already exists, we can overwrite or merge as needed
										switch subV := existingSubValue.(type) {
										case []string:
											if newSubValue, ok := subValue.([]string); ok {
												v[subKey] = append(subV, newSubValue...)
											}
										case []uint8:
											v[subKey] = subValue
										default:
											// Append the value if it's not a slice
											if subV.(string) != subValue.(string) && subV.(string) != "" && subValue.(string) != "" && strings.Contains(subV.(string), subValue.(string)) == false {
												v[subKey] = subValue.(string) + "," + subV.(string) // Concatenate
											} else {
												// If they are equal, do nothing
											}
										}
									}
								}
								existingQuery.Answers[key] = v // Update with merged map
							} else {
								existingQuery.Answers[key] = value // Overwrite with new value
							}
						default:
							existingQuery.Answers[key] = value // Overwrite with new value
						}
					}
				}
			} else {
				existingQuery.Answers = dnsQuery.Answers
			}
		}
		existingQuery.Timestamp = dnsQuery.Timestamp
	} else {
		p.dnsQueries[queryKey] = &dnsQuery
	}
}

// updateSSDPQuery updates or adds an SSDP query to the parser's ssdpQueries map
func (p *GopacketParser) updateSSDPQuery(ssdpQuery SSDPQuery, timestamp time.Time) {
	queryingDevice := p.deviceManager.GetDevice(ssdpQuery.QueryingDeviceIP, "IP")
	if queryingDevice == nil {
		addressSubType := GetAddressSubTypeForIP(ssdpQuery.QueryingDeviceIP)
		queryingDevice = p.deviceManager.UpsertDevice(ssdpQuery.QueryingDeviceIP, "IP", timestamp, addressSubType, "", "", false)
	}

	queryKey := fmt.Sprintf("%s:%s", queryingDevice.Address, ssdpQuery.QueryType)
	if existingQuery, exists := p.ssdpQueries[queryKey]; exists {
		// Update existing query
		if ssdpQuery.UserAgent != "" {
			if existingQuery.UserAgent == "" {
				existingQuery.UserAgent = ssdpQuery.UserAgent
			} else if !strings.Contains(existingQuery.UserAgent, ssdpQuery.UserAgent) {
				existingQuery.UserAgent += ", " + ssdpQuery.UserAgent
			}
		}
		if ssdpQuery.ST != "" {
			if existingQuery.ST == "" {
				existingQuery.ST = ssdpQuery.ST
			} else if !strings.Contains(existingQuery.ST, ssdpQuery.ST) {
				existingQuery.ST += ", " + ssdpQuery.ST
			}
		}
	} else {
		p.ssdpQueries[queryKey] = &ssdpQuery
	}
}

// ParseFile processes a PCAP file and extracts network information.
func (p *GopacketParser) ParseFile() error {
	handle, err := pcap.OpenOffline(p.PcapFile)
	if err != nil {
		return fmt.Errorf("failed to open pcap: %w", err)
	}
	defer handle.Close()
	pcapFileName := filepath.Base(p.PcapFile)

	liblayers.InitLayerLLDP()
	liblayers.InitLayerEIGRP()
	liblayers.InitLayerSSDP()
	liblayers.InitLayerMDNS()
	liblayers.InitLayerHTTP()
	liblayers.InitLayerOPCUA()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	// Set DecodeOptions for better performance
	packetSource.DecodeOptions.Lazy = true
	packetSource.DecodeOptions.NoCopy = true
	packetSource.DecodeOptions.SkipDecodeRecovery = true

	packetID := int64(0)

	// Pre-allocate for better performance
	const batchSize = 1000
	//packetBatch := make([]*model.Packet, 0, batchSize)

	// Reusable buffers for string formatting
	var sb strings.Builder

	// Create a buffer channel for batching
	packetChan := make(chan *model2.Packet, batchSize)
	errChan := make(chan error, 1)
	doneChan := make(chan struct{})

	// Start a worker goroutine to process packets in batches
	go func() {
		defer close(doneChan)
		batch := make([]*model2.Packet, 0, batchSize)

		for packet := range packetChan {
			batch = append(batch, packet)

			if len(batch) >= batchSize {
				if err := p.repo.UpsertPackets(batch); err != nil {
					errChan <- fmt.Errorf("failed to upsert packet batch: %w", err)
					return
				}
				// Clear the batch but keep the allocated memory
				batch = batch[:0]
			}
		}

		// Process any remaining packets
		if len(batch) > 0 {
			if err := p.repo.UpsertPackets(batch); err != nil {
				errChan <- fmt.Errorf("failed to upsert final packet batch: %w", err)
			}
		}
	}()

	for packet := range packetSource.Packets() {
		var flags []string
		// Pre-allocate maps with capacity hints
		layersMap := make(map[string]interface{}, 10) // Assume average 10 layers
		protocols := make([]string, 0, 5)             // Assume average 5 protocols

		var (
			srcMAC, dstMAC         string
			srcIP, dstIP           string
			srcPort, dstPort       string
			srcPortNum, dstPortNum uint16
			flowProto              string
		)

		// Ethernet
		if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
			eth := ethLayer.(*layers.Ethernet)
			srcMAC = eth.SrcMAC.String()
			dstMAC = eth.DstMAC.String()
			layersMap["ethernet"] = map[string]interface{}{
				"src_mac":       srcMAC,
				"dst_mac":       dstMAC,
				"ethernet_type": eth.EthernetType.String(),
			}
			protocols = append(protocols, "ethernet")
		}

		// ARP
		if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
			arp := arpLayer.(*layers.ARP)
			srcMAC = net.HardwareAddr(arp.SourceHwAddress).String()
			dstMAC = net.HardwareAddr(arp.DstHwAddress).String()
			srcIP = net.IP(arp.SourceProtAddress).String()
			dstIP = net.IP(arp.DstProtAddress).String()
			flowProto = "arp"
			layersMap["arp"] = map[string]interface{}{
				"src_hw_addr":    srcMAC,
				"dst_hw_addr":    dstMAC,
				"src_ip":         srcIP,
				"dst_ip":         dstIP,
				"hw_addr_size":   arp.HwAddressSize,
				"prot_addr_size": arp.ProtAddressSize,
				"operation":      arp.Operation,
			}

			if arp.Operation == layers.ARPRequest {
				continue // Skip ARP requests
			}

			protocols = append(protocols, "arp")
		}

		// IPv4
		if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
			ip4 := ip4Layer.(*layers.IPv4)
			srcIP = ip4.SrcIP.String()
			dstIP = ip4.DstIP.String()
			layersMap["ip"] = map[string]interface{}{
				"src_ip":   srcIP,
				"dst_ip":   dstIP,
				"protocol": ip4.Protocol.String(),
				"ttl":      ip4.TTL,
			}
			protocols = append(protocols, "ipv4")
		}

		// IPv6
		if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
			ip6 := ip6Layer.(*layers.IPv6)
			srcIP = ip6.SrcIP.String()
			dstIP = ip6.DstIP.String()
			layersMap["ipv6"] = map[string]interface{}{
				"src_ip":      srcIP,
				"dst_ip":      dstIP,
				"next_header": ip6.NextHeader.String(),
				"hop_limit":   ip6.HopLimit,
			}
			protocols = append(protocols, "ipv6")
		}

		// ICMP
		if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
			icmp := icmpLayer.(*layers.ICMPv4)
			flowProto = "icmp"
			typeCode := icmp.TypeCode.String()
			layersMap["icmp"] = map[string]interface{}{
				"typeCode": typeCode,
				"checksum": icmp.Checksum,
			}
			if strings.Contains(typeCode, "DestinationUnreachable") {
				// Skip packets that are ICMP Destination Unreachable
				continue
			}

			protocols = append(protocols, "icmp")
		}

		// ICMPv6
		if icmp6Layer := packet.Layer(layers.LayerTypeICMPv6); icmp6Layer != nil {
			icmp6 := icmp6Layer.(*layers.ICMPv6)
			flowProto = "icmpv6"
			layersMap["icmpv6"] = map[string]interface{}{
				"type_code": icmp6.TypeCode.String(),
				"checksum":  icmp6.Checksum,
			}
			protocols = append(protocols, "icmpv6")

			// TODO: if type_code is Router Advertisement <- src is router
		}

		// TCP
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp := tcpLayer.(*layers.TCP)
			srcPortNum = uint16(tcp.SrcPort)
			dstPortNum = uint16(tcp.DstPort)

			// Use pre-allocated buffer for string conversion instead of fmt.Sprintf
			sb.Reset()
			sb.WriteString(strconv.FormatUint(uint64(srcPortNum), 10))
			srcPort = sb.String()

			sb.Reset()
			sb.WriteString(strconv.FormatUint(uint64(dstPortNum), 10))
			dstPort = sb.String()

			flowProto = "tcp"
			layersMap["tcp"] = map[string]interface{}{
				"src_port": tcp.SrcPort.String(),
				"dst_port": tcp.DstPort.String(),
				"seq":      tcp.Seq,
				"ack":      tcp.Ack,
				"flags": map[string]bool{
					"syn": tcp.SYN,
					"ack": tcp.ACK,
					"fin": tcp.FIN,
					"rst": tcp.RST,
					"psh": tcp.PSH,
					"urg": tcp.URG,
					"ece": tcp.ECE,
					"cwr": tcp.CWR,
				},
			}
			protocols = append(protocols, "tcp")

			flags = append(flags, tcpFlagsToStrings(tcp))

			serviceUpdated := false

			// Try to detect HTTP on any TCP port if not already detected
			if packet.Layer(liblayers.LayerTypeHTTP) == nil && len(tcp.Payload) > 0 {
				httpLayer := &liblayers.HTTP{}
				if err = httpLayer.DecodeFromBytes(tcp.Payload, nil); err == nil {
					// Successfully decoded as HTTP, add to packet layers
					flowProto = "http"
					httpData := map[string]interface{}{
						"is_request":    httpLayer.IsRequest,
						"version":       string(httpLayer.Version),
						"headers":       httpLayer.Headers,
						"body":          string(httpLayer.Body),
						"content_type":  httpLayer.ContentType,
						"user_agent":    httpLayer.UserAgent,
						"host":          httpLayer.Host,
						"connection":    httpLayer.Connection,
						"cookies":       httpLayer.Cookies,
						"is_keep_alive": httpLayer.IsKeepAlive(),
						"is_chunked":    httpLayer.IsChunked(),
					}

					if httpLayer.IsRequest {
						httpData["method"] = string(httpLayer.Method)
						httpData["request_uri"] = httpLayer.RequestURI
						httpData["query_params"] = httpLayer.QueryParams
						if httpLayer.URL != nil {
							httpData["parsed_url"] = map[string]interface{}{
								"scheme":   httpLayer.URL.Scheme,
								"host":     httpLayer.URL.Host,
								"path":     httpLayer.URL.Path,
								"query":    httpLayer.URL.RawQuery,
								"fragment": httpLayer.URL.Fragment,
							}
						}
						httpData["is_proxy_req"] = httpLayer.IsProxyRequest()
						httpData["is_msccm_req"] = httpLayer.IsMSCCMPost()

						httpLayer.Identifier = srcIP + ":" + srcPort + " -> " + dstIP + ":" + dstPort
						p.httpRingBuffer.AddNonDuplicate(httpLayer, liblayers.IsEqualDeep) // Add to HTTP ring buffer

						// if method is CCM_POST, the destination is the MSCCM server
						if httpLayer.IsMSCCMPost() {
							// Set the device as a MSCCM server
							additionalDataMap := make(map[string]string)
							additionalDataMap["is_msccm_server"] = "true"
							additionalDataJSON, err := json.Marshal(additionalDataMap)
							if err != nil {
								return fmt.Errorf("failed to marshal additional data: %w", err)
							}
							_ = p.deviceManager.UpsertDevice(dstIP, "IP", packet.Metadata().Timestamp, "", "", string(additionalDataJSON), true)
						}

						if httpLayer.IsUpnpReqest() {
							// Set the device as a UPnP server
							additionalDataMap := make(map[string]string)
							additionalDataMap["is_upnp_host"] = "true"
							additionalDataJSON, err := json.Marshal(additionalDataMap)
							if err != nil {
								return fmt.Errorf("failed to marshal additional data: %w", err)
							}
							_ = p.deviceManager.UpsertDevice(dstIP, "IP", packet.Metadata().Timestamp, "", "", string(additionalDataJSON), true)
						}

						if httpLayer.IsUpnpResponse() {
							// Set the device as a UPnP server
							additionalDataMap := make(map[string]string)
							additionalDataMap["is_upnp_host"] = "true"
							additionalDataJSON, err := json.Marshal(additionalDataMap)
							if err != nil {
								return fmt.Errorf("failed to marshal additional data: %w", err)
							}
							_ = p.deviceManager.UpsertDevice(srcIP, "IP", packet.Metadata().Timestamp, "", "", string(additionalDataJSON), false)
						}

						if httpLayer.IsWindowsRequest() {
							// Set the device as a Windows host
							additionalDataMap := make(map[string]string)
							additionalDataMap["is_windows_host"] = "true"
							additionalDataJSON, err := json.Marshal(additionalDataMap)
							if err != nil {
								return fmt.Errorf("failed to marshal additional data: %w", err)
							}
							_ = p.deviceManager.UpsertDevice(srcIP, "IP", packet.Metadata().Timestamp, "", "", string(additionalDataJSON), false)
						}

						// Update the service for HTTP request
						timestamp := packet.Metadata().Timestamp
						p.serviceManager.UpdateService(dstIP, int(dstPortNum), "http", "", timestamp, nil)
						serviceUpdated = true
					} else { // IsResponse
						var request *liblayers.HTTP
						var index int
						for _, httpL := range p.httpRingBuffer.GetAllLIFO() {
							if httpL.Identifier == dstIP+":"+dstPort+" -> "+srcIP+":"+srcPort {
								httpData["request"] = httpL // Link to the request if available
								request = httpL
								break
							}
							index++
						}
						//fmt.Printf("found at index %d\n", index) TODO: refactor to log debug output

						if httpLayer.StatusCode >= 200 && httpLayer.StatusCode < 300 {
							httpData["status_code"] = httpLayer.StatusCode
							httpData["status_msg"] = httpLayer.StatusMsg
							httpData["is_proxy_discovery_resp"] = httpLayer.IsProxyDiscoveryResponse(request)

							timestamp := packet.Metadata().Timestamp
							if srcPort != "" /*&& (srcPortNum == 80 || srcPortNum == 443)*/ {
								if port, err := strconv.Atoi(srcPort); err == nil {
									p.serviceManager.UpdateService(srcIP, port, "http", "", timestamp, nil)
									serviceUpdated = true
								}
							}
						} else { // no valid HTTP response
							// check if request was the first HTTP request to this server
							if port, err := strconv.Atoi(srcPort); err == nil {
								service := p.serviceManager.GetService(srcIP, port, "http")
								if service != nil && service.FirstSeen.Equal(service.LastSeen) {
									// This means this is the first HTTP request to this server
									// Note: ServiceManager doesn't support deletion, skip this edge case
								}
							}
						}
					}

					if httpLayer.ContentLength > 0 {
						httpData["content_length"] = httpLayer.ContentLength
					}

					if len(httpLayer.TransferEncoding) > 0 {
						httpData["transfer_encoding"] = httpLayer.TransferEncoding
					}

					layersMap["http"] = httpData
					protocols = append(protocols, "http")
				}

				// Analyze TLS layer
				if tlsLayer := packet.Layer(liblayers.LayerTypeTLS); tlsLayer != nil {
					fmt.Printf("TLS Layer found: %+v\n", tlsLayer)
				} else if tlsLayer == nil && len(tcp.Payload) > 5 && httpLayer.Version == "" {
					tls := &liblayers.TLS{}
					if err = tls.DecodeFromBytes(tcp.Payload, nil); err == nil {
						for _, handshake := range tls.Handshake {
							if handshake.Type == liblayers.TLSHandshakeTypeClientHello && handshake.ClientHello != nil {
								servernames := ""
								alpnProtocols := ""
								if handshake.ClientHello.SNI != nil && handshake.ClientHello.SNI.ServerNames != nil {
									for _, serverName := range handshake.ClientHello.SNI.ServerNames {
										servernames += serverName + ","
									}
									if len(servernames) > 0 {
										servernames = strings.TrimSuffix(servernames, ",")
									}
								}
								if handshake.ClientHello.ALPN != nil && len(handshake.ClientHello.ALPN.Protocols) > 0 {
									for _, protocol := range handshake.ClientHello.ALPN.Protocols {
										alpnProtocols += protocol + ","
									}
									if len(alpnProtocols) > 0 {
										alpnProtocols = strings.TrimSuffix(alpnProtocols, ",")
									}
								}
								layersMap["tls"] = map[string]interface{}{
									"version":        handshake.ClientHello.Version.String(),
									"ciphersuites":   handshake.ClientHello.CipherSuites,
									"extensions":     handshake.ClientHello.Extensions,
									"servername":     servernames,
									"alpn_protocols": alpnProtocols,
									"session_id":     handshake.ClientHello.SessionID,
									"compression":    handshake.ClientHello.CompressionMethods,
									"random":         handshake.ClientHello.Random,
								}
								protocols = append(protocols, "tls")
							}
						}
					}
				}
			}

			// Update service for TCP - use a direct call to avoid string concatenation
			timestamp := packet.Metadata().Timestamp
			if !serviceUpdated {
				p.serviceManager.UpdateService(srcIP, int(srcPortNum), "tcp", "", timestamp, nil)
			}
		}

		// UDP
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp := udpLayer.(*layers.UDP)
			srcPortNum = uint16(udp.SrcPort)
			dstPortNum = uint16(udp.DstPort)

			// Use pre-allocated buffer for string conversion
			sb.Reset()
			sb.WriteString(strconv.FormatUint(uint64(srcPortNum), 10))
			srcPort = sb.String()

			sb.Reset()
			sb.WriteString(strconv.FormatUint(uint64(dstPortNum), 10))
			dstPort = sb.String()

			// Default UDP protocol, but detect special cases (e.g., RDP over UDP)
			detectedProto := "udp"
			// RDP (Remote Desktop) commonly uses TCP/3389; some RDP implementations also use UDP on 3389
			if srcPortNum == 3389 || dstPortNum == 3389 {
				detectedProto = "rdpudp"
			}

			flowProto = detectedProto
			layersMap["udp"] = map[string]interface{}{
				"src_port": udp.SrcPort.String(),
				"dst_port": udp.DstPort.String(),
			}
			protocols = append(protocols, detectedProto)
			// Update service for UDP (use detected protocol)
			timestamp := packet.Metadata().Timestamp
			p.serviceManager.UpdateService(srcIP, int(srcPortNum), detectedProto, "", timestamp, nil)
		}

		// DNS
		if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
			dns := dnsLayer.(*layers.DNS)

			if dns.ResponseCode != layers.DNSResponseCodeNoErr || len(dns.Answers) == 0 {
				// Skip DNS packets with errors
				continue
			}

			flowProto = "dns"
			layersMap["dns"] = map[string]interface{}{
				"qr":          dns.QR,
				"opcode":      dns.OpCode,
				"aa":          dns.AA,
				"tc":          dns.TC,
				"rd":          dns.RD,
				"ra":          dns.RA,
				"z":           dns.Z,
				"qdcount":     dns.QDCount,
				"ancount":     dns.ANCount,
				"nscount":     dns.NSCount,
				"arcount":     dns.ARCount,
				"questions":   dns.Questions,
				"answers":     dns.Answers,
				"authorities": dns.Authorities,
				"additionals": dns.Additionals,
			}
			protocols = append(protocols, "dns")
			// Update service for DNS
			dnsQuery := DNSQuery{
				QueryingDeviceIP:  srcIP,
				AnsweringDeviceIP: dstIP,
				Questions:         make(map[string]interface{}),
				Answers:           make(map[string]interface{}),
				Timestamp:         packet.Metadata().Timestamp,
			}
			for _, question := range dns.Questions {
				dnsQuery.QueryName = string(question.Name)
				dnsQuery.QueryType = question.Type.String()
				// Store the query result in a map
				dnsQuery.Questions[string(question.Name)] = map[string]interface{}{
					"type":  question.Type.String(),
					"class": question.Class.String(),
				}
			}

			for _, answer := range dns.Answers {
				switch answer.Type {
				case layers.DNSTypeA:
					dnsQuery.Answers[string(answer.Name)] = map[string]interface{}{
						"type":  answer.Type.String(),
						"class": answer.Class.String(),
						"ip":    answer.IP.String(),
					}
				case layers.DNSTypeAAAA:
					dnsQuery.Answers[string(answer.Name)] = map[string]interface{}{
						"type":  answer.Type.String(),
						"class": answer.Class.String(),
						"ip":    answer.IP.String(),
					}
				case layers.DNSTypeCNAME:
					dnsQuery.Answers[string(answer.Name)] = map[string]interface{}{
						"type":  answer.Type.String(),
						"class": answer.Class.String(),
						"cname": string(answer.CNAME),
					}
				case layers.DNSTypeMX:
					dnsQuery.Answers[string(answer.Name)] = map[string]interface{}{
						"type":       answer.Type.String(),
						"class":      answer.Class.String(),
						"preference": answer.MX.Preference,
					}
				case layers.DNSTypeTXT:
					dnsQuery.Answers[string(answer.Name)] = map[string]interface{}{
						"type":  answer.Type.String(),
						"class": answer.Class.String(),
						"txt":   answer.TXT,
					}
				default:
					// Handle other types as needed
					dnsQuery.Answers[string(answer.Name)] = map[string]interface{}{
						"type":  answer.Type.String(),
						"class": answer.Class.String(),
						"data":  answer.Data,
					}
				}
			}
			p.updateDNSQuery(dnsQuery)
		}

		// CISCO EIGRP
		if eigrpLayer := packet.Layer(liblayers.LayerTypeEIGRP); eigrpLayer != nil {
			eigrp := eigrpLayer.(*liblayers.EIGRP)

			flowProto = "eigrp"
			layersMap["eigrp"] = map[string]interface{}{
				"version":           eigrp.Version,
				"opcode":            eigrp.Opcode,
				"as":                eigrp.AS,
				"seq":               eigrp.Sequence,
				"ack":               eigrp.Ack,
				"virtual_router_id": eigrp.VirtualRouterID,
				"parameters":        eigrp.Parameters,
			}
			protocols = append(protocols, "eigrp")
		}

		// LLC
		if llcLayer := packet.Layer(layers.LayerTypeLLC); llcLayer != nil {
			llc := llcLayer.(*layers.LLC)

			flowProto = "llc"
			layersMap["llc"] = map[string]interface{}{
				"dsap":    llc.DSAP,
				"ssap":    llc.SSAP,
				"control": llc.Control,
			}
			protocols = append(protocols, "llc")
		}

		// SNAP
		if snapLayer := packet.Layer(layers.LayerTypeSNAP); snapLayer != nil {
			snap := snapLayer.(*layers.SNAP)

			flowProto = "snap"
			layersMap["snap"] = map[string]interface{}{
				"oui":  snap.OrganizationalCode,
				"type": snap.Type,
			}
			protocols = append(protocols, "snap")
		}

		// DHCPv4
		if dhcpv4Layer := packet.Layer(layers.LayerTypeDHCPv4); dhcpv4Layer != nil {
			dhcpv4 := dhcpv4Layer.(*layers.DHCPv4)

			flowProto = "dhcpv4"
			layersMap["dhcpv4"] = map[string]interface{}{
				"operations":     dhcpv4.Operation.String(),
				"type":           dhcpv4.HardwareType.String(),
				"server_name":    dhcpv4.ServerName,
				"client_hw_addr": dhcpv4.ClientHWAddr.String(),
				"client_ip":      dhcpv4.ClientIP.String(),
				"your_ip":        dhcpv4.YourClientIP.String(),
				"server_ip":      dhcpv4.NextServerIP.String(),
				"relay_ip":       dhcpv4.RelayAgentIP.String(),
				"options":        dhcpv4.Options,
			}
			protocols = append(protocols, "dhcpv4")

			// If request is a Reply, we can extract more information about the network and its servers
			if dhcpv4.Operation == layers.DHCPOpReply {
				serverInfo := make(map[string]interface{})
				for _, option := range dhcpv4.Options {
					dataLen := len(option.Data)
					switch option.Type {
					case layers.DHCPOptServerID:
						// DHCP server IP
						if dataLen == 4 {
							serverInfo["server_ip"] = net.IP(option.Data).String()
						}
					case layers.DHCPOptSubnetMask:
						// Subnet mask
						if dataLen == 4 {
							serverInfo["subnet_mask"] = net.IP(option.Data).String()
						}
					case layers.DHCPOptRouter:
						// Routers (can be multiple)
						var routers []string
						for i := 0; i+3 < dataLen; i += 4 {
							routers = append(routers, net.IP(option.Data[i:i+4]).String())
						}
						serverInfo["routers"] = routers
					case layers.DHCPOptDNS:
						// DNS servers (can be multiple)
						var dnsServers []string
						for i := 0; i+3 < dataLen; i += 4 {
							dnsServers = append(dnsServers, net.IP(option.Data[i:i+4]).String())
						}
						serverInfo["dns_servers"] = dnsServers
					case layers.DHCPOptDomainName:
						// Domain name
						serverInfo["domain_name"] = strings.TrimRight(string(option.Data), "\x00")
					}
				}
				layersMap["dhcpv4_server_info"] = serverInfo
			}

		}

		// DHCPv6
		if dhcpv6Layer := packet.Layer(layers.LayerTypeDHCPv6); dhcpv6Layer != nil {
			dhcpv6 := dhcpv6Layer.(*layers.DHCPv6)

			flowProto = "dhcpv6"
			layersMap["dhcpv6"] = map[string]interface{}{
				"message_type":   dhcpv6.MsgType.String(),
				"hop_count":      dhcpv6.HopCount,
				"link_address":   dhcpv6.LinkAddr.String(),
				"peer_address":   dhcpv6.PeerAddr.String(),
				"transaction_id": fmt.Sprintf("%x", dhcpv6.TransactionID),
				"options":        dhcpv6.Options,
			}
			protocols = append(protocols, "dhcpv6")
		}

		// LLD
		if lldLayer := packet.Layer(layers.LayerTypeLinkLayerDiscovery); lldLayer != nil {
			lld := lldLayer.(*layers.LinkLayerDiscovery)

			flowProto = "lld"
			layersMap["lld"] = map[string]interface{}{
				"chassis_id": lld.ChassisID,
				"port_id":    lld.PortID,
				"ttl":        lld.TTL,
				"values":     lld.Values,
			}
			protocols = append(protocols, "lld")
		}

		// SSDP
		if ssdpLayer := packet.Layer(liblayers.LayerTypeSSDP); ssdpLayer != nil {
			ssdp := ssdpLayer.(*liblayers.SSDP)

			flowProto = "ssdp"
			ssdpData := map[string]interface{}{
				"method":      ssdp.Method,
				"request_uri": ssdp.RequestURI,
				"version":     ssdp.Version,
				"is_response": ssdp.IsResponse,
				"headers":     ssdp.Headers,
			}

			if ssdp.IsResponse {
				ssdpData["status_code"] = ssdp.StatusCode
				ssdpData["status_msg"] = ssdp.StatusMsg
			}

			// Add specific SSDP attributes for better analysis
			if location, exists := ssdp.GetHeader("LOCATION"); exists {
				ssdpData["location"] = location
			}
			if nt, exists := ssdp.GetHeader("NT"); exists {
				ssdpData["notification_type"] = nt
			}
			if nts, exists := ssdp.GetHeader("NTS"); exists {
				ssdpData["notification_subtype"] = nts
				ssdpData["is_alive"] = ssdp.IsAlive()
				ssdpData["is_byebye"] = ssdp.IsByeBye()
			}
			if usn, exists := ssdp.GetHeader("USN"); exists {
				ssdpData["unique_service_name"] = usn
			}
			if server, exists := ssdp.GetHeader("SERVER"); exists {
				ssdpData["server"] = server
			}
			if cacheControl, exists := ssdp.GetHeader("CACHE-CONTROL"); exists {
				ssdpData["cache_control"] = cacheControl
			}

			ssdpData["is_search"] = ssdp.IsSearch()
			ssdpData["is_notify"] = ssdp.IsNotify()

			layersMap["ssdp"] = ssdpData
			protocols = append(protocols, "ssdp")

			// Update service for SSDP (typically port 1900)
			timestamp := packet.Metadata().Timestamp
			var ssdpQuery SSDPQuery
			if ssdp.IsResponse {
				ssdpQuery = SSDPQuery{
					QueryingDeviceIP: srcIP,
					QueryType:        ssdp.Method,
					ST:               ssdp.Headers["NT"],
					UserAgent:        ssdp.Headers["Server"],
					Timestamp:        timestamp,
				}
			} else {
				ssdpQuery = SSDPQuery{
					QueryingDeviceIP: srcIP,
					QueryType:        ssdp.Method,
					ST:               ssdp.Headers["ST"],
					UserAgent:        ssdp.Headers["USER-AGENT"],
					Timestamp:        timestamp,
				}
			}
			p.updateSSDPQuery(ssdpQuery, timestamp)
		}

		// MDNS
		if mdnsLayer := packet.Layer(liblayers.LayerTypeMDNS); mdnsLayer != nil {
			mdns := mdnsLayer.(*liblayers.MDNS)

			flowProto = "mdns"
			mdnsData := map[string]interface{}{
				"id":            mdns.ID,
				"qr":            mdns.QR,
				"opcode":        mdns.OpCode,
				"aa":            mdns.AA,
				"tc":            mdns.TC,
				"rd":            mdns.RD,
				"ra":            mdns.RA,
				"z":             mdns.Z,
				"response_code": mdns.ResponseCode,
				"qd_count":      mdns.QDCount,
				"an_count":      mdns.ANCount,
				"ns_count":      mdns.NSCount,
				"ar_count":      mdns.ARCount,
				"is_query":      mdns.IsQuery(),
				"is_response":   mdns.IsResponse(),
			}

			// Parse questions
			var questions []map[string]interface{}
			for _, question := range mdns.Questions {
				questionData := map[string]interface{}{
					"name":             string(question.Name),
					"type":             question.Type.String(),
					"class":            question.Class.String(),
					"unicast_response": question.UnicastResponse,
				}

				// Extract service type for service discovery analysis
				if serviceType := question.GetServiceType(); serviceType != "" {
					questionData["service_type"] = serviceType
				}

				questions = append(questions, questionData)
			}
			mdnsData["questions"] = questions

			// Parse answers
			var answers []map[string]interface{}
			for _, answer := range mdns.Answers {
				answerData := map[string]interface{}{
					"name":        string(answer.Name),
					"type":        answer.Type.String(),
					"class":       answer.Class.String(),
					"cache_flush": answer.CacheFlush,
					"ttl":         answer.TTL,
					"data_length": answer.DataLength,
				}

				// Parse specific record types
				switch answer.Type {
				case layers.DNSTypeA:
					if answer.IP != nil {
						answerData["ip"] = answer.IP.String()
						err = p.AssociateDNSNameToIP(answerData["ip"].(string), answerData["name"].(string))
						if err != nil {
							log.Error().Msg("Failed to associate ip with DNS name")
						}
					}
				case layers.DNSTypeAAAA:
					if answer.IP != nil {
						answerData["ip"] = answer.IP.String()
						err = p.AssociateDNSNameToIP(answerData["ip"].(string), answerData["name"].(string))
						if err != nil {
							log.Error().Msg("Failed to associate ip with DNS name")
						}
					}
				case layers.DNSTypePTR:
					if answer.PTR != nil {
						answerData["ptr"] = string(answer.PTR)
					}
				case layers.DNSTypeTXT:
					if answer.TXT != nil {
						var txtRecords []string
						for _, txt := range answer.TXT {
							txtRecords = append(txtRecords, string(txt))
						}
						answerData["txt"] = txtRecords
					}
				case layers.DNSTypeSRV:
					answerData["srv"] = map[string]interface{}{
						"priority": answer.SRV.Priority,
						"weight":   answer.SRV.Weight,
						"port":     answer.SRV.Port,
						"target":   string(answer.SRV.Name),
					}
				case layers.DNSTypeCNAME:
					if answer.CNAME != nil {
						answerData["cname"] = string(answer.CNAME)
					}
				case layers.DNSTypeMX:
					answerData["mx"] = map[string]interface{}{
						"preference": answer.MX.Preference,
						"name":       string(answer.MX.Name),
					}
				default:
					if answer.Data != nil {
						answerData["data"] = answer.Data
					}
				}

				answers = append(answers, answerData)
			}
			mdnsData["answers"] = answers

			// Parse authorities
			var authorities []map[string]interface{}
			for _, auth := range mdns.Authorities {
				authData := map[string]interface{}{
					"name":        string(auth.Name),
					"type":        auth.Type.String(),
					"class":       auth.Class.String(),
					"cache_flush": auth.CacheFlush,
					"ttl":         auth.TTL,
					"data_length": auth.DataLength,
				}
				if auth.Data != nil {
					authData["data"] = auth.Data
				}
				authorities = append(authorities, authData)
			}
			mdnsData["authorities"] = authorities

			// Parse additionals
			var additionals []map[string]interface{}
			for _, add := range mdns.Additionals {
				addData := map[string]interface{}{
					"name":        string(add.Name),
					"type":        add.Type.String(),
					"class":       add.Class.String(),
					"cache_flush": add.CacheFlush,
					"ttl":         add.TTL,
					"data_length": add.DataLength,
				}
				if add.Data != nil {
					addData["data"] = add.Data
				}
				additionals = append(additionals, addData)
			}
			mdnsData["additionals"] = additionals

			layersMap["mdns"] = mdnsData
			protocols = append(protocols, "mdns")

			// Update service for mDNS (port 5353)
			timestamp := packet.Metadata().Timestamp
			p.serviceManager.UpdateService(srcIP, 5353, "mdns", "", timestamp, nil)
			// Process mDNS for service discovery
			if mdns.IsResponse() {
				for _, answer := range mdns.Answers {
					if answer.Type == layers.DNSTypeSRV {
						// Register discovered service
						if answer.SRV.Port > 0 {
							p.serviceManager.UpdateService(srcIP, int(answer.SRV.Port), "discovered", "", timestamp, nil)
						}
					}
				}
			}
		}

		timestamp := packet.Metadata().Timestamp
		length := len(packet.Data())
		// Compute payload hash
		var payloadHash string
		if data := packet.Data(); len(data) > 0 {
			importSha := sha256.Sum256(data)
			payloadHash = hex.EncodeToString(importSha[:])
		}
		// Extract TTL/HopLimit if available
		ttl := 0
		if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
			if ip4, ok := ipv4Layer.(*layers.IPv4); ok {
				ttl = int(ip4.TTL)
			}
		} else if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
			if ip6, ok := ipv6Layer.(*layers.IPv6); ok {
				ttl = int(ip6.HopLimit)
			}
		}
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			if tcp, ok := tcpLayer.(*layers.TCP); ok {
				length = len(tcp.Payload)
			}
		}
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			if udp, ok := udpLayer.(*layers.UDP); ok {
				length = len(udp.Payload)
			}
		}
		modelPacket := &model2.Packet{
			ID:          packetID,
			TenantID:    p.TenantID,
			SrcIP:       net.ParseIP(srcIP),
			DstIP:       net.ParseIP(dstIP),
			SrcPort:     int(srcPortNum),
			DstPort:     int(dstPortNum),
			Protocol:    flowProto,
			Flags:       strings.Join(flags, ","),
			Timestamp:   timestamp,
			Length:      length,
			PayloadHash: payloadHash,
			TTL:         ttl,
			CaptureFile: pcapFileName,
			Layers:      layersMap,
			Protocols:   protocols,
		}

		// Send the packet to the batch processing goroutine
		packetChan <- modelPacket

		// Device extraction and storage - optimized with cached values
		// Handle MAC addresses
		if srcMAC != "" && srcIP != "" {
			addressSubType := GetAddressSubTypeForIP(srcIP)
			p.deviceManager.UpsertDevice(srcIP, "IP", timestamp, addressSubType, srcMAC, "", false)
		}
		if dstMAC != "" && dstIP != "" {
			addressSubType := GetAddressSubTypeForIP(dstIP)
			p.deviceManager.UpsertDevice(dstIP, "IP", timestamp, addressSubType, dstMAC, "", true)
		}

		// Industrial protocol parsing and device classification
		// Always attempt industrial protocol parsing for comprehensive analysis
		industrialProtocols, err := p.industrialParser.ParseIndustrialProtocols(packet)
		if err == nil && len(industrialProtocols) > 0 {
			// Update devices with industrial protocol information
			for _, protocolInfo := range industrialProtocols {
				// Update source device with industrial protocol info
				if srcIP != "" {
					p.deviceManager.UpdateDeviceWithIndustrialInfo(srcIP, protocolInfo, false)

					// Collect protocol usage statistics for source device (defer DB write)
					if stats, statsErr := p.industrialParser.CollectProtocolUsageStats(srcIP, []model2.IndustrialProtocolInfo{protocolInfo}); statsErr == nil && stats != nil {
						// Append to deferred stats list instead of writing immediately
						p.protocolUsageStats = append(p.protocolUsageStats, stats)
					}
				}
				// Update destination device with industrial protocol info
				if dstIP != "" {
					p.deviceManager.UpdateDeviceWithIndustrialInfo(dstIP, protocolInfo, true)

					// Collect protocol usage statistics for destination device (defer DB write)
					if stats, statsErr := p.industrialParser.CollectProtocolUsageStats(dstIP, []model2.IndustrialProtocolInfo{protocolInfo}); statsErr == nil && stats != nil {
						// Append to deferred stats list instead of writing immediately
						p.protocolUsageStats = append(p.protocolUsageStats, stats)
					}
				}
			}

			// Add industrial protocol information to layers map
			layersMap["industrial_protocols"] = industrialProtocols

			// Update protocols list with industrial protocol names
			for _, protocolInfo := range industrialProtocols {
				protocols = append(protocols, protocolInfo.Protocol)

				// Update flow protocol if it's an industrial protocol
				if flowProto == "" || flowProto == "tcp" || flowProto == "udp" {
					flowProto = protocolInfo.Protocol
				}
			}
		} else if err != nil {
			// Log industrial protocol parsing errors but continue processing
			fmt.Printf("Warning: Industrial protocol parsing error: %v\n", err)
		}

		// Flow extraction and storage
		if srcIP != "" && dstIP != "" && flowProto != "" {
			var source, destination string

			source = srcIP
			destination = dstIP

			// Always update flow - let FlowManager handle canonicalization
			p.flowManager.UpdateFlow(source, destination, flowProto, srcPort, dstPort, timestamp, length, packetID)
		}

		packetID++
	}

	// Close the channel to signal no more packets
	close(packetChan)

	// Wait for the batch processing to complete
	select {
	case err := <-errChan:
		return err
	case <-doneChan:
		// Processing completed successfully
	}

	// Save all collected data to the repository
	// We can batch these operations too
	const maxBatchSize = 1000
	deviceBatch := make([]*model2.Device, 0, maxBatchSize)
	deviceCount := 0

	for _, dev := range p.deviceManager.GetAllDevices() {
		deviceBatch = append(deviceBatch, dev)
		deviceCount++

		if deviceCount >= maxBatchSize {
			if err = p.repo.UpsertDevices(deviceBatch); err != nil {
				return fmt.Errorf("failed to add device batch: %w", err)
			}
			deviceBatch = deviceBatch[:0]
			deviceCount = 0
		}
	}

	// Add remaining devices
	if deviceCount > 0 {
		if err = p.repo.UpsertDevices(deviceBatch); err != nil {
			return fmt.Errorf("failed to add devices: %w", err)
		}
	}

	// Batch process flows
	flowBatch := make([]*model2.Flow, 0, maxBatchSize)
	flowCount := 0

	for _, flow := range p.flowManager.GetAllFlows() {
		flowBatch = append(flowBatch, flow)
		flowCount++

		if flowCount >= maxBatchSize {
			if err = p.repo.UpsertFlows(flowBatch); err != nil {
				return fmt.Errorf("failed to add flow batch: %w", err)
			}
			flowBatch = flowBatch[:0]
			flowCount = 0
		}
	}

	// Add remaining flows
	if flowCount > 0 {
		if err = p.repo.UpsertFlows(flowBatch); err != nil {
			return fmt.Errorf("failed to add flows: %w", err)
		}
	}

	// Batch process services
	serviceBatch := make([]*model2.Service, 0, maxBatchSize)
	serviceCount := 0

	for _, service := range p.serviceManager.GetAllServices() {
		serviceBatch = append(serviceBatch, service)
		serviceCount++

		if serviceCount >= maxBatchSize {
			if err = p.repo.UpsertServices(serviceBatch); err != nil {
				return fmt.Errorf("failed to add service batch: %w", err)
			}
			serviceBatch = serviceBatch[:0]
			serviceCount = 0
		}
	}

	// Add remaining services
	if serviceCount > 0 {
		if err = p.repo.UpsertServices(serviceBatch); err != nil {
			return fmt.Errorf("failed to add services: %w", err)
		}
	}

	// Save all collected protocol usage statistics in batch (deferred from main loop)
	if len(p.protocolUsageStats) > 0 {
		if err = p.repo.SaveProtocolUsageStatsMultiple(p.protocolUsageStats); err != nil {
			return fmt.Errorf("failed to save protocol usage stats: %w", err)
		}
	}

	dnsQueriesToSave := make([]*model2.DNSQuery, 0, len(p.dnsQueries))

	// Save DNS queries
	for _, dnsQuery := range p.dnsQueries {
		queryingDevice := p.deviceManager.GetDevice(dnsQuery.QueryingDeviceIP, "IP")
		answeringDevice := p.deviceManager.GetDevice(dnsQuery.AnsweringDeviceIP, "IP")
		if queryingDevice == nil {
			err = p.repo.UpsertDevice(&model2.Device{
				Address:           dnsQuery.QueryingDeviceIP,
				AddressType:       "IP",
				FirstSeen:         dnsQuery.Timestamp,
				LastSeen:          dnsQuery.Timestamp,
				AddressSubType:    "IPv4", // Default to IPv4, can be adjusted
				AddressScope:      helper2.GetAddressScope(dnsQuery.QueryingDeviceIP, "IP"),
				MACAddressSet:     model2.NewMACAddressSet(),
				IsOnlyDestination: false,
			})
			if err != nil {
				return fmt.Errorf("failed to add querying device: %w", err)
			}
			queryingDevice, err = p.repo.GetDevice(p.TenantID, dnsQuery.QueryingDeviceIP)
			if err != nil {
				return fmt.Errorf("failed to retrieve querying device: %w", err)
			}
		}
		if answeringDevice == nil {
			err = p.repo.UpsertDevice(&model2.Device{
				Address:           dnsQuery.AnsweringDeviceIP,
				AddressType:       "IP",
				FirstSeen:         dnsQuery.Timestamp,
				LastSeen:          dnsQuery.Timestamp,
				AddressSubType:    "IPv4", // Default to IPv4, can be adjusted
				AddressScope:      helper2.GetAddressScope(dnsQuery.AnsweringDeviceIP, "IP"),
				MACAddressSet:     model2.NewMACAddressSet(),
				IsOnlyDestination: true,
			})
			if err != nil {
				return fmt.Errorf("failed to add answering device: %w", err)
			}
			answeringDevice, err = p.repo.GetDevice(p.TenantID, dnsQuery.AnsweringDeviceIP)
			if err != nil {
				return fmt.Errorf("failed to retrieve answering device: %w", err)
			}
		}

		dnsRecord := &model2.DNSQuery{
			QueryingDeviceID:  queryingDevice.ID,
			AnsweringDeviceID: answeringDevice.ID,
			QueryName:         dnsQuery.QueryName,
			QueryType:         dnsQuery.QueryType,
			QueryResult:       dnsQuery.Answers,
			Timestamp:         dnsQuery.Timestamp,
		}
		dnsQueriesToSave = append(dnsQueriesToSave, dnsRecord)
	}

	if len(dnsQueriesToSave) > 0 {
		err = p.repo.UpsertDNSQueries(dnsQueriesToSave)
		if err != nil {
			return fmt.Errorf("failed to add DNS queries: %w", err)
		}
	}

	// Save SSDP queries
	ssdpQueriesToSave := make([]*model2.SSDPQuery, 0, len(p.ssdpQueries))
	for _, ssdpQuery := range p.ssdpQueries {
		queryingDevice := p.deviceManager.GetDevice(ssdpQuery.QueryingDeviceIP, "IP")

		var additionalDataJSON []byte
		additionalDataMap := make(map[string]string)
		if strings.Contains(ssdpQuery.UserAgent, "Windows") {
			additionalDataMap["is_windows_host"] = "true"
			additionalDataJSON, err = json.Marshal(additionalDataMap)
			if err != nil {
				return fmt.Errorf("failed to marshal additional data: %w", err)
			}
		}
		if strings.Contains(ssdpQuery.UserAgent, "Linux") {
			additionalDataMap["is_linux_host"] = "true"
			additionalDataJSON, err = json.Marshal(additionalDataMap)
			if err != nil {
				return fmt.Errorf("failed to marshal additional data: %w", err)
			}
		}

		if queryingDevice == nil {
			err = p.repo.UpsertDevice(&model2.Device{
				Address:           ssdpQuery.QueryingDeviceIP,
				AddressType:       "IP",
				FirstSeen:         ssdpQuery.Timestamp,
				LastSeen:          ssdpQuery.Timestamp,
				AddressSubType:    "IPv4", // Default to IPv4, can be adjusted
				AddressScope:      helper2.GetAddressScope(ssdpQuery.QueryingDeviceIP, "IP"),
				MACAddressSet:     model2.NewMACAddressSet(),
				IsOnlyDestination: false,
				AdditionalData:    string(additionalDataJSON),
			})
			if err != nil {
				return fmt.Errorf("failed to add querying device for SSDP query: %w", err)
			}
			queryingDevice, err = p.repo.GetDevice(p.TenantID, ssdpQuery.QueryingDeviceIP)
			if err != nil {
				return fmt.Errorf("failed to retrieve querying device for SSDP query: %w", err)
			}
		} else {
			// Update existing device with additional data if needed
			if len(additionalDataMap) > 0 {
				if existingData := queryingDevice.AdditionalData; existingData != "" {
					var existingDataMap map[string]interface{}
					err = json.Unmarshal([]byte(existingData), &existingDataMap)
					if err != nil {
						return fmt.Errorf("failed to unmarshal existing additional data: %w", err)
					}
					for key, value := range additionalDataMap {
						existingDataMap[key] = value
					}
					additionalDataJSON, err = json.Marshal(existingDataMap)
					if err != nil {
						return fmt.Errorf("failed to marshal updated additional data: %w", err)
					}
					queryingDevice.AdditionalData = string(additionalDataJSON)
				} else {
					queryingDevice.AdditionalData = string(additionalDataJSON)
				}
				err = p.repo.UpsertDevice(queryingDevice)
				if err != nil {
					return fmt.Errorf("failed to update querying device for SSDP query: %w", err)
				}
			}
		}
		ssdpRecord := &model2.SSDPQuery{
			QueryingDeviceID: queryingDevice.ID,
			QueryType:        ssdpQuery.QueryType,
			ST:               ssdpQuery.ST,
			UserAgent:        ssdpQuery.UserAgent,
			Timestamp:        ssdpQuery.Timestamp,
		}
		ssdpQueriesToSave = append(ssdpQueriesToSave, ssdpRecord)
	}
	if len(ssdpQueriesToSave) > 0 {
		err = p.repo.UpsertSSDPQueries(ssdpQueriesToSave)
		if err != nil {
			return fmt.Errorf("failed to add SSDP queries: %w", err)
		}
	}

	// Analyze and save communication patterns for industrial devices
	if err = p.analyzeAndSaveCommunicationPatterns(); err != nil {
		// Log error but don't fail the entire parsing process
		fmt.Printf("Warning: Failed to analyze communication patterns: %v\n", err)
	}

	return nil
}

func tcpFlagsToStrings(tcp *layers.TCP) string {
	var flags []string
	if tcp.SYN {
		flags = append(flags, "SYN")
	}
	if tcp.ACK {
		flags = append(flags, "ACK")
	}
	if tcp.FIN {
		flags = append(flags, "FIN")
	}
	if tcp.RST {
		flags = append(flags, "RST")
	}
	if tcp.PSH {
		flags = append(flags, "PSH")
	}
	if tcp.URG {
		flags = append(flags, "URG")
	}
	if tcp.ECE {
		flags = append(flags, "ECE")
	}
	if tcp.CWR {
		flags = append(flags, "CWR")
	}
	return strings.Join(flags, ",")
}

// analyzeAndSaveCommunicationPatterns analyzes communication patterns and saves them to the repository
func (p *GopacketParser) analyzeAndSaveCommunicationPatterns() error {
	// Collect all flows for communication pattern analysis
	var allFlows []model2.Flow
	for _, flow := range p.flowManager.GetAllFlows() {
		allFlows = append(allFlows, *flow)
	}

	if len(allFlows) == 0 {
		return nil // No flows to analyze
	}

	// Analyze communication patterns using the industrial parser
	patterns := p.industrialParser.AnalyzeCommunicationPatterns(allFlows)

	if len(patterns) == 0 {
		return nil // No patterns found
	}

	// Convert patterns to model format and save to repository
	var patternsToSave []*model2.CommunicationPattern
	for _, pattern := range patterns {
		patternsToSave = append(patternsToSave, &pattern)
	}

	// Batch save communication patterns
	const maxPatternBatchSize = 500
	for i := 0; i < len(patternsToSave); i += maxPatternBatchSize {
		end := i + maxPatternBatchSize
		if end > len(patternsToSave) {
			end = len(patternsToSave)
		}

		batch := patternsToSave[i:end]
		if err := p.repo.SaveCommunicationPatterns(batch); err != nil {
			return fmt.Errorf("failed to save communication pattern batch: %w", err)
		}
	}

	return nil
}

func (p *GopacketParser) AssociateDNSNameToIP(ip string, dnsName string) error {
	device := p.deviceManager.GetDevice(ip, "IP")
	if device == nil {
		return fmt.Errorf("device not found for IP %s", ip)
	}

	additionalDataMap := make(map[string]interface{}, 0)
	if len(device.AdditionalData) > 0 {
		err := json.Unmarshal([]byte(device.AdditionalData), &additionalDataMap)
		if err != nil {
			return fmt.Errorf("failed to unmarshal additional data for device %d: %w", device.ID, err)
		}
	}

	// Associate DNS name with the device
	dnsNameMap, ok := additionalDataMap["dnsNames"]
	dnsNameSet := model2.NewSet()
	if !ok {
		dnsNameSet.Add(dnsName)
	} else {
		for _, existingDNSName := range dnsNameMap.([]interface{}) {
			dnsNameSet.Add(existingDNSName.(string))
		}
		dnsNameSet.Add(dnsName)
	}
	additionalDataMap["dnsNames"] = dnsNameSet.List()
	additionalDataJSON, err := json.Marshal(additionalDataMap)
	if err != nil {
		return fmt.Errorf("failed to marshal additional data for device %d: %w", device.ID, err)
	}
	device.AdditionalData = string(additionalDataJSON)

	return nil
}

func GetAddressSubTypeForIP(ip string) string {
	addressSubType := "IPv4"
	if strings.Count(ip, ":") > 1 {
		addressSubType = "IPv6"
	}
	return addressSubType
}

func (p *GopacketParser) saveAllDeviceRelations(devices []*model2.Device, repo repository.Repository, comment string) error {
	for _, dev1 := range devices {
		for _, dev2 := range devices {
			if dev1.ID == dev2.ID {
				continue // Skip self-relation
			}
			relation := &model2.DeviceRelation{
				DeviceID1: dev1.ID,
				DeviceID2: dev2.ID,
				Comment:   comment,
			}
			if err := p.repo.UpsertDeviceRelation(relation); err != nil {
				return fmt.Errorf("failed to add device relation: %w", err)
			}
		}
	}
	return nil
}

var ProtocolColorMap = map[string]string{
	"tcp":        "#1f77b4",
	"udp":        "#ff7f0e",
	"http":       "#2ca02c",
	"https":      "#d62728",
	"dns":        "#9467bd",
	"dhcp":       "#8c564b",
	"eigrp":      "#e377c2",
	"ipv4_eigrp": "#e377c2",
	"ospf":       "#7f7f7f",
	"modbus":     "#bcbd22",
	"ssh":        "#17becf",
	"ftp":        "#aec7e8",
	"arp":        "#98df8a",
	"icmp":       "#c49c94",
	"snmp":       "#ffbb78",
	"ntp":        "#c5b0d5",
	// Color for RDP over UDP flows
	"rdpudp": "#ff69b4",
}
