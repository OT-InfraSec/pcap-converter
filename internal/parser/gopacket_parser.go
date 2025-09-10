package parser

import (
	"encoding/json"
	"fmt"
	helper2 "github.com/InfraSecConsult/pcap-importer-go/lib/helper"
	model2 "github.com/InfraSecConsult/pcap-importer-go/lib/model"
	"net"
	"strconv"
	"strings"
	"time"

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
	// Track devices and their relationships
	devices map[string]*model2.Device
	// Track flows
	flows map[string]*model2.Flow
	// Track services
	services map[string]*model2.Service
	// SSDP queries
	ssdpQueries map[string]*SSDPQuery
	// DNS queries
	dnsQueries    map[string]*DNSQuery
	deviceCounter int64

	httpRingBuffer *helper2.RingBuffer[*liblayers.HTTP]

	repo repository.Repository
}

func NewGopacketParser(pcapFile string, repo repository.Repository) *GopacketParser {
	parser := &GopacketParser{
		PcapFile:       pcapFile,
		devices:        make(map[string]*model2.Device),
		flows:          make(map[string]*model2.Flow),
		services:       make(map[string]*model2.Service),
		dnsQueries:     make(map[string]*DNSQuery),
		ssdpQueries:    make(map[string]*SSDPQuery),
		httpRingBuffer: helper2.NewRingBuffer[*liblayers.HTTP](100), // Adjust size as needed
		repo:           repo,
	}

	// Import existing devices from repository
	devices, err := repo.GetDevices(nil)
	if err == nil {
		for _, device := range devices {
			deviceKey := device.AddressType + ":" + device.Address
			parser.devices[deviceKey] = device
			// Update device counter to be greater than any existing device ID
			if device.ID >= parser.deviceCounter {
				parser.deviceCounter = device.ID + 1
			}
		}
	}

	// Import existing flows from repository
	flows, err := repo.GetFlows(nil)
	if err == nil {
		for _, flow := range flows {
			flowKey := fmt.Sprintf("%s:%s:%s", flow.Source, flow.Destination, flow.Protocol)
			// If this flow has port information, include it in the key
			if flow.SourcePorts.Size() > 0 && flow.DestinationPorts.Size() > 0 {
				srcPorts := flow.SourcePorts.List()
				dstPorts := flow.DestinationPorts.List()
				if len(srcPorts) > 0 && len(dstPorts) > 0 {
					flowKey = fmt.Sprintf("%s:%s:%s:%s:%s", flow.Source, srcPorts[0], flow.Destination, dstPorts[0], flow.Protocol)
				}
			}
			parser.flows[flowKey] = flow
		}
	}

	// Import existing services from repository
	services, err := repo.GetServices(nil)
	if err == nil {
		for _, service := range services {
			serviceKey := fmt.Sprintf("%s:%d:%s", service.IP, service.Port, service.Protocol)
			parser.services[serviceKey] = service
		}
	}

	// Import existing DNS queries from repository
	dnsQueries, err := repo.GetDNSQueries(nil, nil)
	if err == nil {
		for _, query := range dnsQueries {
			// We need to find the corresponding devices for these DNS queries
			var queryingDeviceIP, answeringDeviceIP string

			// Find querying device
			for _, device := range parser.devices {
				if device.ID == query.QueryingDeviceID {
					queryingDeviceIP = device.Address
					break
				}
			}

			// Find answering device
			for _, device := range parser.devices {
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

// upsertDevice updates or creates a device
func (p *GopacketParser) upsertDevice(address string, addressType string, timestamp time.Time, addressSubType string, macAddress string, additionalData string, isDestination bool) *model2.Device {
	devKey := addressType + ":" + address
	dev, exists := p.devices[devKey]
	if !exists {
		macAddressSet := model2.NewMACAddressSet()
		if macAddress != "" {
			macAddressSet.Add(macAddress)
		}
		dev = &model2.Device{
			ID:                p.deviceCounter,
			Address:           address,
			AddressType:       addressType,
			FirstSeen:         timestamp,
			LastSeen:          timestamp,
			AddressSubType:    addressSubType,
			AddressScope:      helper2.GetAddressScope(address, addressType),
			MACAddressSet:     macAddressSet,
			AdditionalData:    additionalData,
			IsOnlyDestination: isDestination,
		}
		p.devices[devKey] = dev
		p.deviceCounter++
	} else {
		if macAddress != "" {
			dev.MACAddressSet.Add(macAddress)
		}
		if additionalData != "" {
			// Merge additional data if it exists
			if dev.AdditionalData != "" {
				var existingData map[string]interface{}
				if err := json.Unmarshal([]byte(dev.AdditionalData), &existingData); err != nil {
					existingData = make(map[string]interface{})
				}
				var newData map[string]interface{}
				if err := json.Unmarshal([]byte(additionalData), &newData); err == nil {
					for k, v := range newData {
						existingData[k] = v
					}
				}
				mergedData, _ := json.Marshal(existingData)
				dev.AdditionalData = string(mergedData)
			} else {
				dev.AdditionalData = additionalData
			}
		}
		if dev.IsOnlyDestination && !isDestination {
			dev.IsOnlyDestination = false
		}
		if timestamp.Before(dev.FirstSeen) {
			dev.FirstSeen = timestamp
		}
		if timestamp.After(dev.LastSeen) {
			dev.LastSeen = timestamp
		}
		p.devices[devKey] = dev
	}
	return dev
}

// updateFlow updates or creates a flow
func (p *GopacketParser) updateFlow(src, dst, protocol string, timestamp time.Time, packetSize int, packetID int64, srcPort, dstPort string) *model2.Flow {
	flowKey := fmt.Sprintf("%s:%s:%s", src, dst, protocol)

	sourcePortsSet := model2.NewSet()
	destinationPortsSet := model2.NewSet()

	if srcPort != "" && dstPort != "" {
		flowKey = fmt.Sprintf("%s:%s:%s:%s:%s", src, srcPort, dst, dstPort, protocol)
		sourcePortsSet.Add(srcPort)
		destinationPortsSet.Add(dstPort)
	}

	flow, exists := p.flows[flowKey]
	if !exists {
		flow = &model2.Flow{
			Source:           src,
			Destination:      dst,
			Protocol:         protocol,
			Packets:          1,
			Bytes:            packetSize,
			FirstSeen:        timestamp,
			LastSeen:         timestamp,
			PacketRefs:       []int64{packetID},
			MinPacketSize:    packetSize,
			MaxPacketSize:    packetSize,
			SourcePorts:      sourcePortsSet,
			DestinationPorts: destinationPortsSet,
		}
		p.flows[flowKey] = flow
	} else {
		flow.Packets++
		flow.Bytes += packetSize
		if timestamp.Before(flow.FirstSeen) {
			flow.FirstSeen = timestamp
		}
		if timestamp.After(flow.LastSeen) {
			flow.LastSeen = timestamp
		}
		flow.PacketRefs = append(flow.PacketRefs, packetID)
		if packetSize < flow.MinPacketSize {
			flow.MinPacketSize = packetSize
		}
		if packetSize > flow.MaxPacketSize {
			flow.MaxPacketSize = packetSize
		}
		if srcPort != "" && dstPort != "" {
			flow.SourcePorts.Add(srcPort)
			flow.DestinationPorts.Add(dstPort)
		} else {
			// If ports are not specified, we still want to keep the flow
			// but without port information
			if flow.SourcePorts == nil {
				flow.SourcePorts = model2.NewSet()
			}
			if flow.DestinationPorts == nil {
				flow.DestinationPorts = model2.NewSet()
			}
		}
	}
	return flow
}

func (p *GopacketParser) updateSSDPQuery(ssdpQuery SSDPQuery, timestamp time.Time) {
	queryingDevice := p.devices["IP:"+ssdpQuery.QueryingDeviceIP]
	if queryingDevice == nil {
		addressSubType := GetAddressSubTypeForIP(ssdpQuery.QueryingDeviceIP)
		queryingDevice = p.upsertDevice(ssdpQuery.QueryingDeviceIP, "IP", timestamp, addressSubType, "", "", false)
	}

	queryKey := fmt.Sprintf("%s:%s", queryingDevice.Address, ssdpQuery.QueryType)
	if existingQuery, exists := p.ssdpQueries[queryKey]; exists {
		// Update existing query
		if ssdpQuery.UserAgent != "" {
			if existingQuery.UserAgent == "" {
				existingQuery.UserAgent = ssdpQuery.UserAgent
			} else {
				// If the user agent already exists, we can append or merge as needed
				if !strings.Contains(existingQuery.UserAgent, ssdpQuery.UserAgent) {
					existingQuery.UserAgent += ", " + ssdpQuery.UserAgent
				}
			}
		}
		if ssdpQuery.ST != "" {
			if existingQuery.ST == "" {
				existingQuery.ST = ssdpQuery.ST
			} else {
				// If the ST already exists, we can append or merge as needed
				if !strings.Contains(existingQuery.ST, ssdpQuery.ST) {
					existingQuery.ST += ", " + ssdpQuery.ST
				}
			}
		}
	} else {
		// Add new query
		p.ssdpQueries[queryKey] = &ssdpQuery
	}
}

// updateService updates or creates a service
func (p *GopacketParser) updateService(ip string, port int, protocol string, timestamp time.Time) *model2.Service {
	serviceKey := p.generateServiceKey(ip, port, protocol)
	service, exists := p.services[serviceKey]
	if !exists {
		service = &model2.Service{
			IP:        ip,
			Port:      port,
			Protocol:  protocol,
			FirstSeen: timestamp,
			LastSeen:  timestamp,
		}
		p.services[serviceKey] = service
	} else {
		if timestamp.Before(service.FirstSeen) {
			service.FirstSeen = timestamp
		}
		if timestamp.After(service.LastSeen) {
			service.LastSeen = timestamp
		}
	}
	return service
}

func (p *GopacketParser) generateServiceKey(ip string, port int, protocol string) string {
	return fmt.Sprintf("%s:%d:%s", ip, port, protocol)
}

func (p *GopacketParser) updateDNSQuery(dnsQuery DNSQuery) {
	queryingDevice := p.devices["IP:"+dnsQuery.QueryingDeviceIP]
	answeringDevice := p.devices["IP:"+dnsQuery.AnsweringDeviceIP]
	if queryingDevice == nil {
		// create new device
		addressSubType := GetAddressSubTypeForIP(dnsQuery.QueryingDeviceIP)
		queryingDevice = p.upsertDevice(dnsQuery.QueryingDeviceIP, "IP", dnsQuery.Timestamp, addressSubType, "", "", false)
	}
	if answeringDevice == nil {
		addressSubType := GetAddressSubTypeForIP(dnsQuery.AnsweringDeviceIP)
		answeringDevice = p.upsertDevice(dnsQuery.AnsweringDeviceIP, "IP", dnsQuery.Timestamp, addressSubType, "", "", true)
	}
	// Create a unique key for the DNS query
	queryKey := fmt.Sprintf("%d:%d:%s:%s", queryingDevice.ID, answeringDevice.ID, dnsQuery.QueryName, dnsQuery.QueryType)
	if existingQuery, exists := p.dnsQueries[queryKey]; exists {
		// Update existing query
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
		// Add new query
		p.dnsQueries[queryKey] = &dnsQuery
	}
}

// ParseFile processes a PCAP file and extracts network information.
func (p *GopacketParser) ParseFile() error {
	handle, err := pcap.OpenOffline(p.PcapFile)
	if err != nil {
		return fmt.Errorf("failed to open pcap: %w", err)
	}
	defer handle.Close()

	liblayers.InitLayerLLDP()
	liblayers.InitLayerEIGRP()
	liblayers.InitLayerSSDP()
	liblayers.InitLayerMDNS()
	liblayers.InitLayerHTTP()

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
		var batch []*model2.Packet

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
		// Pre-allocate maps with capacity hints
		layersMap := make(map[string]interface{}, 10) // Assume average 10 layers
		protocols := make([]string, 0, 5)             // Assume average 5 protocols

		var (
			srcMAC, dstMAC         string
			srcIP, dstIP           string
			srcPort, dstPort       string
			srcPortNum, dstPortNum uint16
			flowProto              string
			isHTTPResponse         bool
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
						isHTTPResponse = true
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
							_ = p.upsertDevice(dstIP, "IP", packet.Metadata().Timestamp, "", "", string(additionalDataJSON), true)
						}

						if httpLayer.IsUpnpReqest() {
							// Set the device as a UPnP server
							additionalDataMap := make(map[string]string)
							additionalDataMap["is_upnp_host"] = "true"
							additionalDataJSON, err := json.Marshal(additionalDataMap)
							if err != nil {
								return fmt.Errorf("failed to marshal additional data: %w", err)
							}
							_ = p.upsertDevice(dstIP, "IP", packet.Metadata().Timestamp, "", "", string(additionalDataJSON), true)
						}

						if httpLayer.IsUpnpResponse() {
							// Set the device as a UPnP server
							additionalDataMap := make(map[string]string)
							additionalDataMap["is_upnp_host"] = "true"
							additionalDataJSON, err := json.Marshal(additionalDataMap)
							if err != nil {
								return fmt.Errorf("failed to marshal additional data: %w", err)
							}
							_ = p.upsertDevice(srcIP, "IP", packet.Metadata().Timestamp, "", "", string(additionalDataJSON), false)
						}

						if httpLayer.IsWindowsRequest() {
							// Set the device as a Windows host
							additionalDataMap := make(map[string]string)
							additionalDataMap["is_windows_host"] = "true"
							additionalDataJSON, err := json.Marshal(additionalDataMap)
							if err != nil {
								return fmt.Errorf("failed to marshal additional data: %w", err)
							}
							_ = p.upsertDevice(srcIP, "IP", packet.Metadata().Timestamp, "", "", string(additionalDataJSON), false)
						}

						// Update the service for HTTP request
						timestamp := packet.Metadata().Timestamp
						p.updateService(dstIP, int(dstPortNum), "http", timestamp)
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
									p.updateService(srcIP, port, "http", timestamp)
								}
							}
						} else { // no valid HTTP response
							// check if request was the first HTTP request to this server
							if port, err := strconv.Atoi(srcPort); err == nil {
								service := p.services[p.generateServiceKey(srcIP, port, "http")]
								if service != nil && service.FirstSeen.Equal(service.LastSeen) {
									// This means this is the first HTTP request to this server and we delete it
									p.services[p.generateServiceKey(srcIP, port, "http")] = nil
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
								isHTTPResponse = true
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
			p.updateService(srcIP, int(srcPortNum), "tcp", timestamp)
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

			flowProto = "udp"
			layersMap["udp"] = map[string]interface{}{
				"src_port": udp.SrcPort.String(),
				"dst_port": udp.DstPort.String(),
			}
			protocols = append(protocols, "udp")
			// Update service for UDP
			timestamp := packet.Metadata().Timestamp
			p.updateService(srcIP, int(srcPortNum), "udp", timestamp)
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
							fmt.Errorf("Failed to associate ip with DNS name")
						}
					}
				case layers.DNSTypeAAAA:
					if answer.IP != nil {
						answerData["ip"] = answer.IP.String()
						err = p.AssociateDNSNameToIP(answerData["ip"].(string), answerData["name"].(string))
						if err != nil {
							fmt.Errorf("Failed to associate ip with DNS name")
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
			p.updateService(srcIP, 5353, "mdns", timestamp)

			// Process mDNS for service discovery
			if mdns.IsResponse() {
				for _, answer := range mdns.Answers {
					if answer.Type == layers.DNSTypeSRV {
						// Register discovered service
						if answer.SRV.Port > 0 {
							p.updateService(srcIP, int(answer.SRV.Port), "discovered", timestamp)
						}
					}
				}
			}
		}

		timestamp := packet.Metadata().Timestamp
		length := len(packet.Data())
		modelPacket := &model2.Packet{
			ID:        packetID,
			Timestamp: timestamp,
			Length:    length,
			Layers:    layersMap,
			Protocols: protocols,
		}

		// Send the packet to the batch processing goroutine
		packetChan <- modelPacket

		// Device extraction and storage - optimized with cached values
		// Handle MAC addresses
		if srcMAC != "" && srcIP != "" {
			addressSubType := GetAddressSubTypeForIP(srcIP)
			p.upsertDevice(srcIP, "IP", timestamp, addressSubType, srcMAC, "", false)
		}
		if dstMAC != "" && dstIP != "" {
			addressSubType := GetAddressSubTypeForIP(dstIP)
			p.upsertDevice(dstIP, "IP", timestamp, addressSubType, dstMAC, "", true)
		}

		// Flow extraction and storage
		if srcIP != "" && dstIP != "" && flowProto != "" {
			var source, destination string

			// For protocols like TCP/UDP that have ports
			/*if srcPort != "" && dstPort != "" {
				// Format source and destination with ports
				if strings.Count(srcIP, ":") > 1 {
					// IPv6 with port
					source = fmt.Sprintf("[%s]:%s", srcIP, srcPort)
				} else {
					// IPv4 with port
					source = fmt.Sprintf("%s:%s", srcIP, srcPort)
				}

				if strings.Count(dstIP, ":") > 1 {
					// IPv6 with port
					destination = fmt.Sprintf("[%s]:%s", dstIP, dstPort)
				} else {
					// IPv4 with port
					destination = fmt.Sprintf("%s:%s", dstIP, dstPort)
				}
			} else {*/
			// For protocols like ICMP, ARP that don't have ports
			source = srcIP
			destination = dstIP
			//}

			if !isHTTPResponse {
				p.updateFlow(source, destination, flowProto, timestamp, length, packetID, srcPort, dstPort)
			}
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

	for _, dev := range p.devices {
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

	for _, flow := range p.flows {
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
		if err := p.repo.UpsertFlows(flowBatch); err != nil {
			return fmt.Errorf("failed to add flows: %w", err)
		}
	}

	// Batch process services
	serviceBatch := make([]*model2.Service, 0, maxBatchSize)
	serviceCount := 0

	for _, service := range p.services {
		serviceBatch = append(serviceBatch, service)
		serviceCount++

		if serviceCount >= maxBatchSize {
			if err := p.repo.UpsertServices(serviceBatch); err != nil {
				return fmt.Errorf("failed to add service batch: %w", err)
			}
			serviceBatch = serviceBatch[:0]
			serviceCount = 0
		}
	}

	// Add remaining services
	if serviceCount > 0 {
		if err := p.repo.UpsertServices(serviceBatch); err != nil {
			return fmt.Errorf("failed to add services: %w", err)
		}
	}

	dnsQueriesToSave := make([]*model2.DNSQuery, 0, len(p.dnsQueries))

	// Save DNS queries
	for _, dnsQuery := range p.dnsQueries {
		queryingDeviceKey := "IP:" + dnsQuery.QueryingDeviceIP
		queryingDevice := p.devices[queryingDeviceKey]
		answeringDeviceKey := "IP:" + dnsQuery.AnsweringDeviceIP
		answeringDevice := p.devices[answeringDeviceKey]
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
			queryingDevice, err = p.repo.GetDevice(dnsQuery.QueryingDeviceIP)
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
			answeringDevice, err = p.repo.GetDevice(dnsQuery.AnsweringDeviceIP)
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
		queryingDeviceKey := "IP:" + ssdpQuery.QueryingDeviceIP
		queryingDevice := p.devices[queryingDeviceKey]

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
			queryingDevice, err = p.repo.GetDevice(ssdpQuery.QueryingDeviceIP)
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

	return nil
}

func (p *GopacketParser) AssociateDNSNameToIP(ip string, dnsName string) error {
	device, ok := p.devices["IP:"+ip]
	if !ok {
		return fmt.Errorf("failed to get device for IP %s", ip)
	}
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
