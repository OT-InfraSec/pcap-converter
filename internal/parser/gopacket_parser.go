package parser

import (
	"fmt"
	"github.com/InfraSecConsult/pcap-importer-go/internal/helper"
	helper2 "github.com/InfraSecConsult/pcap-importer-go/lib/helper"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/InfraSecConsult/pcap-importer-go/internal/model"
	"github.com/InfraSecConsult/pcap-importer-go/internal/repository"

	liblayers "github.com/InfraSecConsult/pcap-importer-go/lib/layers"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

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
	devices map[string]*model.Device
	// Track flows
	flows map[string]*model.Flow
	// Track services
	services map[string]*model.Service
	// DNS queries
	dnsQueries    map[string]*DNSQuery
	deviceCounter int64
}

func NewGopacketParser(pcapFile string) *GopacketParser {
	return &GopacketParser{
		PcapFile:   pcapFile,
		devices:    make(map[string]*model.Device),
		flows:      make(map[string]*model.Flow),
		services:   make(map[string]*model.Service),
		dnsQueries: make(map[string]*DNSQuery),
	}
}

// updateDevice updates or creates a device
func (p *GopacketParser) updateDevice(address string, addressType string, timestamp time.Time, addressSubType string, macAddress string) *model.Device {
	devKey := addressType + ":" + address
	dev, exists := p.devices[devKey]
	if !exists {
		macAddressSet := model.NewMACAddressSet()
		if macAddress != "" {
			macAddressSet.Add(macAddress)
		}
		dev = &model.Device{
			ID:             p.deviceCounter,
			Address:        address,
			AddressType:    addressType,
			FirstSeen:      timestamp,
			LastSeen:       timestamp,
			AddressSubType: addressSubType,
			AddressScope:   helper2.GetAddressScope(address, addressType),
			MACAddressSet:  macAddressSet,
		}
		p.devices[devKey] = dev
		p.deviceCounter++
	} else {
		if macAddress != "" {
			dev.MACAddressSet.Add(macAddress)
		}
		dev.LastSeen = timestamp
	}
	return dev
}

// updateFlow updates or creates a flow
func (p *GopacketParser) updateFlow(src, dst, protocol string, timestamp time.Time, packetSize int, packetID int64, srcPort, dstPort string) *model.Flow {
	flowKey := fmt.Sprintf("%s:%s:%s", src, dst, protocol)

	sourcePortsSet := helper.NewSet()
	destinationPortsSet := helper.NewSet()

	if srcPort != "" && dstPort != "" {
		flowKey = fmt.Sprintf("%s:%s:%s:%s:%s", src, srcPort, dst, dstPort, protocol)
		sourcePortsSet.Add(srcPort)
		destinationPortsSet.Add(dstPort)
	}

	flow, exists := p.flows[flowKey]
	if !exists {
		flow = &model.Flow{
			Source:           src,
			Destination:      dst,
			Protocol:         protocol,
			Packets:          1,
			Bytes:            packetSize,
			FirstSeen:        timestamp,
			LastSeen:         timestamp,
			PacketRefs:       []int64{packetID},
			MinPacketSize:    &packetSize,
			MaxPacketSize:    &packetSize,
			SourcePorts:      sourcePortsSet,
			DestinationPorts: destinationPortsSet,
		}
		p.flows[flowKey] = flow
	} else {
		flow.Packets++
		flow.Bytes += packetSize
		flow.LastSeen = timestamp
		flow.PacketRefs = append(flow.PacketRefs, packetID)
		if packetSize < *flow.MinPacketSize {
			*flow.MinPacketSize = packetSize
		}
		if packetSize > *flow.MaxPacketSize {
			*flow.MaxPacketSize = packetSize
		}
		if srcPort != "" && dstPort != "" {
			flow.SourcePorts.Add(srcPort)
			flow.DestinationPorts.Add(dstPort)
		} else {
			// If ports are not specified, we still want to keep the flow
			// but without port information
			if flow.SourcePorts == nil {
				flow.SourcePorts = helper.NewSet()
			}
			if flow.DestinationPorts == nil {
				flow.DestinationPorts = helper.NewSet()
			}
		}
	}
	return flow
}

// updateService updates or creates a service
func (p *GopacketParser) updateService(ip string, port int, protocol string, timestamp time.Time) *model.Service {
	serviceKey := fmt.Sprintf("%s:%d:%s", ip, port, protocol)
	service, exists := p.services[serviceKey]
	if !exists {
		service = &model.Service{
			IP:        ip,
			Port:      port,
			Protocol:  protocol,
			FirstSeen: timestamp,
			LastSeen:  timestamp,
		}
		p.services[serviceKey] = service
	} else {
		service.LastSeen = timestamp
	}
	return service
}

func (p *GopacketParser) updateDNSQuery(dnsQuery DNSQuery) {
	queryingDevice := p.devices["IP:"+dnsQuery.QueryingDeviceIP]
	answeringDevice := p.devices["IP:"+dnsQuery.AnsweringDeviceIP]
	if queryingDevice == nil {
		// create new device
		addressSubType := GetAddressSubTypeForIP(dnsQuery.QueryingDeviceIP)
		queryingDevice = p.updateDevice(dnsQuery.QueryingDeviceIP, "IP", dnsQuery.Timestamp, addressSubType, "")
	}
	if answeringDevice == nil {
		addressSubType := GetAddressSubTypeForIP(dnsQuery.AnsweringDeviceIP)
		answeringDevice = p.updateDevice(dnsQuery.AnsweringDeviceIP, "IP", dnsQuery.Timestamp, addressSubType, "")
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
											if subV.(string) != subValue.(string) && subV.(string) != "" && subValue.(string) != "" {
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
func (p *GopacketParser) ParseFile(repo repository.Repository) error {
	handle, err := pcap.OpenOffline(p.PcapFile)
	if err != nil {
		return fmt.Errorf("failed to open pcap: %w", err)
	}
	defer handle.Close()

	liblayers.InitLayerLLDP()
	liblayers.InitLayerEIGRP()

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
	packetChan := make(chan *model.Packet, batchSize)
	errChan := make(chan error, 1)
	doneChan := make(chan struct{})

	// Start a worker goroutine to process packets in batches
	go func() {
		defer close(doneChan)
		var batch []*model.Packet

		for packet := range packetChan {
			batch = append(batch, packet)

			if len(batch) >= batchSize {
				if err := repo.AddPackets(batch); err != nil {
					errChan <- fmt.Errorf("failed to add packet batch: %w", err)
					return
				}
				// Clear the batch but keep the allocated memory
				batch = batch[:0]
			}
		}

		// Process any remaining packets
		if len(batch) > 0 {
			if err := repo.AddPackets(batch); err != nil {
				errChan <- fmt.Errorf("failed to add final packet batch: %w", err)
			}
		}
	}()

	for packet := range packetSource.Packets() {
		// Pre-allocate maps with capacity hints
		layersMap := make(map[string]interface{}, 10) // Assume average 10 layers
		protocols := make([]string, 0, 5)             // Assume average 5 protocols

		var (
			srcMAC, dstMAC   string
			srcIP, dstIP     string
			srcPort, dstPort string
			flowProto        string
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
			type_code := icmp.TypeCode.String()
			layersMap["icmp"] = map[string]interface{}{
				"type_code": type_code,
				"checksum":  icmp.Checksum,
			}
			if strings.Contains(type_code, "DestinationUnreachable") {
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
			srcPortNum := uint16(tcp.SrcPort)
			dstPortNum := uint16(tcp.DstPort)

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
			// Update service for TCP - use a direct call to avoid string concatenation
			timestamp := packet.Metadata().Timestamp
			p.updateService(srcIP, int(srcPortNum), "tcp", timestamp)
		}

		// UDP
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp := udpLayer.(*layers.UDP)
			srcPortNum := uint16(udp.SrcPort)
			dstPortNum := uint16(udp.DstPort)

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

		timestamp := packet.Metadata().Timestamp
		length := len(packet.Data())
		modelPacket := &model.Packet{
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
			p.updateDevice(srcIP, "IP", timestamp, addressSubType, srcMAC)
		}
		if dstMAC != "" && dstIP != "" {
			addressSubType := GetAddressSubTypeForIP(dstIP)
			p.updateDevice(dstIP, "IP", timestamp, addressSubType, dstMAC)
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

			p.updateFlow(source, destination, flowProto, timestamp, length, packetID, srcPort, dstPort)
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
	deviceBatch := make([]*model.Device, 0, maxBatchSize)
	deviceCount := 0

	for _, dev := range p.devices {
		deviceBatch = append(deviceBatch, dev)
		deviceCount++

		if deviceCount >= maxBatchSize {
			if err := repo.AddDevices(deviceBatch); err != nil {
				return fmt.Errorf("failed to add device batch: %w", err)
			}
			deviceBatch = deviceBatch[:0]
			deviceCount = 0
		}
	}

	// Add remaining devices
	if deviceCount > 0 {
		if err := repo.AddDevices(deviceBatch); err != nil {
			return fmt.Errorf("failed to add devices: %w", err)
		}
	}

	// Batch process flows
	flowBatch := make([]*model.Flow, 0, maxBatchSize)
	flowCount := 0

	for _, flow := range p.flows {
		flowBatch = append(flowBatch, flow)
		flowCount++

		if flowCount >= maxBatchSize {
			if err := repo.AddFlows(flowBatch); err != nil {
				return fmt.Errorf("failed to add flow batch: %w", err)
			}
			flowBatch = flowBatch[:0]
			flowCount = 0
		}
	}

	// Add remaining flows
	if flowCount > 0 {
		if err := repo.AddFlows(flowBatch); err != nil {
			return fmt.Errorf("failed to add flows: %w", err)
		}
	}

	// Batch process services
	serviceBatch := make([]*model.Service, 0, maxBatchSize)
	serviceCount := 0

	for _, service := range p.services {
		serviceBatch = append(serviceBatch, service)
		serviceCount++

		if serviceCount >= maxBatchSize {
			if err := repo.AddServices(serviceBatch); err != nil {
				return fmt.Errorf("failed to add service batch: %w", err)
			}
			serviceBatch = serviceBatch[:0]
			serviceCount = 0
		}
	}

	// Add remaining services
	if serviceCount > 0 {
		if err := repo.AddServices(serviceBatch); err != nil {
			return fmt.Errorf("failed to add services: %w", err)
		}
	}

	// Save DNS queries
	for _, dnsQuery := range p.dnsQueries {
		queryingDeviceKey := "IP:" + dnsQuery.QueryingDeviceIP
		queryingDevice := p.devices[queryingDeviceKey]
		answeringDeviceKey := "IP:" + dnsQuery.AnsweringDeviceIP
		answeringDevice := p.devices[answeringDeviceKey]
		if queryingDevice == nil {
			err = repo.AddDevice(&model.Device{
				Address:        dnsQuery.QueryingDeviceIP,
				AddressType:    "IP",
				FirstSeen:      dnsQuery.Timestamp,
				LastSeen:       dnsQuery.Timestamp,
				AddressSubType: "IPv4", // Default to IPv4, can be adjusted
				AddressScope:   helper2.GetAddressScope(dnsQuery.QueryingDeviceIP, "IP"),
				MACAddressSet:  model.NewMACAddressSet(),
			})
			if err != nil {
				return fmt.Errorf("failed to add querying device: %w", err)
			}
			queryingDevice, err = repo.GetDevice(dnsQuery.QueryingDeviceIP)
			if err != nil {
				return fmt.Errorf("failed to retrieve querying device: %w", err)
			}
		}
		if answeringDevice == nil {
			err = repo.AddDevice(&model.Device{
				Address:        dnsQuery.AnsweringDeviceIP,
				AddressType:    "IP",
				FirstSeen:      dnsQuery.Timestamp,
				LastSeen:       dnsQuery.Timestamp,
				AddressSubType: "IPv4", // Default to IPv4, can be adjusted
				AddressScope:   helper2.GetAddressScope(dnsQuery.AnsweringDeviceIP, "IP"),
				MACAddressSet:  model.NewMACAddressSet(),
			})
			if err != nil {
				return fmt.Errorf("failed to add answering device: %w", err)
			}
			answeringDevice, err = repo.GetDevice(dnsQuery.AnsweringDeviceIP)
			if err != nil {
				return fmt.Errorf("failed to retrieve answering device: %w", err)
			}
		}

		dnsRecord := &model.DNSQuery{
			QueryingDeviceID:  queryingDevice.ID,
			AnsweringDeviceID: answeringDevice.ID,
			QueryName:         dnsQuery.QueryName,
			QueryType:         dnsQuery.QueryType,
			QueryResult:       dnsQuery.Answers,
			Timestamp:         dnsQuery.Timestamp,
		}
		if err = repo.AddDNSQuery(dnsRecord); err != nil {
			return fmt.Errorf("failed to add DNS record: %w", err)
		}
	}

	return nil
}

func GetAddressSubTypeForIP(ip string) string {
	addressSubType := "IPv4"
	if strings.Count(ip, ":") > 1 {
		addressSubType = "IPv6"
	}
	return addressSubType
}

func (p *GopacketParser) saveAllDeviceRelations(devices []*model.Device, repo repository.Repository, comment string) error {
	for _, dev1 := range devices {
		for _, dev2 := range devices {
			if dev1.ID == dev2.ID {
				continue // Skip self-relation
			}
			relation := &model.DeviceRelation{
				DeviceID1: dev1.ID,
				DeviceID2: dev2.ID,
				Comment:   comment,
			}
			if err := repo.AddDeviceRelation(relation); err != nil {
				return fmt.Errorf("failed to add device relation: %w", err)
			}
		}
	}
	return nil
}
