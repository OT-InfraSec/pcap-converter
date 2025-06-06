package parser

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"pcap-importer-golang/internal/model"
	"pcap-importer-golang/internal/repository"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type GopacketParser struct {
	PcapFile string
	// Track devices and their relationships
	devices map[string]*model.Device
	// Track flows
	flows map[string]*model.Flow
	// Track services
	services map[string]*model.Service
}

func NewGopacketParser(pcapFile string) *GopacketParser {
	return &GopacketParser{
		PcapFile: pcapFile,
		devices:  make(map[string]*model.Device),
		flows:    make(map[string]*model.Flow),
		services: make(map[string]*model.Service),
	}
}

// getAddressScope determines if an address is unicast, multicast, or broadcast
func getAddressScope(address string, addressType string) string {
	if addressType == "MAC" {
		if address == "ff:ff:ff:ff:ff:ff" {
			return "broadcast"
		}
		// Check if MAC is multicast (first byte's least significant bit is 1)
		parts := strings.Split(address, ":")
		if len(parts) > 0 {
			firstByte, err := strconv.ParseInt(parts[0], 16, 8)
			if err == nil && firstByte&0x01 == 1 {
				return "multicast"
			}
		}
		return "unicast"
	} else if addressType == "IP" {
		ip := net.ParseIP(address)
		if ip == nil {
			return ""
		}
		if ip.IsMulticast() {
			return "multicast"
		}
		if ip.IsLoopback() {
			return "unicast"
		}
		if ip.IsLinkLocalMulticast() {
			return "multicast"
		}
		if ip.IsInterfaceLocalMulticast() {
			return "multicast"
		}
		if ip.IsGlobalUnicast() {
			return "unicast"
		}
		if ip.IsPrivate() {
			return "unicast"
		}
		if ip.Equal(net.IPv4bcast) {
			return "broadcast"
		}
		return "unicast"
	}
	return ""
}

// updateDevice updates or creates a device
func (p *GopacketParser) updateDevice(address string, addressType string, timestamp time.Time, addressSubType string) *model.Device {
	devKey := addressType + ":" + address
	dev, exists := p.devices[devKey]
	if !exists {
		dev = &model.Device{
			Address:        address,
			AddressType:    addressType,
			FirstSeen:      timestamp,
			LastSeen:       timestamp,
			AddressSubType: addressSubType,
			AddressScope:   getAddressScope(address, addressType),
		}
		p.devices[devKey] = dev
	} else {
		dev.LastSeen = timestamp
	}
	return dev
}

// updateFlow updates or creates a flow
func (p *GopacketParser) updateFlow(src, dst, protocol string, timestamp time.Time, packetSize int, packetID int64, srcPort, dstPort *uint16) *model.Flow {
	flowKey := fmt.Sprintf("%s:%s:%s", src, dst, protocol)
	if srcPort != nil && dstPort != nil {
		flowKey = fmt.Sprintf("%s:%d:%s:%d:%s", src, *srcPort, dst, *dstPort, protocol)
	}

	flow, exists := p.flows[flowKey]
	if !exists {
		flow = &model.Flow{
			Source:        src,
			Destination:   dst,
			Protocol:      protocol,
			Packets:       1,
			Bytes:         packetSize,
			FirstSeen:     timestamp,
			LastSeen:      timestamp,
			PacketRefs:    []int64{packetID},
			MinPacketSize: &packetSize,
			MaxPacketSize: &packetSize,
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

func (p *GopacketParser) ParseFile(repo repository.Repository) error {
	handle, err := pcap.OpenOffline(p.PcapFile)
	if err != nil {
		return fmt.Errorf("failed to open pcap: %w", err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetID := int64(0)

	seenFlows := make(map[string]struct{})

	for packet := range packetSource.Packets() {
		layersMap := make(map[string]interface{})
		protocols := []string{}

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
			layersMap["icmp"] = map[string]interface{}{
				"type_code": icmp.TypeCode.String(),
				"checksum":  icmp.Checksum,
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
			srcPort = fmt.Sprintf("%d", srcPortNum)
			dstPort = fmt.Sprintf("%d", dstPortNum)
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
		}

		// UDP
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp := udpLayer.(*layers.UDP)
			srcPortNum := uint16(udp.SrcPort)
			dstPortNum := uint16(udp.DstPort)
			srcPort = fmt.Sprintf("%d", srcPortNum)
			dstPort = fmt.Sprintf("%d", dstPortNum)
			flowProto = "udp"
			layersMap["udp"] = map[string]interface{}{
				"src_port": udp.SrcPort.String(),
				"dst_port": udp.DstPort.String(),
			}
			protocols = append(protocols, "udp")
		}

		// DNS
		if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
			dns := dnsLayer.(*layers.DNS)
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
		if err := repo.AddPacket(modelPacket); err != nil {
			return fmt.Errorf("failed to add packet: %w", err)
		}

		// Device extraction and storage
		// Handle MAC addresses
		if srcMAC != "" {
			p.updateDevice(srcMAC, "MAC", timestamp, "")
		}
		if dstMAC != "" {
			p.updateDevice(dstMAC, "MAC", timestamp, "")
		}

		// Handle IP addresses
		if srcIP != "" {
			addressSubType := "IPv4"
			if strings.Count(srcIP, ":") > 1 {
				addressSubType = "IPv6"
			}
			p.updateDevice(srcIP, "IP", timestamp, addressSubType)
		}
		if dstIP != "" {
			addressSubType := "IPv4"
			if strings.Count(dstIP, ":") > 1 {
				addressSubType = "IPv6"
			}
			p.updateDevice(dstIP, "IP", timestamp, addressSubType)
		}

		// Flow extraction and storage
		if srcIP != "" && dstIP != "" && flowProto != "" {
			var source, destination string

			// For protocols like TCP/UDP that have ports
			if srcPort != "" && dstPort != "" {
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
			} else {
				// For protocols like ICMP, ARP that don't have ports
				source = srcIP
				destination = dstIP
			}

			flowKey := fmt.Sprintf("%s-%s-%s", source, destination, flowProto)
			if _, seen := seenFlows[flowKey]; !seen {
				// Set minimum and maximum packet size
				minSize := length
				maxSize := length

				flow := &model.Flow{
					Source:        source,
					Destination:   destination,
					Protocol:      flowProto,
					Packets:       1,
					Bytes:         length,
					FirstSeen:     timestamp,
					LastSeen:      timestamp,
					MinPacketSize: &minSize,
					MaxPacketSize: &maxSize,
					PacketRefs:    []int64{packetID},
				}

				if err := repo.AddFlow(flow); err != nil {
					// Log the error but continue processing
					fmt.Printf("Error adding flow %s -> %s: %v\n", source, destination, err)
				} else {
					seenFlows[flowKey] = struct{}{}
				}
			}
		}

		packetID++
	}

	// Save all collected data to the repository
	for _, dev := range p.devices {
		if err := repo.AddDevice(dev); err != nil {
			return fmt.Errorf("failed to add device: %w", err)
		}
	}

	for _, flow := range p.flows {
		if err := repo.AddFlow(flow); err != nil {
			return fmt.Errorf("failed to add flow: %w", err)
		}
	}

	for _, service := range p.services {
		if err := repo.AddService(service); err != nil {
			return fmt.Errorf("failed to add service: %w", err)
		}
	}

	// Create device relationships
	for _, dev1 := range p.devices {
		for _, dev2 := range p.devices {
			if dev1.Address != dev2.Address {
				relation := &model.DeviceRelation{
					DeviceID1: dev1.ID,
					DeviceID2: dev2.ID,
					Comment:   "Related devices",
				}
				if err := repo.AddDeviceRelation(relation); err != nil {
					return fmt.Errorf("failed to add device relation: %w", err)
				}
			}
		}
	}

	return nil
}
