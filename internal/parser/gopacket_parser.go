package parser

import (
	"fmt"
	"strconv"
	"strings"

	"pcap-importer-golang/internal/model"
	"pcap-importer-golang/internal/repository"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type GopacketParser struct {
	PcapFile string
}

func NewGopacketParser(pcapFile string) *GopacketParser {
	return &GopacketParser{PcapFile: pcapFile}
}

func (p *GopacketParser) ParseFile(repo repository.Repository) error {
	handle, err := pcap.OpenOffline(p.PcapFile)
	if err != nil {
		return fmt.Errorf("failed to open pcap: %w", err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetID := int64(0)
	seenDevices := make(map[string]struct{})
	seenFlows := make(map[string]struct{})

	for packet := range packetSource.Packets() {
		layersMap := make(map[string]interface{})
		protocols := []string{}

		var (
			srcMAC, dstMAC   string
			srcIP, dstIP     string
			srcPort, dstPort string
			// Use uint16 to store numeric port values
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
		// TCP
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp := tcpLayer.(*layers.TCP)
			// Get numeric port values
			srcPortNum = uint16(tcp.SrcPort)
			dstPortNum = uint16(tcp.DstPort)
			// Convert to string for map storage
			srcPort = strconv.Itoa(int(srcPortNum))
			dstPort = strconv.Itoa(int(dstPortNum))
			flowProto = "tcp"
			layersMap["tcp"] = map[string]interface{}{
				"src_port": srcPort,
				"dst_port": dstPort,
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
			// Get numeric port values
			srcPortNum = uint16(udp.SrcPort)
			dstPortNum = uint16(udp.DstPort)
			// Convert to string for map storage
			srcPort = strconv.Itoa(int(srcPortNum))
			dstPort = strconv.Itoa(int(dstPortNum))
			flowProto = "udp"
			layersMap["udp"] = map[string]interface{}{
				"src_port": srcPort,
				"dst_port": dstPort,
			}
			protocols = append(protocols, "udp")
		}
		// DNS
		if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
			dns := dnsLayer.(*layers.DNS)
			layersMap["dns"] = map[string]interface{}{
				"id":        dns.ID,
				"qr":        dns.QR,
				"opcode":    dns.OpCode.String(),
				"rcode":     dns.ResponseCode.String(),
				"questions": len(dns.Questions),
				"answers":   len(dns.Answers),
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
			devKey := "MAC:" + srcMAC
			if _, seen := seenDevices[devKey]; !seen {
				// Validate MAC address format before adding
				if model.IsValidMACAddress(srcMAC) {
					dev := &model.Device{
						Address:        srcMAC,
						AddressType:    "MAC",
						FirstSeen:      timestamp,
						LastSeen:       timestamp,
						AddressSubType: "",
						AddressScope:   "",
					}
					if err := repo.AddDevice(dev); err != nil {
						// Log the error but continue processing
						fmt.Printf("Error adding device with MAC %s: %v\n", srcMAC, err)
					} else {
						seenDevices[devKey] = struct{}{}
					}
				} else {
					fmt.Printf("Skipping invalid MAC address format: %s\n", srcMAC)
				}
			}
		}

		if dstMAC != "" {
			devKey := "MAC:" + dstMAC
			if _, seen := seenDevices[devKey]; !seen {
				// Validate MAC address format before adding
				if model.IsValidMACAddress(dstMAC) {
					dev := &model.Device{
						Address:        dstMAC,
						AddressType:    "MAC",
						FirstSeen:      timestamp,
						LastSeen:       timestamp,
						AddressSubType: "",
						AddressScope:   "",
					}
					if err := repo.AddDevice(dev); err != nil {
						// Log the error but continue processing
						fmt.Printf("Error adding device with MAC %s: %v\n", dstMAC, err)
					} else {
						seenDevices[devKey] = struct{}{}
					}
				} else {
					fmt.Printf("Skipping invalid MAC address format: %s\n", dstMAC)
				}
			}
		}

		// Handle IP addresses
		if srcIP != "" {
			devKey := "IP:" + srcIP
			if _, seen := seenDevices[devKey]; !seen {
				// Validate IP address format before adding
				if model.IsValidIPAddress(srcIP) {
					// Determine IPv4 vs IPv6 for address subtype
					addressSubType := "IPv4"
					if strings.Count(srcIP, ":") > 1 {
						addressSubType = "IPv6"
					}

					dev := &model.Device{
						Address:        srcIP,
						AddressType:    "IP",
						AddressSubType: addressSubType,
						FirstSeen:      timestamp,
						LastSeen:       timestamp,
						AddressScope:   "",
					}
					if err := repo.AddDevice(dev); err != nil {
						// Log the error but continue processing
						fmt.Printf("Error adding device with IP %s: %v\n", srcIP, err)
					} else {
						seenDevices[devKey] = struct{}{}
					}
				} else {
					fmt.Printf("Skipping invalid IP address format: %s\n", srcIP)
				}
			}
		}

		if dstIP != "" {
			devKey := "IP:" + dstIP
			if _, seen := seenDevices[devKey]; !seen {
				// Validate IP address format before adding
				if model.IsValidIPAddress(dstIP) {
					// Determine IPv4 vs IPv6 for address subtype
					addressSubType := "IPv4"
					if strings.Count(dstIP, ":") > 1 {
						addressSubType = "IPv6"
					}

					dev := &model.Device{
						Address:        dstIP,
						AddressType:    "IP",
						AddressSubType: addressSubType,
						FirstSeen:      timestamp,
						LastSeen:       timestamp,
						AddressScope:   "",
					}
					if err := repo.AddDevice(dev); err != nil {
						// Log the error but continue processing
						fmt.Printf("Error adding device with IP %s: %v\n", dstIP, err)
					} else {
						seenDevices[devKey] = struct{}{}
					}
				} else {
					fmt.Printf("Skipping invalid IP address format: %s\n", dstIP)
				}
			}
		}

		// Flow extraction and storage (simple 5-tuple)
		if srcIP != "" && dstIP != "" && srcPort != "" && dstPort != "" && flowProto != "" {
			flowKey := fmt.Sprintf("%s-%s-%s-%s-%s", srcIP, dstIP, srcPort, dstPort, flowProto)
			if _, seen := seenFlows[flowKey]; !seen {
				// Format source address correctly
				var source, destination string

				// Check if source is IPv6 and format accordingly
				if strings.Count(srcIP, ":") > 1 {
					// IPv6 address needs to be enclosed in square brackets
					source = fmt.Sprintf("[%s]:%s", srcIP, srcPort)
				} else {
					// IPv4 address
					source = fmt.Sprintf("%s:%s", srcIP, srcPort)
				}

				// Check if destination is IPv6 and format accordingly
				if strings.Count(dstIP, ":") > 1 {
					// IPv6 address needs to be enclosed in square brackets
					destination = fmt.Sprintf("[%s]:%s", dstIP, dstPort)
				} else {
					// IPv4 address
					destination = fmt.Sprintf("%s:%s", dstIP, dstPort)
				}

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
	return nil
}
