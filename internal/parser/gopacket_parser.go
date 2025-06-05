package parser

import (
	"fmt"

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
			srcPort = tcp.SrcPort.String()
			dstPort = tcp.DstPort.String()
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
			srcPort = udp.SrcPort.String()
			dstPort = udp.DstPort.String()
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
		if srcMAC != "" {
			devKey := "MAC:" + srcMAC
			if _, seen := seenDevices[devKey]; !seen {
				dev := &model.Device{
					Address:        srcMAC,
					AddressType:    "MAC",
					FirstSeen:      timestamp,
					LastSeen:       timestamp,
					AddressSubType: "",
					AddressScope:   "",
				}
				repo.AddDevice(dev)
				seenDevices[devKey] = struct{}{}
			}
		}
		if dstMAC != "" {
			devKey := "MAC:" + dstMAC
			if _, seen := seenDevices[devKey]; !seen {
				dev := &model.Device{
					Address:        dstMAC,
					AddressType:    "MAC",
					FirstSeen:      timestamp,
					LastSeen:       timestamp,
					AddressSubType: "",
					AddressScope:   "",
				}
				repo.AddDevice(dev)
				seenDevices[devKey] = struct{}{}
			}
		}
		if srcIP != "" {
			devKey := "IP:" + srcIP
			if _, seen := seenDevices[devKey]; !seen {
				dev := &model.Device{
					Address:        srcIP,
					AddressType:    "IP",
					FirstSeen:      timestamp,
					LastSeen:       timestamp,
					AddressSubType: "",
					AddressScope:   "",
				}
				repo.AddDevice(dev)
				seenDevices[devKey] = struct{}{}
			}
		}
		if dstIP != "" {
			devKey := "IP:" + dstIP
			if _, seen := seenDevices[devKey]; !seen {
				dev := &model.Device{
					Address:        dstIP,
					AddressType:    "IP",
					FirstSeen:      timestamp,
					LastSeen:       timestamp,
					AddressSubType: "",
					AddressScope:   "",
				}
				repo.AddDevice(dev)
				seenDevices[devKey] = struct{}{}
			}
		}

		// Flow extraction and storage (simple 5-tuple)
		if srcIP != "" && dstIP != "" && srcPort != "" && dstPort != "" && flowProto != "" {
			flowKey := fmt.Sprintf("%s-%s-%s-%s-%s", srcIP, dstIP, srcPort, dstPort, flowProto)
			if _, seen := seenFlows[flowKey]; !seen {
				flow := &model.Flow{
					Source:      fmt.Sprintf("%s:%s", srcIP, srcPort),
					Destination: fmt.Sprintf("%s:%s", dstIP, dstPort),
					Protocol:    flowProto,
					Packets:     1,
					Bytes:       length,
					FirstSeen:   timestamp,
					LastSeen:    timestamp,
					PacketRefs:  []int64{packetID},
				}
				repo.AddFlow(flow)
				seenFlows[flowKey] = struct{}{}
			}
		}

		packetID++
	}
	return nil
}
