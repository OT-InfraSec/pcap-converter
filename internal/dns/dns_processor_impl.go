package dns

import (
	"fmt"

	"github.com/InfraSecConsult/pcap-importer-go/lib/model"

	"github.com/InfraSecConsult/pcap-importer-go/internal/repository"
)

type DefaultDNSProcessor struct{}

func NewDefaultDNSProcessor() *DefaultDNSProcessor {
	return &DefaultDNSProcessor{}
}

// dnsKey is used to match requests and responses
func dnsKey(id interface{}, srcIP, dstIP, srcPort, dstPort string) string {
	return fmt.Sprintf("%v-%s-%s-%s-%s", id, srcIP, dstIP, srcPort, dstPort)
}

func (d *DefaultDNSProcessor) Process(repo repository.Repository) error {
	packets, err := repoQueryPacketsWithDNS(repo)
	if err != nil {
		return err
	}

	type reqInfo struct {
		Packet    *model.Packet
		QueryName string
		QueryType string
		SrcIP     string
		DstIP     string
		SrcPort   string
		DstPort   string
		ID        interface{}
	}
	requests := make(map[string]reqInfo)

	for _, pkt := range packets {
		layers := pkt.Layers
		dnsRaw, ok := layers["dns"]
		if !ok {
			continue
		}
		dnsMap, ok := dnsRaw.(map[string]interface{})
		if !ok {
			continue
		}
		id := dnsMap["id"]
		qr := dnsMap["qr"]

		// Extract IP/port info
		srcIP, dstIP, srcPort, dstPort := extractIPPort(layers)

		// Extract query name/type if present
		queryName, queryType := "", ""
		if qs, ok := dnsMap["questions"].(float64); ok && qs > 0 {
			if qn, ok := dnsMap["query_name"].(string); ok {
				queryName = qn
			}
			if qt, ok := dnsMap["query_type"].(string); ok {
				queryType = qt
			}
		}

		key := dnsKey(id, srcIP, dstIP, srcPort, dstPort)
		if qr == false || qr == "false" || qr == 0 {
			requests[key] = reqInfo{
				Packet:    pkt,
				QueryName: queryName,
				QueryType: queryType,
				SrcIP:     srcIP,
				DstIP:     dstIP,
				SrcPort:   srcPort,
				DstPort:   dstPort,
				ID:        id,
			}
		} else {
			// Try to find matching request (reverse src/dst)
			reqKey := dnsKey(id, dstIP, srcIP, dstPort, srcPort)
			if req, found := requests[reqKey]; found {
				dnsQuery := &model.DNSQuery{
					QueryName:   req.QueryName,
					QueryType:   req.QueryType,
					QueryResult: dnsMap,
					Timestamp:   pkt.Timestamp,
				}
				repo.AddDNSQuery(dnsQuery)
			}
		}
	}
	return nil
}

func extractIPPort(layers map[string]interface{}) (srcIP, dstIP, srcPort, dstPort string) {
	if ip, ok := layers["ip"].(map[string]interface{}); ok {
		srcIP, _ = ip["src_ip"].(string)
		dstIP, _ = ip["dst_ip"].(string)
	}
	if udp, ok := layers["udp"].(map[string]interface{}); ok {
		srcPort, _ = udp["src_port"].(string)
		dstPort, _ = udp["dst_port"].(string)
	}
	if tcp, ok := layers["tcp"].(map[string]interface{}); ok {
		if srcPort == "" {
			srcPort, _ = tcp["src_port"].(string)
		}
		if dstPort == "" {
			dstPort, _ = tcp["dst_port"].(string)
		}
	}
	return
}

// repoQueryPacketsWithDNS fetches all packets with a DNS layer from the repository
func repoQueryPacketsWithDNS(repo repository.Repository) ([]*model.Packet, error) {
	// This is a placeholder. In a real implementation, the repository would support queries.
	// For now, assume we can type-assert to SQLiteRepository and query directly.
	type sqlRepo interface {
		AllPackets(tenantID string) ([]*model.Packet, error)
	}
	sr, ok := repo.(sqlRepo)
	if !ok {
		return nil, fmt.Errorf("repository does not support AllPackets")
	}
	all, err := sr.AllPackets("")
	if err != nil {
		return nil, err
	}
	var result []*model.Packet
	for _, pkt := range all {
		if _, ok := pkt.Layers["dns"]; ok {
			result = append(result, pkt)
		}
	}
	return result, nil
}
