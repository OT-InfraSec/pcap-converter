package dns

import "github.com/InfraSecConsult/pcap-importer-go/internal/repository"

type NoopDNSProcessor struct{}

func (n *NoopDNSProcessor) Process(repo repository.Repository) error {
	return nil
}
