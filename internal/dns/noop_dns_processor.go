package dns

import "pcap-importer-golang/internal/repository"

type NoopDNSProcessor struct{}

func (n *NoopDNSProcessor) Process(repo repository.Repository) error {
	return nil
}
