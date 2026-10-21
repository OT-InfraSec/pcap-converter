package repository

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	helper "github.com/InfraSecConsult/pcap-importer-go/lib/helper"
	"github.com/InfraSecConsult/pcap-importer-go/lib/model"
)

// BenchmarkUpsertCDPNeighbors writes a full import's worth of rows (the parser's cap):
// the upsert is one SELECT plus one INSERT per row inside a single transaction.
func BenchmarkUpsertCDPNeighbors(b *testing.B) {
	now := time.Now()
	rows := make([]*model.CDPNeighbor, 0, 100000)
	for i := 0; i < cap(rows); i++ {
		rows = append(rows, cdpAt("t1", fmt.Sprintf("m%d", i%500), fmt.Sprintf("p%d", i), nil, nil, fmt.Sprintf("d%d", i), now, now))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		repo, err := NewSQLiteRepositoryWithCanonicalizer(filepath.Join(b.TempDir(), "cdp.sqlite"), helper.NewFlowCanonicalizer())
		if err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		if err = repo.UpsertCDPNeighbors(rows); err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
		_ = repo.Close()
	}
}
