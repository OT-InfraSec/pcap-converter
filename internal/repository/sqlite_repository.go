package repository

import (
	"database/sql"
	"encoding/json"
	"time"

	"pcap-importer-golang/internal/model"

	_ "github.com/mattn/go-sqlite3"
)

type SQLiteRepository struct {
	db *sql.DB
}

func NewSQLiteRepository(path string) (*SQLiteRepository, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}
	repo := &SQLiteRepository{db: db}
	if err := repo.createTables(); err != nil {
		return nil, err
	}
	return repo, nil
}

func (r *SQLiteRepository) createTables() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS packets (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp TEXT NOT NULL,
			length INTEGER NOT NULL,
			layers TEXT NOT NULL,
			protocols TEXT
		);`,
		// Add other tables as needed (devices, flows, dns_queries)
	}
	for _, q := range queries {
		if _, err := r.db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

func (r *SQLiteRepository) AddPacket(packet *model.Packet) error {
	layersJSON, _ := json.Marshal(packet.Layers)
	protocolsJSON, _ := json.Marshal(packet.Protocols)
	_, err := r.db.Exec(
		`INSERT INTO packets (timestamp, length, layers, protocols) VALUES (?, ?, ?, ?);`,
		packet.Timestamp.Format(time.RFC3339Nano),
		packet.Length,
		string(layersJSON),
		string(protocolsJSON),
	)
	return err
}

func (r *SQLiteRepository) AllPackets() ([]*model.Packet, error) {
	rows, err := r.db.Query(`SELECT id, timestamp, length, layers, protocols FROM packets`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var packets []*model.Packet
	for rows.Next() {
		var (
			id int64
			tsStr string
			length int
			layersStr string
			protocolsStr string
		)
		if err := rows.Scan(&id, &tsStr, &length, &layersStr, &protocolsStr); err != nil {
			return nil, err
		}
		ts, _ := time.Parse(time.RFC3339Nano, tsStr)
		var layers map[string]interface{}
		_ = json.Unmarshal([]byte(layersStr), &layers)
		var protocols []string
		_ = json.Unmarshal([]byte(protocolsStr), &protocols)
		packets = append(packets, &model.Packet{
			ID:        id,
			Timestamp: ts,
			Length:    length,
			Layers:    layers,
			Protocols: protocols,
		})
	}
	return packets, nil
}

func (r *SQLiteRepository) AddDevice(device *model.Device) error {
	// Stub for now
	return nil
}

func (r *SQLiteRepository) AddFlow(flow *model.Flow) error {
	// Stub for now
	return nil
}

func (r *SQLiteRepository) AddDNSQuery(query *model.DNSQuery) error {
	// Stub for now
	return nil
}

func (r *SQLiteRepository) Commit() error {
	// No-op for now (autocommit)
	return nil
}

func (r *SQLiteRepository) Close() error {
	return r.db.Close()
}
