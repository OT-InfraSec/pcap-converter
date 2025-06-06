package repository

import (
	"database/sql"
	"encoding/json"
	"log"
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
		`CREATE TABLE IF NOT EXISTS devices (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			address TEXT NOT NULL,
			address_type TEXT NOT NULL,
			first_seen TEXT NOT NULL,
			last_seen TEXT NOT NULL,
			address_sub_type TEXT,
			address_scope TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS flows (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			source TEXT NOT NULL,
			destination TEXT NOT NULL,
			protocol TEXT NOT NULL,
			packets INTEGER NOT NULL,
			bytes INTEGER NOT NULL,
			first_seen TEXT NOT NULL,
			last_seen TEXT NOT NULL,
			source_device_id INTEGER,
			destination_device_id INTEGER,
			min_packet_size INTEGER,
			max_packet_size INTEGER,
			packet_refs TEXT
		);
		`,
		// Add other tables as needed (dns_queries)
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

func (r *SQLiteRepository) AddDevice(device *model.Device) error {
	// Validiere das Device bevor es zur Datenbank hinzugefügt wird
	if err := device.Validate(); err != nil {
		return err
	}

	_, err := r.db.Exec(
		`INSERT INTO devices (address, address_type, first_seen, last_seen, address_sub_type, address_scope) VALUES (?, ?, ?, ?, ?, ?);`,
		device.Address,
		device.AddressType,
		device.FirstSeen.Format(time.RFC3339Nano),
		device.LastSeen.Format(time.RFC3339Nano),
		device.AddressSubType,
		device.AddressScope,
	)
	return err
}

func (r *SQLiteRepository) AddFlow(flow *model.Flow) error {
	// Validiere den Flow bevor er zur Datenbank hinzugefügt wird
	if err := flow.Validate(); err != nil {
		return err
	}

	packetRefsJSON, _ := json.Marshal(flow.PacketRefs)
	_, err := r.db.Exec(
		`INSERT INTO flows (source, destination, protocol, packets, bytes, first_seen, last_seen, source_device_id, destination_device_id, min_packet_size, max_packet_size, packet_refs) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`,
		flow.Source,
		flow.Destination,
		flow.Protocol,
		flow.Packets,
		flow.Bytes,
		flow.FirstSeen.Format(time.RFC3339Nano),
		flow.LastSeen.Format(time.RFC3339Nano),
		flow.SourceDeviceID,
		flow.DestinationDeviceID,
		flow.MinPacketSize,
		flow.MaxPacketSize,
		string(packetRefsJSON),
	)
	return err
}

func (r *SQLiteRepository) AllPackets() ([]*model.Packet, error) {
	rows, err := r.db.Query(`SELECT id, timestamp, length, layers, protocols FROM packets`)
	if err != nil {
		return nil, err
	}
	defer func(rows *sql.Rows) {
		err := rows.Close()
		if err != nil {
			// Log the error but do not return it, as we are already returning packets
			// This is a best-effort cleanup
			log.Printf("Error closing rows: %v", err)
		}
	}(rows)
	var packets []*model.Packet
	for rows.Next() {
		var (
			id           int64
			tsStr        string
			length       int
			layersStr    string
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
