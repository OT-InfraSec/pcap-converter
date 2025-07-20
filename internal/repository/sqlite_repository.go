package repository

import (
	"database/sql"
	"encoding/json"
	"errors"
	model2 "github.com/InfraSecConsult/pcap-importer-go/lib/model"
	"github.com/mattn/go-sqlite3"
	"log"
	"strings"
	"time"

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
			address_scope TEXT,
			mac_addresses TEXT,
			additional_data TEXT,
			is_only_destination BOOLEAN
		);`,
		`CREATE TABLE IF NOT EXISTS services (
			element_id INTEGER PRIMARY KEY AUTOINCREMENT,
			ip TEXT NOT NULL,
			port INTEGER NOT NULL,
			first_seen TEXT NOT NULL,
			last_seen TEXT NOT NULL,
			protocol TEXT
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
			packet_refs TEXT,
			source_ports TEXT,
			destination_ports TEXT,
			FOREIGN KEY (source_device_id) REFERENCES devices (id),
			FOREIGN KEY (destination_device_id) REFERENCES devices (id)
		);`,
		`CREATE TABLE IF NOT EXISTS packet_protocols (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			packet_id INTEGER NOT NULL,
			protocol TEXT NOT NULL,
			FOREIGN KEY (packet_id) REFERENCES packets (id)
		);`,
		`CREATE TABLE IF NOT EXISTS service_flows (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			service_id INTEGER NOT NULL,
			flow_id INTEGER NOT NULL,
			FOREIGN KEY (service_id) REFERENCES services (element_id),
			FOREIGN KEY (flow_id) REFERENCES flows (id)
		);`,
		`CREATE TABLE IF NOT EXISTS device_relations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			device_id_1 INTEGER NOT NULL,
			device_id_2 INTEGER NOT NULL,
			comment TEXT,
			FOREIGN KEY (device_id_1) REFERENCES devices (id),
			FOREIGN KEY (device_id_2) REFERENCES devices (id),
			UNIQUE (device_id_1, device_id_2)
		);`,
		`CREATE TABLE IF NOT EXISTS dns_queries (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			querying_device_id INTEGER,
			answering_device_id INTEGER,
			query_name TEXT NOT NULL,
			query_type TEXT NOT NULL,
			query_result TEXT,
			timestamp TEXT NOT NULL,
			UNIQUE (querying_device_id, answering_device_id, query_name, query_type, query_result, timestamp),
			FOREIGN KEY (querying_device_id) REFERENCES devices (id),
			FOREIGN KEY (answering_device_id) REFERENCES devices (id)
		);`,
		// Create indexes for better query performance
		`CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp);`,
		`CREATE INDEX IF NOT EXISTS idx_devices_address ON devices(address);`,
		`CREATE INDEX IF NOT EXISTS idx_services_ip_port ON services(ip, port);`,
		`CREATE INDEX IF NOT EXISTS idx_flows_protocol ON flows(protocol);`,
		`CREATE INDEX IF NOT EXISTS idx_flows_timestamps ON flows(first_seen, last_seen);`,
	}

	// Enable foreign key constraints
	if _, err := r.db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		return err
	}

	for _, q := range queries {
		if _, err := r.db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

func (r *SQLiteRepository) AddPacket(packet *model2.Packet) error {
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

func (r *SQLiteRepository) AddDevice(device *model2.Device) error {
	// Validiere das Device bevor es zur Datenbank hinzugefügt wird
	if err := device.Validate(); err != nil {
		return err
	}
	_, err := r.db.Exec(
		`INSERT INTO devices (address, address_type, first_seen, last_seen, address_sub_type, address_scope, mac_addresses, additional_data, is_only_destination) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);`,
		device.Address,
		device.AddressType,
		device.FirstSeen.Format(time.RFC3339Nano),
		device.LastSeen.Format(time.RFC3339Nano),
		device.AddressSubType,
		device.AddressScope,
		device.MACAddressSet.ToString(),
		device.AdditionalData,
		device.IsOnlyDestination,
	)
	return err
}

func (r *SQLiteRepository) GetDevice(address string) (*model2.Device, error) {
	query := `SELECT id, address, address_type, first_seen, last_seen, address_sub_type, address_scope, mac_addresses, additional_data, is_only_destination FROM devices WHERE address = ?`
	row := r.db.QueryRow(query, address)

	var device model2.Device
	var firstSeenStr, lastSeenStr, macAddressesStr string

	if err := row.Scan(&device.ID, &device.Address, &device.AddressType, &firstSeenStr, &lastSeenStr,
		&device.AddressSubType, &device.AddressScope, &macAddressesStr, &device.AdditionalData, &device.IsOnlyDestination); err != nil {
		return nil, err
	}

	device.FirstSeen, _ = time.Parse(time.RFC3339Nano, firstSeenStr)
	device.LastSeen, _ = time.Parse(time.RFC3339Nano, lastSeenStr)

	device.MACAddressSet = model2.NewMACAddressSet()

	for _, mac := range strings.Split(macAddressesStr, ",") {
		if mac != "" {
			device.MACAddressSet.Add(mac)
		}
	}

	return &device, nil
}

func (r *SQLiteRepository) AddFlow(flow *model2.Flow) error {
	// Validiere den Flow bevor er zur Datenbank hinzugefügt wird
	if err := flow.Validate(); err != nil {
		return err
	}

	// Get source and destination device IDs
	srcAddress := flow.Source
	srcAddress, err := model2.ExtractIPAddress(srcAddress)
	if srcAddress == "" || err != nil {
		return errors.New("invalid source address")
	}
	destAddress := flow.Destination
	destAddress, err = model2.ExtractIPAddress(destAddress)
	if destAddress == "" || err != nil {
		return errors.New("invalid destination address")
	}

	srcDevice, err := r.GetDeviceForAddress(srcAddress)
	if err != nil {
		log.Fatalf("Error getting source device for address %s: %v", srcAddress, err)
		return err
	}

	destDevice, err := r.GetDeviceForAddress(destAddress)
	if err != nil {
		log.Fatalf("Error getting destination device for address %s: %v", destAddress, err)
		return err
	}

	packetRefsJSON, _ := json.Marshal(flow.PacketRefs)
	result, err := r.db.Exec(
		`INSERT INTO flows (source, destination, protocol, packets, bytes, first_seen, last_seen, source_device_id, destination_device_id, min_packet_size, max_packet_size, packet_refs, source_ports, destination_ports) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`,
		flow.Source,
		flow.Destination,
		flow.Protocol,
		flow.Packets,
		flow.Bytes,
		flow.FirstSeen.Format(time.RFC3339Nano),
		flow.LastSeen.Format(time.RFC3339Nano),
		srcDevice.ID,
		destDevice.ID,
		flow.MinPacketSize,
		flow.MaxPacketSize,
		string(packetRefsJSON),
		flow.SourcePorts.ToString(),
		flow.DestinationPorts.ToString(),
	)
	if err != nil {
		log.Fatalf("Error inserting flow: %v", err)
		return err
	}
	flow.ID, err = result.LastInsertId()
	if err != nil {
		log.Fatalf("Error getting last insert ID for flow: %v", err)
	}
	return err
}

func (r *SQLiteRepository) AllPackets() ([]*model2.Packet, error) {
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
	var packets []*model2.Packet
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
		packets = append(packets, &model2.Packet{
			ID:        id,
			Timestamp: ts,
			Length:    length,
			Layers:    layers,
			Protocols: protocols,
		})
	}
	return packets, nil
}

func (r *SQLiteRepository) AddService(service *model2.Service) error {
	if err := service.Validate(); err != nil {
		return err
	}

	_, err := r.db.Exec(
		`INSERT INTO services (ip, port, first_seen, last_seen, protocol) VALUES (?, ?, ?, ?, ?);`,
		service.IP,
		service.Port,
		service.FirstSeen.Format(time.RFC3339Nano),
		service.LastSeen.Format(time.RFC3339Nano),
		service.Protocol,
	)
	return err
}

func (r *SQLiteRepository) AddDeviceRelation(relation *model2.DeviceRelation) error {
	_, err := r.db.Exec(
		`INSERT INTO device_relations (device_id_1, device_id_2, comment) VALUES (?, ?, ?);`,
		relation.DeviceID1,
		relation.DeviceID2,
		relation.Comment,
	)
	return err
}

func (r *SQLiteRepository) AddDNSQuery(query *model2.DNSQuery) error {
	if err := query.Validate(); err != nil {
		return err
	}

	jsonQueryResult, err := json.Marshal(query.QueryResult)
	if err != nil {
		log.Printf("Error marshaling query result: %v", err)
	}
	_, err = r.db.Exec(
		`INSERT INTO dns_queries (querying_device_id, answering_device_id, query_name, query_type, query_result, timestamp) 
		VALUES (?, ?, ?, ?, ?, ?);`,
		query.QueryingDeviceID,
		query.AnsweringDeviceID,
		query.QueryName,
		query.QueryType,
		string(jsonQueryResult),
		query.Timestamp.Format(time.RFC3339Nano),
	)
	if err != nil {
		log.Printf("Error inserting DNS query: %v", err)
		if sqliteErr, ok := err.(sqlite3.Error); ok && sqliteErr.Code == sqlite3.ErrConstraint {
			return nil // Ignore unique constraint violations
		}
	}
	return err
}

func (r *SQLiteRepository) GetServices(filters map[string]interface{}) ([]*model2.Service, error) {
	query := "SELECT element_id, ip, port, first_seen, last_seen, protocol FROM services"
	params := []interface{}{}

	if len(filters) > 0 {
		conditions := []string{}
		for key, value := range filters {
			conditions = append(conditions, key+" = ?")
			params = append(params, value)
		}
		query += " WHERE " + strings.Join(conditions, " AND ")
	}

	rows, err := r.db.Query(query, params...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var services []*model2.Service
	for rows.Next() {
		var (
			elementID int64
			ip        string
			port      int
			firstSeen string
			lastSeen  string
			protocol  string
		)
		if err := rows.Scan(&elementID, &ip, &port, &firstSeen, &lastSeen, &protocol); err != nil {
			return nil, err
		}

		firstSeenTime, _ := time.Parse(time.RFC3339Nano, firstSeen)
		lastSeenTime, _ := time.Parse(time.RFC3339Nano, lastSeen)

		services = append(services, &model2.Service{
			ID:        elementID,
			IP:        ip,
			Port:      port,
			FirstSeen: firstSeenTime,
			LastSeen:  lastSeenTime,
			Protocol:  protocol,
		})
	}
	return services, nil
}

func (r *SQLiteRepository) GetDeviceRelations(deviceID *int64) ([]*model2.DeviceRelation, error) {
	query := "SELECT id, device_id_1, device_id_2, comment FROM device_relations"
	params := []interface{}{}

	if deviceID != nil {
		query += " WHERE device_id_1 = ? OR device_id_2 = ?"
		params = append(params, *deviceID, *deviceID)
	}

	rows, err := r.db.Query(query, params...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var relations []*model2.DeviceRelation
	for rows.Next() {
		var (
			id        int64
			deviceID1 int64
			deviceID2 int64
			comment   string
		)
		if err := rows.Scan(&id, &deviceID1, &deviceID2, &comment); err != nil {
			return nil, err
		}

		relations = append(relations, &model2.DeviceRelation{
			ID:        id,
			DeviceID1: deviceID1,
			DeviceID2: deviceID2,
			Comment:   comment,
		})
	}
	return relations, nil
}

func (r *SQLiteRepository) GetDNSQueries(eqFilters map[string]interface{}, likeFilters map[string]interface{}) ([]*model2.DNSQuery, error) {
	query := "SELECT id, querying_device_id, answering_device_id, query_name, query_type, query_result, timestamp FROM dns_queries"
	params := []interface{}{}

	if len(eqFilters) > 0 || len(likeFilters) > 0 {
		conditions := []string{}
		if len(eqFilters) > 0 {
			for key, value := range eqFilters {
				conditions = append(conditions, key+" = ?")
				params = append(params, value)
			}
		}
		if len(likeFilters) > 0 {
			for key, value := range likeFilters {
				conditions = append(conditions, key+" LIKE ?")
				params = append(params, value.(string))
			}
		}
		query += " WHERE " + strings.Join(conditions, " AND ")
	}

	rows, err := r.db.Query(query, params...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var queries []*model2.DNSQuery
	for rows.Next() {
		var (
			id                int64
			queryingDeviceID  int64
			answeringDeviceID int64
			queryName         string
			queryType         string
			queryResult       map[string]interface{}
			timestamp         string
		)
		if err := rows.Scan(&id, &queryingDeviceID, &answeringDeviceID, &queryName, &queryType, &queryResult, &timestamp); err != nil {
			return nil, err
		}

		timestampTime, _ := time.Parse(time.RFC3339Nano, timestamp)

		queries = append(queries, &model2.DNSQuery{
			ID:                id,
			QueryingDeviceID:  queryingDeviceID,
			AnsweringDeviceID: answeringDeviceID,
			QueryName:         queryName,
			QueryType:         queryType,
			QueryResult:       queryResult,
			Timestamp:         timestampTime,
		})
	}
	return queries, nil
}

func (r *SQLiteRepository) GetDeviceForAddress(address string) (*model2.Device, error) {
	query := `SELECT id, address, address_type, first_seen, last_seen, address_sub_type, address_scope, mac_addresses, additional_data FROM devices WHERE address = ?`
	row := r.db.QueryRow(query, address)

	var device model2.Device
	var firstSeenStr, lastSeenStr, macAddressesStr string

	if err := row.Scan(&device.ID, &device.Address, &device.AddressType, &firstSeenStr, &lastSeenStr,
		&device.AddressSubType, &device.AddressScope, &macAddressesStr, &device.AdditionalData); err != nil {
		return nil, err
	}

	device.FirstSeen, _ = time.Parse(time.RFC3339Nano, firstSeenStr)
	device.LastSeen, _ = time.Parse(time.RFC3339Nano, lastSeenStr)

	device.MACAddressSet = model2.NewMACAddressSet()

	for _, mac := range strings.Split(macAddressesStr, ",") {
		if mac != "" {
			device.MACAddressSet.Add(mac)
		}
	}

	return &device, nil
}

func (r *SQLiteRepository) Commit() error {
	// No-op for now (autocommit)
	return nil
}

func (r *SQLiteRepository) Close() error {
	return r.db.Close()
}

// AddPackets inserts multiple packets in a single transaction.
func (r *SQLiteRepository) AddPackets(packets []*model2.Packet) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT INTO packets (timestamp, length, layers, protocols) VALUES (?, ?, ?, ?);`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, packet := range packets {
		layersJSON, err := json.Marshal(packet.Layers)
		if err != nil {
			return err
		}
		protocolsJSON, err := json.Marshal(packet.Protocols)
		if err != nil {
			return err
		}
		_, err = stmt.Exec(
			packet.Timestamp.Format(time.RFC3339Nano),
			packet.Length,
			string(layersJSON),
			string(protocolsJSON),
		)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

// AddDevices inserts multiple devices in a single transaction.
func (r *SQLiteRepository) AddDevices(devices []*model2.Device) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT INTO devices (address, address_type, first_seen, last_seen, address_sub_type, address_scope, mac_addresses, additional_data, is_only_destination) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, device := range devices {
		macs := ""
		if device.MACAddressSet != nil {
			macs = device.MACAddressSet.ToString()
		}
		result, err := stmt.Exec(
			device.Address,
			device.AddressType,
			device.FirstSeen.Format(time.RFC3339Nano),
			device.LastSeen.Format(time.RFC3339Nano),
			device.AddressSubType,
			device.AddressScope,
			macs,
			device.AdditionalData,
			device.IsOnlyDestination,
		)
		if err != nil {
			return err
		}
		lastInsertID, err := result.LastInsertId()
		if err != nil {
			return err
		}
		device.ID = lastInsertID
	}
	return tx.Commit()
}

// AddFlows inserts multiple flows in a single transaction.
func (r *SQLiteRepository) AddFlows(flows []*model2.Flow) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT INTO flows (source, destination, protocol, packets, bytes, first_seen, last_seen, min_packet_size, max_packet_size, packet_refs, source_ports,
                   destination_ports, source_device_id,
                   destination_device_id)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, (
    SELECT id FROM devices WHERE address = ?
    ), (
    SELECT id FROM devices WHERE address = ?
    ));`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, flow := range flows {
		packetRefsJSON, err := json.Marshal(flow.PacketRefs)
		if err != nil {
			return err
		}
		sourcePorts := ""
		destinationPorts := ""
		if flow.SourcePorts != nil {
			sourcePorts = flow.SourcePorts.ToString()
		}
		if flow.DestinationPorts != nil {
			destinationPorts = flow.DestinationPorts.ToString()
		}
		var minPkt, maxPkt interface{}
		if flow.MinPacketSize != nil {
			minPkt = *flow.MinPacketSize
		} else {
			minPkt = nil
		}
		if flow.MaxPacketSize != nil {
			maxPkt = *flow.MaxPacketSize
		} else {
			maxPkt = nil
		}
		_, err = stmt.Exec(
			flow.Source,
			flow.Destination,
			flow.Protocol,
			flow.Packets,
			flow.Bytes,
			flow.FirstSeen.Format(time.RFC3339Nano),
			flow.LastSeen.Format(time.RFC3339Nano),
			minPkt,
			maxPkt,
			string(packetRefsJSON),
			sourcePorts,
			destinationPorts,
			flow.Source,
			flow.Destination,
		)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

// AddServices inserts multiple services in a single transaction.
func (r *SQLiteRepository) AddServices(services []*model2.Service) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT INTO services (ip, port, first_seen, last_seen, protocol) VALUES (?, ?, ?, ?, ?);`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, service := range services {
		if err := service.Validate(); err != nil {
			return err
		}

		_, err := stmt.Exec(
			service.IP,
			service.Port,
			service.FirstSeen.Format(time.RFC3339Nano),
			service.LastSeen.Format(time.RFC3339Nano),
			service.Protocol,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// AddDNSQueries inserts multiple DNS queries in a single transaction.
func (r *SQLiteRepository) AddDNSQueries(queries []*model2.DNSQuery) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT INTO dns_queries (querying_device_id, answering_device_id, query_name, query_type, query_result, timestamp) VALUES (?, ?, ?, ?, ?, ?);`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, query := range queries {
		err = query.Validate()
		if err != nil {
			log.Printf("Error validating DNS query: %v", err)
			continue // Skip this query if validation fails
		}

		jsonQueryResult, err := json.Marshal(query.QueryResult)
		if err != nil {
			log.Printf("Error marshaling query result: %v", err)
		}

		_, err = stmt.Exec(
			query.QueryingDeviceID,
			query.AnsweringDeviceID,
			query.QueryName,
			query.QueryType,
			string(jsonQueryResult),
			query.Timestamp.Format(time.RFC3339Nano),
		)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

// AddDeviceRelations inserts multiple device relations in a single transaction.
func (r *SQLiteRepository) AddDeviceRelations(relations []*model2.DeviceRelation) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO device_relations (device_id_1, device_id_2, comment) VALUES (?, ?, ?);`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, rel := range relations {
		_, err := stmt.Exec(rel.DeviceID1, rel.DeviceID2, rel.Comment)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (r *SQLiteRepository) UpdateDevice(device *model2.Device) error {
	if device.ID == 0 {
		return errors.New("device ID must not be zero")
	}
	_, err := r.db.Exec(
		`UPDATE devices SET address = ?, address_type = ?, first_seen = ?, last_seen = ?, address_sub_type = ?, address_scope = ?, mac_addresses = ?, additional_data = ? WHERE id = ?;`,
		device.Address,
		device.AddressType,
		device.FirstSeen.Format(time.RFC3339Nano),
		device.LastSeen.Format(time.RFC3339Nano),
		device.AddressSubType,
		device.AddressScope,
		device.MACAddressSet.ToString(),
		device.AdditionalData,
		device.ID,
	)
	return err
}
