package repository

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"strings"
	"time"

	model2 "github.com/InfraSecConsult/pcap-importer-go/lib/model"
	"github.com/mattn/go-sqlite3"

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
		`CREATE TABLE IF NOT EXISTS ssdp_queries (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			querying_device_id INTEGER NOT NULL,
			query_type VARCHAR(20) NOT NULL,
			st TEXT,
			user_agent TEXT,
			UNIQUE (querying_device_id, query_type)
        );`,
		`CREATE TABLE IF NOT EXISTS industrial_devices (
			device_address TEXT PRIMARY KEY,
			device_type TEXT NOT NULL,
			role TEXT NOT NULL,
			confidence REAL NOT NULL,
			protocols TEXT NOT NULL,
			security_level INTEGER NOT NULL,
			vendor TEXT,
			product_name TEXT,
			serial_number TEXT,
			firmware_version TEXT,
			last_seen DATETIME NOT NULL,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS protocol_usage_stats (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			device_address TEXT NOT NULL,
			protocol TEXT NOT NULL,
			packet_count INTEGER NOT NULL,
			byte_count INTEGER NOT NULL,
			first_seen DATETIME NOT NULL,
			last_seen DATETIME NOT NULL,
			communication_role TEXT NOT NULL,
			ports_used TEXT NOT NULL,
			UNIQUE (device_address, protocol)
		);`,
		`CREATE TABLE IF NOT EXISTS communication_patterns (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			source_device_address TEXT NOT NULL,
			destination_device_address TEXT NOT NULL,
			protocol TEXT NOT NULL,
			frequency_ms INTEGER NOT NULL,
			data_volume INTEGER NOT NULL,
			flow_count INTEGER NOT NULL,
			deviation_frequency REAL NOT NULL,
			deviation_data_volume REAL NOT NULL,
			pattern_type TEXT NOT NULL,
			criticality TEXT NOT NULL,
			created_at DATETIME NOT NULL,
			UNIQUE (source_device_address, destination_device_address, protocol)
		);`,
		// Create indexes for better query performance
		`CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp);`,
		`CREATE INDEX IF NOT EXISTS idx_devices_address ON devices(address);`,
		`CREATE INDEX IF NOT EXISTS idx_services_ip_port ON services(ip, port);`,
		`CREATE INDEX IF NOT EXISTS idx_flows_protocol ON flows(protocol);`,
		`CREATE INDEX IF NOT EXISTS idx_flows_timestamps ON flows(first_seen, last_seen);`,
		`CREATE INDEX IF NOT EXISTS idx_industrial_devices_type ON industrial_devices(device_type);`,
		`CREATE INDEX IF NOT EXISTS idx_industrial_devices_role ON industrial_devices(role);`,
		`CREATE INDEX IF NOT EXISTS idx_protocol_usage_stats_device ON protocol_usage_stats(device_address);`,
		`CREATE INDEX IF NOT EXISTS idx_protocol_usage_stats_protocol ON protocol_usage_stats(protocol);`,
		`CREATE INDEX IF NOT EXISTS idx_communication_patterns_source ON communication_patterns(source_device_address);`,
		`CREATE INDEX IF NOT EXISTS idx_communication_patterns_dest ON communication_patterns(destination_device_address);`,
		`CREATE INDEX IF NOT EXISTS idx_communication_patterns_protocol ON communication_patterns(protocol);`,
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
		return errors.Join(err, errors.New("invalid device data in function AddDevice"))
	}
	macAddresses := ""
	if device.MACAddressSet != nil {
		macAddresses = device.MACAddressSet.ToString()
	}

	_, err := r.db.Exec(
		`INSERT INTO devices (address, address_type, first_seen, last_seen, address_sub_type, address_scope, mac_addresses, additional_data, is_only_destination) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);`,
		device.Address,
		device.AddressType,
		device.FirstSeen.Format(time.RFC3339Nano),
		device.LastSeen.Format(time.RFC3339Nano),
		device.AddressSubType,
		device.AddressScope,
		macAddresses,
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

func (r *SQLiteRepository) GetDevices(filters map[string]interface{}) ([]*model2.Device, error) {
	query := `SELECT id, address, address_type, first_seen, last_seen, address_sub_type, address_scope, mac_addresses, additional_data, is_only_destination FROM devices`
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

	var devices []*model2.Device
	for rows.Next() {
		var firstSeenStr, lastSeenStr, macAddressesStr string
		var device model2.Device

		if err := rows.Scan(&device.ID, &device.Address, &device.AddressType, &firstSeenStr, &lastSeenStr,
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

		devices = append(devices, &device)
	}

	return devices, nil
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

func (r *SQLiteRepository) GetFlows(filters map[string]interface{}) ([]*model2.Flow, error) {
	query := `SELECT id, source, destination, protocol, packets, bytes, first_seen, last_seen, source_device_id, destination_device_id, min_packet_size, max_packet_size, packet_refs, source_ports, destination_ports FROM flows`
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

	var flows []*model2.Flow
	for rows.Next() {
		var firstSeenStr, lastSeenStr, sourcePortsStr, destinationPortsStr, packetRefsJson string
		var flow model2.Flow

		if err := rows.Scan(&flow.ID, &flow.Source, &flow.Destination, &flow.Protocol, &flow.Packets, &flow.Bytes, &firstSeenStr, &lastSeenStr, &flow.SourceDeviceID, &flow.DestinationDeviceID, &flow.MinPacketSize, &flow.MaxPacketSize, &packetRefsJson, &sourcePortsStr, &destinationPortsStr); err != nil {
			return nil, err
		}

		flow.SourcePorts = model2.NewSet()
		for _, port := range strings.Split(sourcePortsStr, ",") {
			if port != "" {
				flow.SourcePorts.Add(port)
			}
		}
		flow.DestinationPorts = model2.NewSet()
		for _, port := range strings.Split(destinationPortsStr, ",") {
			if port != "" {
				flow.DestinationPorts.Add(port)
			}
		}

		if err := json.Unmarshal([]byte(packetRefsJson), &flow.PacketRefs); err != nil {
			log.Printf("Error unmarshaling packet refs for flow ID %d: %v", flow.ID, err)
			flow.PacketRefs = make([]int64, 0) // Initialize to an empty map if unmarshaling fails
		}

		flow.FirstSeen, _ = time.Parse(time.RFC3339Nano, firstSeenStr)
		flow.LastSeen, _ = time.Parse(time.RFC3339Nano, lastSeenStr)

		flows = append(flows, &flow)
	}

	return flows, nil
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
		minPkt := flow.MinPacketSize
		maxPkt := flow.MaxPacketSize
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
	macAddresses := ""
	if device.MACAddressSet != nil {
		macAddresses = device.MACAddressSet.ToString()
	}

	_, err := r.db.Exec(
		`UPDATE devices SET address = ?, address_type = ?, first_seen = ?, last_seen = ?, address_sub_type = ?, address_scope = ?, mac_addresses = ?, additional_data = ? WHERE id = ?;`,
		device.Address,
		device.AddressType,
		device.FirstSeen.Format(time.RFC3339Nano),
		device.LastSeen.Format(time.RFC3339Nano),
		device.AddressSubType,
		device.AddressScope,
		macAddresses,
		device.AdditionalData,
		device.ID,
	)
	return err
}

// UpdatePacket updates an existing packet in the database by ID.
func (r *SQLiteRepository) UpdatePacket(packet *model2.Packet) error {
	if packet.ID == 0 {
		return errors.New("packet ID is required for update")
	}

	layersJSON, err := json.Marshal(packet.Layers)
	if err != nil {
		return err
	}

	protocolsJSON, err := json.Marshal(packet.Protocols)
	if err != nil {
		return err
	}

	_, err = r.db.Exec(
		`UPDATE packets SET timestamp = ?, length = ?, layers = ?, protocols = ? WHERE id = ?;`,
		packet.Timestamp.Format(time.RFC3339Nano),
		packet.Length,
		string(layersJSON),
		string(protocolsJSON),
		packet.ID,
	)
	return err
}

// UpsertPacket inserts a packet if it doesn't exist, or updates it if it exists.
func (r *SQLiteRepository) UpsertPacket(packet *model2.Packet) error {
	// If packet has ID, try to update first
	if packet.ID > 0 {
		// Check if packet exists
		var exists bool
		err := r.db.QueryRow("SELECT EXISTS(SELECT 1 FROM packets WHERE id = ?)", packet.ID).Scan(&exists)
		if err != nil {
			return err
		}

		if exists {
			return r.UpdatePacket(packet)
		}
	}

	// If packet doesn't exist or has no ID, insert it
	return r.AddPacket(packet)
}

// UpsertPackets inserts multiple packets in a single transaction, updating existing ones.
func (r *SQLiteRepository) UpsertPackets(packets []*model2.Packet) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Prepare insert statement
	insertStmt, err := tx.Prepare(`INSERT INTO packets (timestamp, length, layers, protocols) VALUES (?, ?, ?, ?);`)
	if err != nil {
		return err
	}
	defer insertStmt.Close()

	// Prepare update statement
	updateStmt, err := tx.Prepare(`UPDATE packets SET timestamp = ?, length = ?, layers = ?, protocols = ? WHERE id = ?;`)
	if err != nil {
		return err
	}
	defer updateStmt.Close()

	// Prepare check statement
	checkStmt, err := tx.Prepare("SELECT EXISTS(SELECT 1 FROM packets WHERE id = ?)")
	if err != nil {
		return err
	}
	defer checkStmt.Close()

	for _, packet := range packets {
		layersJSON, err := json.Marshal(packet.Layers)
		if err != nil {
			return err
		}

		protocolsJSON, err := json.Marshal(packet.Protocols)
		if err != nil {
			return err
		}

		// If packet has an ID, check if it exists
		if packet.ID > 0 {
			var exists bool
			err = checkStmt.QueryRow(packet.ID).Scan(&exists)
			if err != nil {
				return err
			}

			if exists {
				_, err = updateStmt.Exec(
					packet.Timestamp.Format(time.RFC3339Nano),
					packet.Length,
					string(layersJSON),
					string(protocolsJSON),
					packet.ID,
				)
				if err != nil {
					return err
				}
				continue
			}
		}

		// If packet doesn't exist or has no ID, insert it
		_, err = insertStmt.Exec(
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

// UpsertDevice inserts a device if it doesn't exist, or updates it if it exists.
func (r *SQLiteRepository) UpsertDevice(device *model2.Device) error {
	// Validate the device
	if err := device.Validate(); err != nil {
		return errors.Join(err, errors.New("invalid device data in function UpsertDevice"))
	}

	// Check if device exists by address
	existingDevice, err := r.GetDevice(device.Address)
	if err == nil && existingDevice != nil {
		// Device exists, update it
		device.ID = existingDevice.ID
		return r.UpdateDevice(device)
	}

	// Device doesn't exist or there was an error retrieving it, insert it
	return r.AddDevice(device)
}

// UpsertDevices inserts multiple devices in a single transaction, updating existing ones.
func (r *SQLiteRepository) UpsertDevices(devices []*model2.Device) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Prepare statements
	insertStmt, err := tx.Prepare(`INSERT INTO devices (address, address_type, first_seen, last_seen, address_sub_type, address_scope, mac_addresses, additional_data, is_only_destination) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);`)
	if err != nil {
		return err
	}
	defer insertStmt.Close()

	updateStmt, err := tx.Prepare(`UPDATE devices SET address_type = ?, first_seen = ?, last_seen = ?, address_sub_type = ?, address_scope = ?, mac_addresses = ?, additional_data = ?, is_only_destination = ? WHERE id = ?;`)
	if err != nil {
		return err
	}
	defer updateStmt.Close()

	checkStmt, err := tx.Prepare(`SELECT id FROM devices WHERE address = ?;`)
	if err != nil {
		return err
	}
	defer checkStmt.Close()

	for _, device := range devices {
		if err = device.Validate(); err != nil {
			return errors.Join(err, errors.New("invalid device data in for range of function UpsertDevice"))
		}

		// Check if device exists
		var deviceID int64
		err = checkStmt.QueryRow(device.Address).Scan(&deviceID)

		if err == nil {
			// Device exists, update it
			macs := ""
			if device.MACAddressSet != nil {
				macs = device.MACAddressSet.ToString()
			}

			_, err = updateStmt.Exec(
				device.AddressType,
				device.FirstSeen.Format(time.RFC3339Nano),
				device.LastSeen.Format(time.RFC3339Nano),
				device.AddressSubType,
				device.AddressScope,
				macs,
				device.AdditionalData,
				device.IsOnlyDestination,
				deviceID,
			)
			if err != nil {
				return err
			}
			device.ID = deviceID
		} else if err == sql.ErrNoRows {
			// Device doesn't exist, insert it
			macs := ""
			if device.MACAddressSet != nil {
				macs = device.MACAddressSet.ToString()
			}

			result, err := insertStmt.Exec(
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
		} else {
			// Other error
			return err
		}
	}

	return tx.Commit()
}

// UpdateService updates an existing service in the database by ID.
func (r *SQLiteRepository) UpdateService(service *model2.Service) error {
	if service.ID == 0 {
		return errors.New("service ID is required for update")
	}

	if err := service.Validate(); err != nil {
		return err
	}

	_, err := r.db.Exec(
		`UPDATE services SET ip = ?, port = ?, first_seen = ?, last_seen = ?, protocol = ? WHERE element_id = ?;`,
		service.IP,
		service.Port,
		service.FirstSeen.Format(time.RFC3339Nano),
		service.LastSeen.Format(time.RFC3339Nano),
		service.Protocol,
		service.ID,
	)
	return err
}

// UpdateFlow updates an existing flow in the database by ID.
func (r *SQLiteRepository) UpdateFlow(flow *model2.Flow) error {
	if flow.ID == 0 {
		return errors.New("flow ID is required for update")
	}

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
		log.Printf("Error getting source device for address %s: %v", srcAddress, err)
		return err
	}

	destDevice, err := r.GetDeviceForAddress(destAddress)
	if err != nil {
		log.Printf("Error getting destination device for address %s: %v", destAddress, err)
		return err
	}

	// Marshal packet references
	packetRefsJSON, err := json.Marshal(flow.PacketRefs)
	if err != nil {
		return err
	}

	// Prepare source and destination ports
	sourcePorts := ""
	destinationPorts := ""
	if flow.SourcePorts != nil {
		sourcePorts = flow.SourcePorts.ToString()
	}
	if flow.DestinationPorts != nil {
		destinationPorts = flow.DestinationPorts.ToString()
	}

	_, err = r.db.Exec(
		`UPDATE flows SET source = ?, destination = ?, protocol = ?, packets = ?, bytes = ?, 
		first_seen = ?, last_seen = ?, source_device_id = ?, destination_device_id = ?, 
		min_packet_size = ?, max_packet_size = ?, packet_refs = ?, source_ports = ?, destination_ports = ? 
		WHERE id = ?;`,
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
		sourcePorts,
		destinationPorts,
		flow.ID,
	)
	return err
}

// UpdateDeviceRelation updates an existing device relation in the database by ID.
func (r *SQLiteRepository) UpdateDeviceRelation(relation *model2.DeviceRelation) error {
	if relation.ID == 0 {
		return errors.New("device relation ID is required for update")
	}

	_, err := r.db.Exec(
		`UPDATE device_relations SET device_id_1 = ?, device_id_2 = ?, comment = ? WHERE id = ?;`,
		relation.DeviceID1,
		relation.DeviceID2,
		relation.Comment,
		relation.ID,
	)
	return err
}

// UpsertDeviceRelation inserts a device relation if it doesn't exist, or updates it if it exists.
func (r *SQLiteRepository) UpsertDeviceRelation(relation *model2.DeviceRelation) error {
	// Try to insert with UNIQUE constraint (will fail if relation with same device IDs exists)
	result, err := r.db.Exec(
		`INSERT OR IGNORE INTO device_relations (device_id_1, device_id_2, comment) VALUES (?, ?, ?);`,
		relation.DeviceID1,
		relation.DeviceID2,
		relation.Comment,
	)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	// If insert succeeded, get the new ID and return
	if rowsAffected > 0 {
		lastInsertID, err := result.LastInsertId()
		if err != nil {
			return err
		}
		relation.ID = lastInsertID
		return nil
	}

	// If no rows affected, it means the relation already exists, so update it
	// First find the existing relation ID
	var existingID int64
	err = r.db.QueryRow(
		"SELECT id FROM device_relations WHERE device_id_1 = ? AND device_id_2 = ?",
		relation.DeviceID1,
		relation.DeviceID2,
	).Scan(&existingID)
	if err != nil {
		return err
	}

	// Set the ID and update
	relation.ID = existingID
	return r.UpdateDeviceRelation(relation)
}

// UpdateDNSQuery updates an existing DNS query in the database by ID.
func (r *SQLiteRepository) UpdateDNSQuery(query *model2.DNSQuery) error {
	if query.ID == 0 {
		return errors.New("DNS query ID is required for update")
	}

	if err := query.Validate(); err != nil {
		return err
	}

	jsonQueryResult, err := json.Marshal(query.QueryResult)
	if err != nil {
		log.Printf("Error marshaling query result: %v", err)
		return err
	}

	_, err = r.db.Exec(
		`UPDATE dns_queries SET querying_device_id = ?, answering_device_id = ?, query_name = ?, query_type = ?, query_result = ?, timestamp = ? WHERE id = ?;`,
		query.QueryingDeviceID,
		query.AnsweringDeviceID,
		query.QueryName,
		query.QueryType,
		string(jsonQueryResult),
		query.Timestamp.Format(time.RFC3339Nano),
		query.ID,
	)
	return err
}

// UpsertDNSQuery inserts a DNS query if it doesn't exist, or updates it if it exists.
func (r *SQLiteRepository) UpsertDNSQuery(query *model2.DNSQuery) error {
	if err := query.Validate(); err != nil {
		return err
	}

	// For DNS queries we can't directly use the OR REPLACE approach because of the UNIQUE constraint
	// on multiple columns. Instead, we'll use the ID if provided to check if it exists.

	// If query has ID, try to update first
	if query.ID > 0 {
		// Check if query exists
		var exists bool
		err := r.db.QueryRow("SELECT EXISTS(SELECT 1 FROM dns_queries WHERE id = ?)", query.ID).Scan(&exists)
		if err != nil {
			return err
		}

		if exists {
			return r.UpdateDNSQuery(query)
		}
	}

	// Otherwise, check if a query with the same unique identifiers exists
	var existingID int64
	jsonQueryResult, err := json.Marshal(query.QueryResult)
	if err != nil {
		log.Printf("Error marshaling query result: %v", err)
		return err
	}

	err = r.db.QueryRow(
		`SELECT id FROM dns_queries WHERE querying_device_id = ? AND answering_device_id = ? 
		AND query_name = ? AND query_type = ? AND query_result = ? AND timestamp = ?`,
		query.QueryingDeviceID,
		query.AnsweringDeviceID,
		query.QueryName,
		query.QueryType,
		string(jsonQueryResult),
		query.Timestamp.Format(time.RFC3339Nano),
	).Scan(&existingID)

	if err == nil {
		// Query exists, update it
		query.ID = existingID
		return r.UpdateDNSQuery(query)
	} else if err == sql.ErrNoRows {
		// Query doesn't exist, insert it
		return r.AddDNSQuery(query)
	} else {
		// Other error
		return err
	}
}

// UpsertDNSQueries inserts multiple DNS queries in a single transaction, updating existing ones.
func (r *SQLiteRepository) UpsertDNSQueries(queries []*model2.DNSQuery) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Prepare statements
	insertStmt, err := tx.Prepare(`INSERT INTO dns_queries (querying_device_id, answering_device_id, query_name, query_type, query_result, timestamp) VALUES (?, ?, ?, ?, ?, ?);`)
	if err != nil {
		return err
	}
	defer insertStmt.Close()

	updateStmt, err := tx.Prepare(`UPDATE dns_queries SET querying_device_id = ?, answering_device_id = ?, query_name = ?, query_type = ?, query_result = ?, timestamp = ? WHERE id = ?;`)
	if err != nil {
		return err
	}
	defer updateStmt.Close()

	// Prepare check statement for ID
	checkByIDStmt, err := tx.Prepare("SELECT EXISTS(SELECT 1 FROM dns_queries WHERE id = ?)")
	if err != nil {
		return err
	}
	defer checkByIDStmt.Close()

	// Prepare check statement for unique combination
	checkByUniqueStmt, err := tx.Prepare(`SELECT id FROM dns_queries WHERE querying_device_id = ? AND answering_device_id = ? AND query_name = ? AND query_type = ? AND query_result = ? AND timestamp = ?`)
	if err != nil {
		return err
	}
	defer checkByUniqueStmt.Close()

	for _, query := range queries {
		if err := query.Validate(); err != nil {
			continue // Skip invalid queries
		}

		jsonQueryResult, err := json.Marshal(query.QueryResult)
		if err != nil {
			log.Printf("Error marshaling query result: %v", err)
			continue
		}

		// Check if query has an ID and exists
		var exists bool = false
		var existingID int64 = 0

		if query.ID > 0 {
			err = checkByIDStmt.QueryRow(query.ID).Scan(&exists)
			if err != nil {
				return err
			}

			if exists {
				existingID = query.ID
			}
		}

		// If no ID or ID not found, check by unique combination
		if !exists {
			err = checkByUniqueStmt.QueryRow(
				query.QueryingDeviceID,
				query.AnsweringDeviceID,
				query.QueryName,
				query.QueryType,
				string(jsonQueryResult),
				query.Timestamp.Format(time.RFC3339Nano),
			).Scan(&existingID)

			if err == nil {
				exists = true
			} else if err != sql.ErrNoRows {
				// Real error, not just "not found"
				return err
			}
		}

		if exists {
			// Update existing query
			_, err = updateStmt.Exec(
				query.QueryingDeviceID,
				query.AnsweringDeviceID,
				query.QueryName,
				query.QueryType,
				string(jsonQueryResult),
				query.Timestamp.Format(time.RFC3339Nano),
				existingID,
			)
			if err != nil {
				return err
			}
			query.ID = existingID
		} else {
			// Insert new query
			result, err := insertStmt.Exec(
				query.QueryingDeviceID,
				query.AnsweringDeviceID,
				query.QueryName,
				query.QueryType,
				string(jsonQueryResult),
				query.Timestamp.Format(time.RFC3339Nano),
			)
			if err != nil {
				// Check if it's a constraint violation (entry already exists)
				if sqliteErr, ok := err.(sqlite3.Error); ok && sqliteErr.Code == sqlite3.ErrConstraint {
					continue // Skip if already exists due to unique constraint
				}
				return err
			}

			lastInsertID, err := result.LastInsertId()
			if err != nil {
				return err
			}
			query.ID = lastInsertID
		}
	}

	return tx.Commit()
}

// AllDevices returns all devices from the database.
func (r *SQLiteRepository) AllDevices() ([]*model2.Device, error) {
	query := `SELECT id, address, address_type, first_seen, last_seen, address_sub_type, address_scope, mac_addresses, additional_data, is_only_destination FROM devices`
	rows, err := r.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []*model2.Device
	for rows.Next() {
		var device model2.Device
		var firstSeenStr, lastSeenStr, macAddressesStr string

		if err := rows.Scan(&device.ID, &device.Address, &device.AddressType, &firstSeenStr, &lastSeenStr,
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

		devices = append(devices, &device)
	}

	return devices, nil
}

// AllFlows returns all flows from the database.
func (r *SQLiteRepository) AllFlows() ([]*model2.Flow, error) {
	query := `SELECT id, source, destination, protocol, packets, bytes, first_seen, last_seen, source_device_id, destination_device_id, 
	          min_packet_size, max_packet_size, packet_refs, source_ports, destination_ports FROM flows`
	rows, err := r.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var flows []*model2.Flow
	for rows.Next() {
		var flow model2.Flow
		var firstSeenStr, lastSeenStr, packetRefsStr, sourcePortsStr, destPortsStr string
		var minPacketSizeSQL, maxPacketSizeSQL sql.NullInt64
		var sourceDeviceID, destDeviceID sql.NullInt64

		if err := rows.Scan(&flow.ID, &flow.Source, &flow.Destination, &flow.Protocol, &flow.Packets, &flow.Bytes,
			&firstSeenStr, &lastSeenStr, &sourceDeviceID, &destDeviceID, &minPacketSizeSQL, &maxPacketSizeSQL,
			&packetRefsStr, &sourcePortsStr, &destPortsStr); err != nil {
			return nil, err
		}

		flow.FirstSeen, _ = time.Parse(time.RFC3339Nano, firstSeenStr)
		flow.LastSeen, _ = time.Parse(time.RFC3339Nano, lastSeenStr)

		if minPacketSizeSQL.Valid {
			minSize := int(minPacketSizeSQL.Int64)
			flow.MinPacketSize = minSize
		}
		if maxPacketSizeSQL.Valid {
			maxSize := int(maxPacketSizeSQL.Int64)
			flow.MaxPacketSize = maxSize
		}

		// Parse packet references
		if packetRefsStr != "" {
			var packetRefs []int64
			if err := json.Unmarshal([]byte(packetRefsStr), &packetRefs); err != nil {
				log.Printf("Error parsing packet refs: %v", err)
			} else {
				flow.PacketRefs = packetRefs
			}
		}

		// Parse ports
		flow.SourcePorts = model2.NewSet()
		flow.DestinationPorts = model2.NewSet()

		if sourcePortsStr != "" {
			for _, port := range strings.Split(sourcePortsStr, ",") {
				flow.SourcePorts.Add(port)
			}
		}

		if destPortsStr != "" {
			for _, port := range strings.Split(destPortsStr, ",") {
				flow.DestinationPorts.Add(port)
			}
		}

		flows = append(flows, &flow)
	}

	return flows, nil
}

// UpsertService inserts a service if it doesn't exist, or updates it if it exists.
func (r *SQLiteRepository) UpsertService(service *model2.Service) error {
	if err := service.Validate(); err != nil {
		return err
	}

	// Check if service exists by IP, port, and protocol
	var serviceID int64
	err := r.db.QueryRow(
		`SELECT element_id FROM services WHERE ip = ? AND port = ? AND protocol = ?`,
		service.IP, service.Port, service.Protocol,
	).Scan(&serviceID)

	if err == nil {
		// Service exists, update it
		service.ID = serviceID
		return r.UpdateService(service)
	} else if err == sql.ErrNoRows {
		// Service doesn't exist, insert it
		result, err := r.db.Exec(
			`INSERT INTO services (ip, port, first_seen, last_seen, protocol) VALUES (?, ?, ?, ?, ?);`,
			service.IP,
			service.Port,
			service.FirstSeen.Format(time.RFC3339Nano),
			service.LastSeen.Format(time.RFC3339Nano),
			service.Protocol,
		)
		if err != nil {
			return err
		}

		lastInsertID, err := result.LastInsertId()
		if err != nil {
			return err
		}
		service.ID = lastInsertID
		return nil
	}

	// Other error
	return err
}

// UpsertServices inserts multiple services in a single transaction, updating existing ones.
func (r *SQLiteRepository) UpsertServices(services []*model2.Service) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Prepare statements
	insertStmt, err := tx.Prepare(`INSERT INTO services (ip, port, first_seen, last_seen, protocol) VALUES (?, ?, ?, ?, ?);`)
	if err != nil {
		return err
	}
	defer insertStmt.Close()

	updateStmt, err := tx.Prepare(`UPDATE services SET first_seen = ?, last_seen = ?, protocol = ? WHERE element_id = ?;`)
	if err != nil {
		return err
	}
	defer updateStmt.Close()

	checkStmt, err := tx.Prepare(`SELECT element_id FROM services WHERE ip = ? AND port = ? AND protocol = ?`)
	if err != nil {
		return err
	}
	defer checkStmt.Close()

	for _, service := range services {
		if err := service.Validate(); err != nil {
			return err
		}

		// Check if service exists
		var serviceID int64
		err = checkStmt.QueryRow(service.IP, service.Port, service.Protocol).Scan(&serviceID)

		if err == nil {
			// Service exists, update it
			_, err = updateStmt.Exec(
				service.FirstSeen.Format(time.RFC3339Nano),
				service.LastSeen.Format(time.RFC3339Nano),
				service.Protocol,
				serviceID,
			)
			if err != nil {
				return err
			}
			service.ID = serviceID
		} else if err == sql.ErrNoRows {
			// Service doesn't exist, insert it
			result, err := insertStmt.Exec(
				service.IP,
				service.Port,
				service.FirstSeen.Format(time.RFC3339Nano),
				service.LastSeen.Format(time.RFC3339Nano),
				service.Protocol,
			)
			if err != nil {
				return err
			}

			lastInsertID, err := result.LastInsertId()
			if err != nil {
				return err
			}
			service.ID = lastInsertID
		} else {
			// Other error
			return err
		}
	}

	return tx.Commit()
}

// UpsertFlow inserts a flow if it doesn't exist, or updates it if it exists.
func (r *SQLiteRepository) UpsertFlow(flow *model2.Flow) error {
	if err := flow.Validate(); err != nil {
		return err
	}

	// If flow has ID, try to update it
	if flow.ID > 0 {
		var exists bool
		err := r.db.QueryRow("SELECT EXISTS(SELECT 1 FROM flows WHERE id = ?)", flow.ID).Scan(&exists)
		if err != nil {
			return err
		}

		if exists {
			return r.UpdateFlow(flow)
		}
	}

	// Try to find existing flow by source, destination, and protocol
	var flowID int64
	err := r.db.QueryRow(
		`SELECT id FROM flows WHERE source = ? AND destination = ? AND protocol = ?`,
		flow.Source, flow.Destination, flow.Protocol,
	).Scan(&flowID)

	if err == nil {
		// Flow exists, update it
		flow.ID = flowID
		return r.UpdateFlow(flow)
	} else if err == sql.ErrNoRows {
		// Flow doesn't exist, insert it
		return r.AddFlow(flow)
	}

	// Other error
	return err
}

// UpsertFlows inserts multiple flows in a single transaction, updating existing ones.
func (r *SQLiteRepository) UpsertFlows(flows []*model2.Flow) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, flow := range flows {
		if err := flow.Validate(); err != nil {
			return err
		}

		// Check if flow exists
		var flowID int64
		if flow.ID > 0 {
			var exists bool
			err := tx.QueryRow("SELECT EXISTS(SELECT 1 FROM flows WHERE id = ?)", flow.ID).Scan(&exists)
			if err != nil {
				return err
			}

			if exists {
				flowID = flow.ID
			}
		}

		if flowID == 0 {
			// Check by source, destination, and protocol
			err := tx.QueryRow(
				`SELECT id FROM flows WHERE source = ? AND destination = ? AND protocol = ?`,
				flow.Source, flow.Destination, flow.Protocol,
			).Scan(&flowID)

			if err != nil && err != sql.ErrNoRows {
				return err
			}
		}

		if flowID > 0 {
			// Flow exists, update it
			flow.ID = flowID

			// Get source and destination device IDs
			srcAddress, err := model2.ExtractIPAddress(flow.Source)
			if srcAddress == "" || err != nil {
				return errors.New("invalid source address")
			}
			destAddress, err := model2.ExtractIPAddress(flow.Destination)
			if destAddress == "" || err != nil {
				return errors.New("invalid destination address")
			}

			var srcDeviceID, destDeviceID int64
			err = tx.QueryRow("SELECT id FROM devices WHERE address = ?", srcAddress).Scan(&srcDeviceID)
			if err != nil {
				return err
			}

			err = tx.QueryRow("SELECT id FROM devices WHERE address = ?", destAddress).Scan(&destDeviceID)
			if err != nil {
				return err
			}

			// Marshal packet references and prepare port strings
			packetRefsJSON, err := json.Marshal(flow.PacketRefs)
			if err != nil {
				return err
			}

			sourcePorts := ""
			if flow.SourcePorts != nil {
				sourcePorts = flow.SourcePorts.ToString()
			}

			destinationPorts := ""
			if flow.DestinationPorts != nil {
				destinationPorts = flow.DestinationPorts.ToString()
			}

			// Update the flow
			_, err = tx.Exec(
				`UPDATE flows SET source = ?, destination = ?, protocol = ?, packets = ?, bytes = ?,
				first_seen = ?, last_seen = ?, source_device_id = ?, destination_device_id = ?,
				min_packet_size = ?, max_packet_size = ?, packet_refs = ?, source_ports = ?, destination_ports = ?
				WHERE id = ?;`,
				flow.Source,
				flow.Destination,
				flow.Protocol,
				flow.Packets,
				flow.Bytes,
				flow.FirstSeen.Format(time.RFC3339Nano),
				flow.LastSeen.Format(time.RFC3339Nano),
				srcDeviceID,
				destDeviceID,
				flow.MinPacketSize,
				flow.MaxPacketSize,
				string(packetRefsJSON),
				sourcePorts,
				destinationPorts,
				flowID,
			)
			if err != nil {
				return err
			}
		} else {
			// Flow doesn't exist, insert it

			// Get source and destination device IDs
			srcAddress, err := model2.ExtractIPAddress(flow.Source)
			if srcAddress == "" || err != nil {
				return errors.New("invalid source address")
			}
			destAddress, err := model2.ExtractIPAddress(flow.Destination)
			if destAddress == "" || err != nil {
				return errors.New("invalid destination address")
			}

			// Marshal packet references and prepare port strings
			packetRefsJSON, err := json.Marshal(flow.PacketRefs)
			if err != nil {
				return err
			}

			sourcePorts := ""
			if flow.SourcePorts != nil {
				sourcePorts = flow.SourcePorts.ToString()
			}

			destinationPorts := ""
			if flow.DestinationPorts != nil {
				destinationPorts = flow.DestinationPorts.ToString()
			}

			minPkt := flow.MinPacketSize
			maxPkt := flow.MaxPacketSize

			// Insert the new flow
			result, err := tx.Exec(
				`INSERT INTO flows (source, destination, protocol, packets, bytes, first_seen, last_seen, 
				min_packet_size, max_packet_size, packet_refs, source_ports, destination_ports, 
				source_device_id, destination_device_id) 
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 
				(SELECT id FROM devices WHERE address = ?), 
				(SELECT id FROM devices WHERE address = ?));`,
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
				srcAddress,
				destAddress,
			)
			if err != nil {
				return err
			}

			lastInsertID, err := result.LastInsertId()
			if err != nil {
				return err
			}
			flow.ID = lastInsertID
		}
	}

	return tx.Commit()
}

func (r *SQLiteRepository) AddSSDPQuery(query *model2.SSDPQuery) error {
	if err := query.Validate(); err != nil {
		return err
	}

	// Insert the SSDP query
	result, err := r.db.Exec(
		`INSERT INTO ssdp_queries (querying_device_id, query_type, st, user_agent) VALUES (?, ?, ?, ?);`,
		query.QueryingDeviceID,
		query.QueryType,
		query.ST,
		query.UserAgent,
	)
	if err != nil {
		return err
	}

	lastInsertID, err := result.LastInsertId()
	if err != nil {
		return err
	}
	query.ID = lastInsertID

	return nil
}

func (r *SQLiteRepository) UpdateSSDPQuery(query *model2.SSDPQuery) error {
	if query.ID == 0 {
		return errors.New("SSDP query ID is required for update")
	}

	if err := query.Validate(); err != nil {
		return err
	}

	// Query exists, update it
	_, err := r.db.Exec(
		`UPDATE ssdp_queries SET st = ?, user_agent = ? WHERE id = ?;`,
		query.ST,
		query.UserAgent,
		query.ID)

	return err
}

func (r *SQLiteRepository) UpsertSSDPQuery(query *model2.SSDPQuery) error {
	if err := query.Validate(); err != nil {
		return err
	}

	if query.ID > 0 {
		var exists bool
		err := r.db.QueryRow("SELECT EXISTS(SELECT 1 FROM ssdp_queries WHERE id = ?)", query.ID).Scan(&exists)
		if err != nil {
			return err
		}

		if exists {
			return r.UpdateSSDPQuery(query)
		}
	}

	// Check if query exists by device ID and search target
	var existingID int64
	err := r.db.QueryRow(
		`SELECT id FROM ssdp_queries WHERE querying_device_id = ? AND query_type = ?`,
		query.QueryingDeviceID, query.QueryType,
	).Scan(&existingID)

	if err == nil {
		query.ID = existingID
		return r.UpdateSSDPQuery(query)
	} else if errors.Is(err, sql.ErrNoRows) {
		// Flow doesn't exist, insert it
		return r.AddSSDPQuery(query)
	}

	// Other error
	return err
}

// UpsertSSDPQueries inserts multiple SSDP queries in a single transaction, updating existing ones.
func (r *SQLiteRepository) UpsertSSDPQueries(queries []*model2.SSDPQuery) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Prepare insert statement
	insertStmt, err := tx.Prepare(`INSERT INTO ssdp_queries (querying_device_id, query_type, st, user_agent) VALUES (?, ?, ?, ?);`)
	if err != nil {
		return err
	}
	defer insertStmt.Close()

	// Prepare update statement
	updateStmt, err := tx.Prepare(`UPDATE ssdp_queries SET st = ?, user_agent = ? WHERE id = ?;`)
	if err != nil {
		return err
	}
	defer updateStmt.Close()

	// Prepare check statement for ID
	checkByIDStmt, err := tx.Prepare("SELECT EXISTS(SELECT 1 FROM ssdp_queries WHERE id = ?)")
	if err != nil {
		return err
	}
	defer checkByIDStmt.Close()

	// Prepare check statement for unique combination
	checkByUniqueStmt, err := tx.Prepare(`SELECT id FROM ssdp_queries WHERE querying_device_id = ? AND query_type = ?`)
	if err != nil {
		return err
	}
	defer checkByUniqueStmt.Close()

	for _, query := range queries {
		if err := query.Validate(); err != nil {
			continue // Skip invalid queries
		}

		// If query has an ID, check if it exists
		var exists bool = false
		var existingID int64 = 0

		if query.ID > 0 {
			err = checkByIDStmt.QueryRow(query.ID).Scan(&exists)
			if err != nil {
				return err
			}

			if exists {
				existingID = query.ID
			}
		}

		if !exists {
			err = checkByUniqueStmt.QueryRow(query.QueryingDeviceID, query.QueryType).Scan(&existingID)

			if err == nil {
				exists = true
			} else if errors.Is(err, sql.ErrNoRows) {
				exists = false
			} else {
				return err
			}
		}

		if exists {
			query.ID = existingID
			// Update existing query
			_, err = updateStmt.Exec(
				query.ST,
				query.UserAgent,
				query.ID,
			)
			if err != nil {
				return err
			}
		} else { // Insert new query
			result, err := insertStmt.Exec(
				query.QueryingDeviceID,
				query.QueryType,
				query.ST,
				query.UserAgent,
			)
			if err != nil {
				// Check if it's a constraint violation (entry already exists)
				if sqliteErr, ok := err.(sqlite3.Error); ok && sqliteErr.Code == sqlite3.ErrConstraint {
					continue // Skip if already exists due to unique constraint
				}
				return err
			}

			lastInsertID, err := result.LastInsertId()
			if err != nil {
				return err
			}
			query.ID = lastInsertID
		}
	}
	return tx.Commit()
}
