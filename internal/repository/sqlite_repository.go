package repository

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/InfraSecConsult/pcap-importer-go/lib/helper"
	model2 "github.com/InfraSecConsult/pcap-importer-go/lib/model"
	sqlite3 "github.com/mattn/go-sqlite3"
)

type SQLiteRepository struct {
	db *sql.DB
	// Flow canonicalizer for determining canonical flow direction
	flowCanonicalizer helper.FlowCanonicalizer
	// Error handler for graceful degradation
	errorHandler FlowErrorHandler
}

func NewSQLiteRepository(path string) (*SQLiteRepository, error) {
	// use default canonicalizer
	return NewSQLiteRepositoryWithCanonicalizer(path, helper.NewFlowCanonicalizer())
}

func NewSQLiteRepositoryWithCanonicalizer(path string, canonicalizer helper.FlowCanonicalizer) (*SQLiteRepository, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}
	repo := &SQLiteRepository{
		db:                db,
		flowCanonicalizer: canonicalizer,
		errorHandler:      &DefaultFlowErrorHandler{},
	}
	if err := repo.createTables(); err != nil {
		return nil, err
	}
	return repo, nil
}

func (r *SQLiteRepository) createTables() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS packets (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			tenant_id TEXT,
			flow_id INTEGER,
			timestamp TEXT NOT NULL,
			src_ip TEXT,
			dst_ip TEXT,
			src_port INTEGER,
			dst_port INTEGER,
			protocol TEXT,
			length INTEGER NOT NULL,
			flags TEXT,
			payload BLOB,
			layers TEXT NOT NULL,
			protocols TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS devices (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			tenant_id TEXT,
			address TEXT NOT NULL,
			address_type TEXT NOT NULL,
			address_sub_type TEXT,
			address_scope TEXT,
			mac_addresses TEXT,
			additional_data TEXT,
			protocol_list TEXT,
			dns_names TEXT,
			hostname TEXT,
			device_type TEXT,
			vendor TEXT,
			os TEXT,
			first_seen TEXT,
			last_seen TEXT,
			is_router BOOLEAN,
			is_only_destination BOOLEAN,
			is_external BOOLEAN,
			confidence REAL,
			description TEXT
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
			tenant_id TEXT,
			src_ip TEXT NOT NULL,
			dst_ip TEXT NOT NULL,
			src_port INTEGER,
			dst_port INTEGER,
			protocol TEXT NOT NULL,
			packet_count INTEGER NOT NULL,
			byte_count INTEGER NOT NULL,
			first_seen TEXT NOT NULL,
			last_seen TEXT NOT NULL,
			duration REAL,
			source_device_id INTEGER,
			destination_device_id INTEGER,
			min_packet_size INTEGER,
			max_packet_size INTEGER,
			packet_refs TEXT,
			source_ports TEXT,
			destination_ports TEXT,
			-- Bidirectional statistics
			packets_client_to_server INTEGER NOT NULL DEFAULT 0,
			packets_server_to_client INTEGER NOT NULL DEFAULT 0,
			bytes_client_to_server INTEGER NOT NULL DEFAULT 0,
			bytes_server_to_client INTEGER NOT NULL DEFAULT 0,
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
			created_at DATETIME NOT NULL
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
		`CREATE INDEX IF NOT EXISTS idx_flows_canonical ON flows(src_ip, dst_ip, protocol);`,
		`CREATE INDEX IF NOT EXISTS idx_flows_reverse_lookup ON flows(dst_ip, src_ip, protocol);`,
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

// Helper for converting net.IP to string for DB stores
func ipToString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

// Helper for converting DB string to net.IP
func stringToIP(s string) net.IP {
	if s == "" {
		return nil
	}
	return net.ParseIP(s)
}

func sliceToJSON(slice []string) string {
	if len(slice) == 0 {
		return ""
	}
	b, err := json.Marshal(slice)
	if err != nil {
		return ""
	}
	return string(b)
}

func (r *SQLiteRepository) AddPacket(packet *model2.Packet) error {
	layersJSON, _ := json.Marshal(packet.Layers)
	protocolsJSON, _ := json.Marshal(packet.Protocols)
	_, err := r.db.Exec(
		`INSERT INTO packets (tenant_id, flow_id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, flags, payload, layers, protocols) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`,
		nil,
		packet.FlowID,
		packet.Timestamp.Format(time.RFC3339Nano),
		ipToString(packet.SrcIP),
		ipToString(packet.DstIP),
		packet.SrcPort,
		packet.DstPort,
		packet.Protocol,
		packet.Length,
		packet.Flags,
		packet.Payload,
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
	macAddressesList := device.MACAddressSet.ToString()

	_, err := r.db.Exec(
		`INSERT INTO devices (tenant_id, address, address_type, first_seen, last_seen, address_sub_type, address_scope, mac_addresses, additional_data, protocol_list, dns_names, hostname, device_type, vendor, os, is_router, is_only_destination, is_external, confidence, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`,
		device.TenantID,
		device.Address,
		device.AddressType,
		device.FirstSeen.Format(time.RFC3339Nano),
		device.LastSeen.Format(time.RFC3339Nano),
		device.AddressSubType,
		device.AddressScope,
		macAddressesList,
		device.AdditionalData,
		sliceToJSON(device.ProtocolList),
		sliceToJSON(device.DNSNames),
		device.Hostname,
		device.DeviceType,
		device.Vendor,
		device.OS,
		device.IsRouter,
		device.IsOnlyDestination,
		device.IsExternal,
		device.Confidence,
		device.Description,
	)
	return err
}

func (r *SQLiteRepository) GetDevice(address string) (*model2.Device, error) {
	query := `SELECT id, tenant_id, address, address_type, first_seen, last_seen, address_sub_type, address_scope, mac_addresses, additional_data, protocol_list, dns_names, hostname, device_type, vendor, os, is_router, is_only_destination, is_external, confidence, description FROM devices WHERE address = ?`
	row := r.db.QueryRow(query, address)

	var device model2.Device
	var firstSeenStr, lastSeenStr, macAddressesStr, protocolListStr, dnsNamesStr, hostname, deviceType, vendor, os string
	var tenantID sql.NullString
	var isRouter, isOnlyDestination, isExternal sql.NullBool
	var confidence sql.NullFloat64
	var description sql.NullString

	if err := row.Scan(&device.ID, &tenantID, &device.Address, &device.AddressType, &firstSeenStr, &lastSeenStr,
		&device.AddressSubType, &device.AddressScope, &macAddressesStr, &device.AdditionalData, &protocolListStr, &dnsNamesStr, &hostname, &deviceType, &vendor, &os, &isRouter, &isOnlyDestination, &isExternal, &confidence, &description); err != nil {
		return nil, err
	}

	device.FirstSeen, _ = time.Parse(time.RFC3339Nano, firstSeenStr)
	device.LastSeen, _ = time.Parse(time.RFC3339Nano, lastSeenStr)

	device.MACAddressSet = model2.NewMACAddressSet()
	// Try to unmarshal as JSON array first
	var macs []string
	if macAddressesStr != "" {
		if err := json.Unmarshal([]byte(macAddressesStr), &macs); err != nil {
			// fallback to comma-separated list
			macs = strings.Split(macAddressesStr, ",")
		}
	}
	// Convert macs into MACAddressSet in device
	for _, mac := range macs {
		if mac != "" && device.MACAddressSet != nil {
			device.MACAddressSet.Add(mac)
		}
	}
	for _, mac := range macs {
		if mac != "" && device.MACAddressSet != nil {
			device.MACAddressSet.Add(mac)
		}
	}
	device.ProtocolList = jsonArrayToSlice(protocolListStr)
	device.DNSNames = jsonArrayToSlice(dnsNamesStr)
	device.Hostname = hostname
	device.DeviceType = deviceType
	device.Vendor = vendor
	device.OS = os
	if tenantID.Valid {
		device.TenantID = tenantID.String
	}
	if isRouter.Valid {
		device.IsRouter = isRouter.Bool
	}
	if isOnlyDestination.Valid {
		device.IsOnlyDestination = isOnlyDestination.Bool
	}
	if isExternal.Valid {
		device.IsExternal = isExternal.Bool
	}
	if confidence.Valid {
		device.Confidence = confidence.Float64
	}
	if description.Valid {
		device.Description = description.String
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
	if flow.SrcIP == nil || flow.SrcIP.String() == "" {
		return errors.New("invalid source address")
	}
	srcAddress := flow.SrcIP.String()
	srcAddress, err := model2.ExtractIPAddress(srcAddress)
	if srcAddress == "" || err != nil {
		return errors.New("invalid source address")
	}
	if flow.DstIP == nil || flow.DstIP.String() == "" {
		return errors.New("invalid destination address")
	}
	destAddress := flow.DstIP.String()
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

	if flow.Duration <= 0 {
		flow.Duration = float64(flow.LastSeen.Sub(flow.FirstSeen).Milliseconds())
	}

	// AddFlow: include bidirectional columns
	packetRefsJSON, _ := json.Marshal(flow.PacketRefs)
	result, err := r.db.Exec(
		`INSERT INTO flows (tenant_id, src_ip, dst_ip, src_port, dst_port, protocol, packet_count, byte_count, first_seen, last_seen, duration, source_device_id, destination_device_id, min_packet_size, max_packet_size, packet_refs, source_ports, destination_ports, packets_client_to_server, packets_server_to_client, bytes_client_to_server, bytes_server_to_client) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`,
		flow.TenantID,
		ipToString(flow.SrcIP),
		ipToString(flow.DstIP),
		flow.SrcPort,
		flow.DstPort,
		flow.Protocol,
		flow.PacketCount,
		flow.ByteCount,
		flow.FirstSeen.Format(time.RFC3339Nano),
		flow.LastSeen.Format(time.RFC3339Nano),
		flow.Duration,
		srcDevice.ID,
		destDevice.ID,
		flow.MinPacketSize,
		flow.MaxPacketSize,
		string(packetRefsJSON),
		flow.SourcePorts.ToString(),
		flow.DestinationPorts.ToString(),
		flow.PacketsClientToServer,
		flow.PacketsServerToClient,
		flow.BytesClientToServer,
		flow.BytesServerToClient,
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
	query := `SELECT id, tenant_id, src_ip, dst_ip, src_port, dst_port, protocol, packet_count, byte_count, first_seen, last_seen, duration, source_device_id, destination_device_id, min_packet_size, max_packet_size, packet_refs, source_ports, destination_ports, packets_client_to_server, packets_server_to_client, bytes_client_to_server, bytes_server_to_client FROM flows`
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
		var srcIPStr, dstIPStr string
		var srcPortInt, dstPortInt sql.NullInt64
		var packetCountInt, byteCountInt sql.NullInt64
		var durationFloat sql.NullFloat64
		var tenantID sql.NullString
		var flow model2.Flow

		if err := rows.Scan(&flow.ID, &tenantID, &srcIPStr, &dstIPStr, &srcPortInt, &dstPortInt, &flow.Protocol, &packetCountInt, &byteCountInt, &firstSeenStr, &lastSeenStr, &durationFloat, &flow.SourceDeviceID, &flow.DestinationDeviceID, &flow.MinPacketSize, &flow.MaxPacketSize, &packetRefsJson, &sourcePortsStr, &destinationPortsStr, &flow.PacketsClientToServer, &flow.PacketsServerToClient, &flow.BytesClientToServer, &flow.BytesServerToClient); err != nil {
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
		flow.SrcIP = stringToIP(srcIPStr)
		flow.DstIP = stringToIP(dstIPStr)
		if srcPortInt.Valid {
			flow.SrcPort = int(srcPortInt.Int64)
		}
		if dstPortInt.Valid {
			flow.DstPort = int(dstPortInt.Int64)
		}
		if packetCountInt.Valid {
			flow.PacketCount = int(packetCountInt.Int64)
		}
		if byteCountInt.Valid {
			flow.ByteCount = int64(byteCountInt.Int64)
		}
		if durationFloat.Valid {
			flow.Duration = durationFloat.Float64
		}
		if tenantID.Valid {
			flow.TenantID = tenantID.String
		}

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
		service.IP.String(),
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
			IP:        net.ParseIP(ip),
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

	stmt, err := tx.Prepare(`INSERT INTO packets (flow_id, src_ip, src_port, dst_ip, dst_port, timestamp, length, layers, protocols) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);`)
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
			packet.FlowID,
			ipToString(packet.SrcIP),
			packet.SrcPort,
			ipToString(packet.DstIP),
			packet.DstPort,
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

	stmt, err := tx.Prepare(`INSERT INTO flows (tenant_id, src_ip, dst_ip, src_port, dst_port, protocol, packet_count, byte_count, first_seen, last_seen, duration, min_packet_size, max_packet_size, packet_refs, source_ports, destination_ports, packets_client_to_server, packets_server_to_client, bytes_client_to_server, bytes_server_to_client, source_device_id, destination_device_id)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, (
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
			flow.TenantID,
			ipToString(flow.SrcIP),
			ipToString(flow.DstIP),
			flow.SrcPort,
			flow.DstPort,
			flow.Protocol,
			flow.PacketCount,
			flow.ByteCount,
			flow.FirstSeen.Format(time.RFC3339Nano),
			flow.LastSeen.Format(time.RFC3339Nano),
			flow.Duration,
			minPkt,
			maxPkt,
			string(packetRefsJSON),
			sourcePorts,
			destinationPorts,
			flow.PacketsClientToServer,
			flow.PacketsServerToClient,
			flow.BytesClientToServer,
			flow.BytesServerToClient,
			ipToString(flow.SrcIP),
			ipToString(flow.DstIP),
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
		if err = service.Validate(); err != nil {
			return err
		}

		_, err = stmt.Exec(
			service.IP.String(),
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
	insertStmt, err := tx.Prepare(`INSERT INTO packets (flow_id, src_ip, src_port, dst_ip, dst_port, timestamp, length, layers, protocols) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);`)
	if err != nil {
		return err
	}
	defer insertStmt.Close()

	// Prepare update statement
	updateStmt, err := tx.Prepare(`UPDATE packets SET flow_id = ?, src_ip = ?, src_port = ?, dst_ip = ?, dst_port = ?, timestamp = ?, length = ?, layers = ?, protocols = ? WHERE id = ?;`)
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
					packet.FlowID,
					ipToString(packet.SrcIP),
					packet.SrcPort,
					ipToString(packet.DstIP),
					packet.DstPort,
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
			packet.FlowID,
			ipToString(packet.SrcIP),
			packet.SrcPort,
			ipToString(packet.DstIP),
			packet.DstPort,
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
		service.IP.String(),
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
	srcAddress := ipToString(flow.SrcIP)
	srcAddress, err := model2.ExtractIPAddress(srcAddress)
	if srcAddress == "" || err != nil {
		return errors.New("invalid source address")
	}
	destAddress := ipToString(flow.DstIP)
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
		`UPDATE flows SET src_ip = ?, dst_ip = ?, src_port = ?, dst_port = ?, protocol = ?, packet_count = ?, byte_count = ?,
		first_seen = ?, last_seen = ?, duration = ?, source_device_id = ?, destination_device_id = ?,
		min_packet_size = ?, max_packet_size = ?, packet_refs = ?, source_ports = ?, destination_ports = ?, packets_client_to_server = ?, packets_server_to_client = ?, bytes_client_to_server = ?, bytes_server_to_client = ?
		WHERE id = ?;`,
		ipToString(flow.SrcIP),
		ipToString(flow.DstIP),
		flow.SrcPort,
		flow.DstPort,
		flow.Protocol,
		flow.PacketCount,
		flow.ByteCount,
		flow.FirstSeen.Format(time.RFC3339Nano),
		flow.LastSeen.Format(time.RFC3339Nano),
		flow.Duration,
		srcDevice.ID,
		destDevice.ID,
		flow.MinPacketSize,
		flow.MaxPacketSize,
		string(packetRefsJSON),
		sourcePorts,
		destinationPorts,
		flow.PacketsClientToServer,
		flow.PacketsServerToClient,
		flow.BytesClientToServer,
		flow.BytesServerToClient,
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
			} else if err == sql.ErrNoRows {
				exists = false
			} else {
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

// FlowProcessingError represents errors that occur during flow processing operations.
type FlowProcessingError struct {
	Flow    *model2.Flow
	Err     error
	Context string // e.g., "canonicalize", "lookup", "update", "create"
	Action  string // e.g., "parse_address", "find_canonical", "merge_stats"
}

func (e *FlowProcessingError) Error() string {
	return fmt.Sprintf("flow processing error [%s:%s]: %s - flow %s -> %s", e.Context, e.Action, e.Err.Error(), ipToString(e.Flow.SrcIP), ipToString(e.Flow.DstIP))
}

func (e *FlowProcessingError) Unwrap() error {
	return e.Err
}

// FlowErrorHandler provides strategies for handling flow processing errors.
type FlowErrorHandler interface {
	HandleCanonicalizationError(flow *model2.Flow, err error) error
	HandleLookupError(flow *model2.Flow, err error) error
	HandleUpdateError(flow *model2.Flow, err error) error
	HandleCreationError(flow *model2.Flow, err error) error
}

// DefaultFlowErrorHandler provides default error handling strategies.
type DefaultFlowErrorHandler struct{}

// HandleCanonicalizationError handles canonicalization failures by falling back to lexicographic ordering.
func (h *DefaultFlowErrorHandler) HandleCanonicalizationError(flow *model2.Flow, err error) error {
	// Log the error but continue with lexicographic fallback
	log.Printf("Canonicalization failed for flow %s -> %s: %v, falling back to lexicographic ordering", ipToString(flow.SrcIP), ipToString(flow.DstIP), err)

	// For address parsing failures, we can't create a canonical flow
	// Return the error to prevent corrupted data
	return &FlowProcessingError{
		Flow:    flow,
		Err:     err,
		Context: "canonicalize",
		Action:  "parse_address",
	}
}

// HandleLookupError handles lookup failures.
func (h *DefaultFlowErrorHandler) HandleLookupError(flow *model2.Flow, err error) error {
	if err == sql.ErrNoRows {
		// Not an error - flow doesn't exist yet
		return nil
	}

	log.Printf("Flow lookup failed for flow %s -> %s: %v", ipToString(flow.SrcIP), ipToString(flow.DstIP), err)
	return &FlowProcessingError{
		Flow:    flow,
		Err:     err,
		Context: "lookup",
		Action:  "find_canonical",
	}
}

// HandleUpdateError handles update failures with retry logic.
func (h *DefaultFlowErrorHandler) HandleUpdateError(flow *model2.Flow, err error) error {
	// Check for constraint violations that might be due to concurrent updates
	if sqliteErr, ok := err.(sqlite3.Error); ok && sqliteErr.Code == sqlite3.ErrConstraint {
		log.Printf("Constraint violation during flow update %s -> %s: %v, this may be due to concurrent processing", ipToString(flow.SrcIP), ipToString(flow.DstIP), err)
		return &FlowProcessingError{
			Flow:    flow,
			Err:     err,
			Context: "update",
			Action:  "constraint_violation",
		}
	}

	log.Printf("Flow update failed for flow %s -> %s: %v", ipToString(flow.SrcIP), ipToString(flow.DstIP), err)
	return &FlowProcessingError{
		Flow:    flow,
		Err:     err,
		Context: "update",
		Action:  "merge_stats",
	}
}

// HandleCreationError handles creation failures.
func (h *DefaultFlowErrorHandler) HandleCreationError(flow *model2.Flow, err error) error {
	log.Printf("Flow creation failed for flow %s -> %s: %v", ipToString(flow.SrcIP), ipToString(flow.DstIP), err)
	return &FlowProcessingError{
		Flow:    flow,
		Err:     err,
		Context: "create",
		Action:  "insert_canonical",
	}
}

// UpsertFlows inserts or updates multiple flows in the database.
func (r *SQLiteRepository) UpsertFlows(flows []*model2.Flow) error {
	for _, flow := range flows {
		if err := r.UpsertFlow(flow); err != nil {
			return err
		}
	}
	return nil
}

// UpsertFlow inserts or updates a flow in the database, handling bidirectional flow merging.
func (r *SQLiteRepository) UpsertFlow(flow *model2.Flow) error {
	if err := flow.Validate(); err != nil {
		return err
	}

	// Canonicalize the flow direction
	canonicalSrc, canonicalDst, isReversed := r.flowCanonicalizer.CanonicalizeFlow(ipToString(flow.SrcIP), ipToString(flow.DstIP), *flow.SourcePorts, *flow.DestinationPorts, flow.Protocol)

	// Check if a canonical flow already exists
	var existingFlow *model2.Flow
	existingFlows, err := r.GetFlows(map[string]interface{}{
		"src_ip":   canonicalSrc,
		"dst_ip":   canonicalDst,
		"protocol": flow.Protocol,
	})
	if err != nil {
		return fmt.Errorf("failed to check for existing flow: %w", err)
	}

	if len(existingFlows) > 0 {
		existingFlow = existingFlows[0]
	}

	if existingFlow != nil {
		// Update existing flow
		return r.updateBidirectionalFlow(existingFlow, flow, isReversed)
	} else {
		// Insert new flow in canonical form
		canonicalFlow := &model2.Flow{
			SrcIP:                 stringToIP(canonicalSrc),
			DstIP:                 stringToIP(canonicalDst),
			Protocol:              flow.Protocol,
			PacketCount:           flow.PacketCount,
			ByteCount:             flow.ByteCount,
			SrcPort:               flow.SrcPort,
			DstPort:               flow.DstPort,
			FirstSeen:             flow.FirstSeen,
			LastSeen:              flow.LastSeen,
			PacketRefs:            make([]int64, len(flow.PacketRefs)),
			MinPacketSize:         flow.MinPacketSize,
			MaxPacketSize:         flow.MaxPacketSize,
			SourcePorts:           r.copySet(flow.SourcePorts),
			DestinationPorts:      r.copySet(flow.DestinationPorts),
			PacketsClientToServer: 0,
			PacketsServerToClient: 0,
			BytesClientToServer:   0,
			BytesServerToClient:   0,
		}
		copy(canonicalFlow.PacketRefs, flow.PacketRefs)

		// Set bidirectional stats and ports based on direction
		if isReversed {
			canonicalFlow.PacketsServerToClient = flow.PacketCount
			canonicalFlow.BytesServerToClient = flow.ByteCount
			// For reversed flows, flip ports
			canonicalFlow.SrcPort = flow.DstPort
			canonicalFlow.DstPort = flow.SrcPort
		} else {
			canonicalFlow.PacketsClientToServer = flow.PacketCount
			canonicalFlow.BytesClientToServer = flow.ByteCount
		}

		return r.AddFlow(canonicalFlow)
	}
}

// copySet creates a copy of a Set
func (r *SQLiteRepository) copySet(s *model2.Set) *model2.Set {
	if s == nil {
		return model2.NewSet()
	}
	result := model2.NewSet()
	for _, item := range s.List() {
		result.Add(item)
	}
	return result
}

// parseAddressPort extracts IP and port from an address string like "192.168.1.1:80"
// NOTE: Keep jsonArrayToSlice above so we can reuse

func jsonArrayToSlice(s string) []string {
	if s == "" {
		return nil
	}
	var result []string
	if err := json.Unmarshal([]byte(s), &result); err == nil {
		return result
	}
	// fallback
	return strings.Split(s, ",")
}
func (r *SQLiteRepository) parseAddressPort(address string) (ip string, port uint16) {
	if strings.Contains(address, "[") && strings.Contains(address, "]:") {
		// IPv6 with port: [2001:db8::1]:80
		parts := strings.Split(address, "]:")
		if len(parts) == 2 {
			ip = strings.TrimPrefix(parts[0], "[")
			if p, err := strconv.Atoi(parts[1]); err == nil {
				port = uint16(p)
			}
		}
	} else if strings.Count(address, ":") == 1 {
		// IPv4 with port: 192.168.1.1:80
		parts := strings.Split(address, ":")
		ip = parts[0]
		if p, err := strconv.Atoi(parts[1]); err == nil {
			port = uint16(p)
		}
	} else {
		// Just IP address
		ip = address
	}
	return
}

// updateBidirectionalFlow updates an existing flow with new packet data in the appropriate direction
func (r *SQLiteRepository) updateBidirectionalFlow(existingFlow, newFlow *model2.Flow, isReversed bool) error {
	// Update timestamps
	if newFlow.FirstSeen.Before(existingFlow.FirstSeen) {
		existingFlow.FirstSeen = newFlow.FirstSeen
	}
	if newFlow.LastSeen.After(existingFlow.LastSeen) {
		existingFlow.LastSeen = newFlow.LastSeen
	}

	// Update packet/byte counts
	existingFlow.PacketCount += newFlow.PacketCount
	existingFlow.ByteCount += newFlow.ByteCount

	// Update bidirectional stats
	if isReversed {
		existingFlow.PacketsServerToClient += newFlow.PacketCount
		existingFlow.BytesServerToClient += newFlow.ByteCount
	} else {
		existingFlow.PacketsClientToServer += newFlow.PacketCount
		existingFlow.BytesClientToServer += newFlow.ByteCount
	}

	// Update packet refs
	existingFlow.PacketRefs = append(existingFlow.PacketRefs, newFlow.PacketRefs...)

	// Update min/max packet sizes
	if newFlow.MinPacketSize < existingFlow.MinPacketSize {
		existingFlow.MinPacketSize = newFlow.MinPacketSize
	}
	if newFlow.MaxPacketSize > existingFlow.MaxPacketSize {
		existingFlow.MaxPacketSize = newFlow.MaxPacketSize
	}

	// Merge port sets
	if newFlow.SourcePorts != nil {
		if existingFlow.SourcePorts == nil {
			existingFlow.SourcePorts = model2.NewSet()
		}
		for _, port := range newFlow.SourcePorts.List() {
			existingFlow.SourcePorts.Add(port)
		}
	}
	if newFlow.DestinationPorts != nil {
		if existingFlow.DestinationPorts == nil {
			existingFlow.DestinationPorts = model2.NewSet()
		}
		for _, port := range newFlow.DestinationPorts.List() {
			existingFlow.DestinationPorts.Add(port)
		}
	}

	// Update in database
	return r.UpdateFlow(existingFlow)
}

// UpsertService inserts or updates a service in the database.
func (r *SQLiteRepository) UpsertService(service *model2.Service) error {
	if err := service.Validate(); err != nil {
		return err
	}

	// Check if service exists by ip, port, protocol
	existingServices, err := r.GetServices(map[string]interface{}{
		"ip":       service.IP.String(),
		"port":     service.Port,
		"protocol": service.Protocol,
	})
	if err != nil {
		return fmt.Errorf("failed to check for existing service: %w", err)
	}

	if len(existingServices) > 0 {
		// Service exists, update timestamps
		existing := existingServices[0]
		if service.FirstSeen.Before(existing.FirstSeen) {
			existing.FirstSeen = service.FirstSeen
		}
		if service.LastSeen.After(existing.LastSeen) {
			existing.LastSeen = service.LastSeen
		}
		return r.UpdateService(existing)
	} else {
		// Service doesn't exist, insert it
		return r.AddService(service)
	}
}

// UpsertServices inserts or updates multiple services in the database.
func (r *SQLiteRepository) UpsertServices(services []*model2.Service) error {
	for _, service := range services {
		if err := r.UpsertService(service); err != nil {
			return errors.Join(err, errors.New("error with service "+fmt.Sprintf("%+v", service)))
		}
	}
	return nil
}
