package repository

import (
	"encoding/json"
	"time"

	model2 "github.com/InfraSecConsult/pcap-importer-go/lib/model"
)

// Industrial Device Operations

// SaveIndustrialDeviceInfo saves industrial device information
func (r *SQLiteRepository) SaveIndustrialDeviceInfo(info *model2.IndustrialDeviceInfo) error {
	if err := info.Validate(); err != nil {
		return err
	}

	protocolsJSON, err := json.Marshal(info.Protocols)
	if err != nil {
		return err
	}

	_, err = r.db.Exec(
		`INSERT INTO industrial_devices (device_address, device_type, role, confidence, protocols, security_level, vendor, product_name, serial_number, firmware_version, last_seen, created_at, updated_at) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`,
		info.DeviceAddress,
		string(info.DeviceType),
		string(info.Role),
		info.Confidence,
		string(protocolsJSON),
		int(info.SecurityLevel),
		info.Vendor,
		info.ProductName,
		info.SerialNumber,
		info.FirmwareVersion,
		info.LastSeen.Format(time.RFC3339Nano),
		info.CreatedAt.Format(time.RFC3339Nano),
		info.UpdatedAt.Format(time.RFC3339Nano),
	)
	return err
}

// GetIndustrialDeviceInfo retrieves industrial device information by device address
func (r *SQLiteRepository) GetIndustrialDeviceInfo(deviceAddress string) (*model2.IndustrialDeviceInfo, error) {
	query := `SELECT device_address, device_type, role, confidence, protocols, security_level, vendor, product_name, serial_number, firmware_version, last_seen, created_at, updated_at 
			  FROM industrial_devices WHERE device_address = ?`
	row := r.db.QueryRow(query, deviceAddress)

	var info model2.IndustrialDeviceInfo
	var protocolsJSON, lastSeenStr, createdAtStr, updatedAtStr string
	var securityLevel int

	err := row.Scan(
		&info.DeviceAddress,
		&info.DeviceType,
		&info.Role,
		&info.Confidence,
		&protocolsJSON,
		&securityLevel,
		&info.Vendor,
		&info.ProductName,
		&info.SerialNumber,
		&info.FirmwareVersion,
		&lastSeenStr,
		&createdAtStr,
		&updatedAtStr,
	)
	if err != nil {
		return nil, err
	}

	info.SecurityLevel = model2.SecurityLevel(securityLevel)
	info.LastSeen, _ = time.Parse(time.RFC3339Nano, lastSeenStr)
	info.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAtStr)
	info.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAtStr)

	if err := json.Unmarshal([]byte(protocolsJSON), &info.Protocols); err != nil {
		return nil, err
	}

	return &info, nil
}

// GetIndustrialDevicesByType retrieves industrial devices by device type
func (r *SQLiteRepository) GetIndustrialDevicesByType(deviceType model2.IndustrialDeviceType) ([]*model2.IndustrialDeviceInfo, error) {
	query := `SELECT device_address, device_type, role, confidence, protocols, security_level, vendor, product_name, serial_number, firmware_version, last_seen, created_at, updated_at 
			  FROM industrial_devices WHERE device_type = ?`
	rows, err := r.db.Query(query, string(deviceType))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []*model2.IndustrialDeviceInfo
	for rows.Next() {
		var info model2.IndustrialDeviceInfo
		var protocolsJSON, lastSeenStr, createdAtStr, updatedAtStr string
		var securityLevel int

		err := rows.Scan(
			&info.DeviceAddress,
			&info.DeviceType,
			&info.Role,
			&info.Confidence,
			&protocolsJSON,
			&securityLevel,
			&info.Vendor,
			&info.ProductName,
			&info.SerialNumber,
			&info.FirmwareVersion,
			&lastSeenStr,
			&createdAtStr,
			&updatedAtStr,
		)
		if err != nil {
			return nil, err
		}

		info.SecurityLevel = model2.SecurityLevel(securityLevel)
		info.LastSeen, _ = time.Parse(time.RFC3339Nano, lastSeenStr)
		info.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAtStr)
		info.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAtStr)

		if err := json.Unmarshal([]byte(protocolsJSON), &info.Protocols); err != nil {
			return nil, err
		}

		devices = append(devices, &info)
	}

	return devices, nil
}

// UpdateIndustrialDeviceInfo updates existing industrial device information
func (r *SQLiteRepository) UpdateIndustrialDeviceInfo(info *model2.IndustrialDeviceInfo) error {
	if err := info.Validate(); err != nil {
		return err
	}

	protocolsJSON, err := json.Marshal(info.Protocols)
	if err != nil {
		return err
	}

	_, err = r.db.Exec(
		`UPDATE industrial_devices SET device_type = ?, role = ?, confidence = ?, protocols = ?, security_level = ?, vendor = ?, product_name = ?, serial_number = ?, firmware_version = ?, last_seen = ?, updated_at = ? 
		WHERE device_address = ?;`,
		string(info.DeviceType),
		string(info.Role),
		info.Confidence,
		string(protocolsJSON),
		int(info.SecurityLevel),
		info.Vendor,
		info.ProductName,
		info.SerialNumber,
		info.FirmwareVersion,
		info.LastSeen.Format(time.RFC3339Nano),
		info.UpdatedAt.Format(time.RFC3339Nano),
		info.DeviceAddress,
	)
	return err
}

// UpsertIndustrialDeviceInfo inserts or updates industrial device information
func (r *SQLiteRepository) UpsertIndustrialDeviceInfo(info *model2.IndustrialDeviceInfo) error {
	// Check if device exists
	_, err := r.GetIndustrialDeviceInfo(info.DeviceAddress)
	if err == nil {
		// Device exists, update it
		return r.UpdateIndustrialDeviceInfo(info)
	}
	// Device doesn't exist, insert it
	return r.SaveIndustrialDeviceInfo(info)
}

// DeleteIndustrialDeviceInfo deletes industrial device information
func (r *SQLiteRepository) DeleteIndustrialDeviceInfo(deviceAddress string) error {
	_, err := r.db.Exec(`DELETE FROM industrial_devices WHERE device_address = ?;`, deviceAddress)
	return err
}

// Protocol Usage Statistics Operations

// SaveProtocolUsageStats saves protocol usage statistics
func (r *SQLiteRepository) SaveProtocolUsageStats(stats *model2.ProtocolUsageStats) error {
	if err := stats.Validate(); err != nil {
		return err
	}

	portsJSON, err := json.Marshal(stats.PortsUsed)
	if err != nil {
		return err
	}

	_, err = r.db.Exec(
		`INSERT INTO protocol_usage_stats (device_address, protocol, packet_count, byte_count, first_seen, last_seen, communication_role, ports_used) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?);`,
		stats.DeviceID, // DeviceID is actually the device address in our API
		stats.Protocol,
		stats.PacketCount,
		stats.ByteCount,
		stats.FirstSeen.Format(time.RFC3339Nano),
		stats.LastSeen.Format(time.RFC3339Nano),
		stats.CommunicationRole,
		string(portsJSON),
	)
	return err
}

// GetProtocolUsageStats retrieves protocol usage statistics for a device
func (r *SQLiteRepository) GetProtocolUsageStats(deviceAddress string) ([]*model2.ProtocolUsageStats, error) {
	query := `SELECT id, device_address, protocol, packet_count, byte_count, first_seen, last_seen, communication_role, ports_used 
			  FROM protocol_usage_stats WHERE device_address = ?`
	rows, err := r.db.Query(query, deviceAddress)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var statsList []*model2.ProtocolUsageStats
	for rows.Next() {
		var stats model2.ProtocolUsageStats
		var id int64
		var portsJSON, firstSeenStr, lastSeenStr string

		err := rows.Scan(
			&id,
			&stats.DeviceID, // DeviceID is actually the device address in our API
			&stats.Protocol,
			&stats.PacketCount,
			&stats.ByteCount,
			&firstSeenStr,
			&lastSeenStr,
			&stats.CommunicationRole,
			&portsJSON,
		)
		if err != nil {
			return nil, err
		}

		stats.FirstSeen, _ = time.Parse(time.RFC3339Nano, firstSeenStr)
		stats.LastSeen, _ = time.Parse(time.RFC3339Nano, lastSeenStr)

		if err := json.Unmarshal([]byte(portsJSON), &stats.PortsUsed); err != nil {
			return nil, err
		}

		statsList = append(statsList, &stats)
	}

	return statsList, nil
}

// GetProtocolUsageStatsByProtocol retrieves protocol usage statistics by protocol
func (r *SQLiteRepository) GetProtocolUsageStatsByProtocol(protocol string) ([]*model2.ProtocolUsageStats, error) {
	query := `SELECT id, device_address, protocol, packet_count, byte_count, first_seen, last_seen, communication_role, ports_used 
			  FROM protocol_usage_stats WHERE protocol = ?`
	rows, err := r.db.Query(query, protocol)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var statsList []*model2.ProtocolUsageStats
	for rows.Next() {
		var stats model2.ProtocolUsageStats
		var id int64
		var portsJSON, firstSeenStr, lastSeenStr string

		err := rows.Scan(
			&id,
			&stats.DeviceID, // DeviceID is actually the device address in our API
			&stats.Protocol,
			&stats.PacketCount,
			&stats.ByteCount,
			&firstSeenStr,
			&lastSeenStr,
			&stats.CommunicationRole,
			&portsJSON,
		)
		if err != nil {
			return nil, err
		}

		stats.FirstSeen, _ = time.Parse(time.RFC3339Nano, firstSeenStr)
		stats.LastSeen, _ = time.Parse(time.RFC3339Nano, lastSeenStr)

		if err := json.Unmarshal([]byte(portsJSON), &stats.PortsUsed); err != nil {
			return nil, err
		}

		statsList = append(statsList, &stats)
	}

	return statsList, nil
}

// UpdateProtocolUsageStats updates existing protocol usage statistics
func (r *SQLiteRepository) UpdateProtocolUsageStats(stats *model2.ProtocolUsageStats) error {
	if err := stats.Validate(); err != nil {
		return err
	}

	portsJSON, err := json.Marshal(stats.PortsUsed)
	if err != nil {
		return err
	}

	_, err = r.db.Exec(
		`UPDATE protocol_usage_stats SET packet_count = ?, byte_count = ?, first_seen = ?, last_seen = ?, communication_role = ?, ports_used = ? 
		WHERE device_address = ? AND protocol = ?;`,
		stats.PacketCount,
		stats.ByteCount,
		stats.FirstSeen.Format(time.RFC3339Nano),
		stats.LastSeen.Format(time.RFC3339Nano),
		stats.CommunicationRole,
		string(portsJSON),
		stats.DeviceID, // DeviceID is actually the device address in our API
		stats.Protocol,
	)
	return err
}

// UpsertProtocolUsageStats inserts or updates protocol usage statistics
func (r *SQLiteRepository) UpsertProtocolUsageStats(stats *model2.ProtocolUsageStats) error {
	// Check if stats exist
	existingStats, err := r.GetProtocolUsageStats(stats.DeviceID)
	if err == nil {
		// Check if this specific protocol exists for the device
		for _, existing := range existingStats {
			if existing.Protocol == stats.Protocol {
				// Stats exist, update them
				return r.UpdateProtocolUsageStats(stats)
			}
		}
	}
	// Stats don't exist, insert them
	return r.SaveProtocolUsageStats(stats)
}

// DeleteProtocolUsageStats deletes protocol usage statistics
func (r *SQLiteRepository) DeleteProtocolUsageStats(deviceAddress, protocol string) error {
	_, err := r.db.Exec(`DELETE FROM protocol_usage_stats WHERE device_address = ? AND protocol = ?;`, deviceAddress, protocol)
	return err
}

// Communication Pattern Operations

// SaveCommunicationPattern saves a communication pattern
func (r *SQLiteRepository) SaveCommunicationPattern(pattern *model2.CommunicationPattern) error {
	if err := pattern.Validate(); err != nil {
		return err
	}

	_, err := r.db.Exec(
		`INSERT INTO communication_patterns (source_device_address, destination_device_address, protocol, frequency_ms, data_volume, flow_count, deviation_frequency, deviation_data_volume, pattern_type, criticality, created_at) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`,
		pattern.SourceDevice,
		pattern.DestinationDevice,
		pattern.Protocol,
		pattern.Frequency.Milliseconds(),
		pattern.DataVolume,
		pattern.FlowCount,
		pattern.DeviationFrequency,
		pattern.DeviationDataVolume,
		pattern.PatternType,
		pattern.Criticality,
		time.Now().Format(time.RFC3339Nano),
	)
	return err
}

// GetCommunicationPatterns retrieves communication patterns for a device
func (r *SQLiteRepository) GetCommunicationPatterns(deviceAddress string) ([]*model2.CommunicationPattern, error) {
	query := `SELECT id, source_device_address, destination_device_address, protocol, frequency_ms, data_volume, flow_count, deviation_frequency, deviation_data_volume, pattern_type, criticality, created_at 
			  FROM communication_patterns WHERE source_device_address = ? OR destination_device_address = ?`
	rows, err := r.db.Query(query, deviceAddress, deviceAddress)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var patterns []*model2.CommunicationPattern
	for rows.Next() {
		var pattern model2.CommunicationPattern
		var id int64
		var frequencyMs int64
		var createdAtStr string

		err := rows.Scan(
			&id,
			&pattern.SourceDevice,
			&pattern.DestinationDevice,
			&pattern.Protocol,
			&frequencyMs,
			&pattern.DataVolume,
			&pattern.FlowCount,
			&pattern.DeviationFrequency,
			&pattern.DeviationDataVolume,
			&pattern.PatternType,
			&pattern.Criticality,
			&createdAtStr,
		)
		if err != nil {
			return nil, err
		}

		pattern.Frequency = time.Duration(frequencyMs) * time.Millisecond

		patterns = append(patterns, &pattern)
	}

	return patterns, nil
}

// GetCommunicationPatternsByProtocol retrieves communication patterns by protocol
func (r *SQLiteRepository) GetCommunicationPatternsByProtocol(protocol string) ([]*model2.CommunicationPattern, error) {
	query := `SELECT id, source_device_address, destination_device_address, protocol, frequency_ms, data_volume, flow_count, deviation_frequency, deviation_data_volume, pattern_type, criticality, created_at 
			  FROM communication_patterns WHERE protocol = ?`
	rows, err := r.db.Query(query, protocol)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var patterns []*model2.CommunicationPattern
	for rows.Next() {
		var pattern model2.CommunicationPattern
		var id int64
		var frequencyMs int64
		var createdAtStr string

		err := rows.Scan(
			&id,
			&pattern.SourceDevice,
			&pattern.DestinationDevice,
			&pattern.Protocol,
			&frequencyMs,
			&pattern.DataVolume,
			&pattern.FlowCount,
			&pattern.DeviationFrequency,
			&pattern.DeviationDataVolume,
			&pattern.PatternType,
			&pattern.Criticality,
			&createdAtStr,
		)
		if err != nil {
			return nil, err
		}

		pattern.Frequency = time.Duration(frequencyMs) * time.Millisecond

		patterns = append(patterns, &pattern)
	}

	return patterns, nil
}

// UpdateCommunicationPattern updates an existing communication pattern
func (r *SQLiteRepository) UpdateCommunicationPattern(pattern *model2.CommunicationPattern) error {
	if err := pattern.Validate(); err != nil {
		return err
	}

	_, err := r.db.Exec(
		`UPDATE communication_patterns SET frequency_ms = ?, data_volume = ?, flow_count = ?, deviation_frequency = ?, deviation_data_volume = ?, pattern_type = ?, criticality = ? 
		WHERE source_device_address = ? AND destination_device_address = ? AND protocol = ?;`,
		pattern.Frequency.Milliseconds(),
		pattern.DataVolume,
		pattern.FlowCount,
		pattern.DeviationFrequency,
		pattern.DeviationDataVolume,
		pattern.PatternType,
		pattern.Criticality,
		pattern.SourceDevice,
		pattern.DestinationDevice,
		pattern.Protocol,
	)
	return err
}

// UpsertCommunicationPattern inserts or updates a communication pattern
func (r *SQLiteRepository) UpsertCommunicationPattern(pattern *model2.CommunicationPattern) error {
	// Check if pattern exists
	existingPatterns, err := r.GetCommunicationPatterns(pattern.SourceDevice)
	if err == nil {
		// Check if this specific pattern exists
		for _, existing := range existingPatterns {
			if existing.SourceDevice == pattern.SourceDevice &&
				existing.DestinationDevice == pattern.DestinationDevice &&
				existing.Protocol == pattern.Protocol {
				// Pattern exists, update it
				return r.UpdateCommunicationPattern(pattern)
			}
		}
	}
	// Pattern doesn't exist, insert it
	return r.SaveCommunicationPattern(pattern)
}

// DeleteCommunicationPattern deletes a communication pattern
func (r *SQLiteRepository) DeleteCommunicationPattern(sourceDeviceAddress, destinationDeviceAddress, protocol string) error {
	_, err := r.db.Exec(`DELETE FROM communication_patterns WHERE source_device_address = ? AND destination_device_address = ? AND protocol = ?;`, sourceDeviceAddress, destinationDeviceAddress, protocol)
	return err
}

// Batch Operations for Industrial Data

// SaveIndustrialDeviceInfos saves multiple industrial device infos in a single transaction
func (r *SQLiteRepository) SaveIndustrialDeviceInfos(infos []*model2.IndustrialDeviceInfo) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT INTO industrial_devices (device_address, device_type, role, confidence, protocols, security_level, vendor, product_name, serial_number, firmware_version, last_seen, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, info := range infos {
		if err := info.Validate(); err != nil {
			return err
		}

		protocolsJSON, err := json.Marshal(info.Protocols)
		if err != nil {
			return err
		}

		_, err = stmt.Exec(
			info.DeviceAddress,
			string(info.DeviceType),
			string(info.Role),
			info.Confidence,
			string(protocolsJSON),
			int(info.SecurityLevel),
			info.Vendor,
			info.ProductName,
			info.SerialNumber,
			info.FirmwareVersion,
			info.LastSeen.Format(time.RFC3339Nano),
			info.CreatedAt.Format(time.RFC3339Nano),
			info.UpdatedAt.Format(time.RFC3339Nano),
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// SaveProtocolUsageStatsMultiple saves multiple protocol usage statistics in a single transaction
func (r *SQLiteRepository) SaveProtocolUsageStatsMultiple(stats []*model2.ProtocolUsageStats) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT INTO protocol_usage_stats (device_address, protocol, packet_count, byte_count, first_seen, last_seen, communication_role, ports_used) VALUES (?, ?, ?, ?, ?, ?, ?, ?);`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, stat := range stats {
		if err := stat.Validate(); err != nil {
			return err
		}

		portsJSON, err := json.Marshal(stat.PortsUsed)
		if err != nil {
			return err
		}

		_, err = stmt.Exec(
			stat.DeviceID, // DeviceID is actually the device address in our API
			stat.Protocol,
			stat.PacketCount,
			stat.ByteCount,
			stat.FirstSeen.Format(time.RFC3339Nano),
			stat.LastSeen.Format(time.RFC3339Nano),
			stat.CommunicationRole,
			string(portsJSON),
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// SaveCommunicationPatterns saves multiple communication patterns in a single transaction
func (r *SQLiteRepository) SaveCommunicationPatterns(patterns []*model2.CommunicationPattern) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT INTO communication_patterns (source_device_address, destination_device_address, protocol, frequency_ms, data_volume, flow_count, deviation_frequency, deviation_data_volume, pattern_type, criticality, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, pattern := range patterns {
		if err = pattern.Validate(); err != nil {
			return err
		}

		_, err = stmt.Exec(
			pattern.SourceDevice,
			pattern.DestinationDevice,
			pattern.Protocol,
			pattern.Frequency.Milliseconds(),
			pattern.DataVolume,
			pattern.FlowCount,
			pattern.DeviationFrequency,
			pattern.DeviationDataVolume,
			pattern.PatternType,
			pattern.Criticality,
			time.Now().Format(time.RFC3339Nano),
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// Industrial Protocol Info Operations

// SaveIndustrialProtocolInfo saves industrial protocol information
func (r *SQLiteRepository) SaveIndustrialProtocolInfo(info *model2.IndustrialProtocolInfo) error {
	if err := info.Validate(); err != nil {
		return err
	}

	deviceIdentityJSON, err := json.Marshal(info.DeviceIdentity)
	if err != nil {
		return err
	}
	securityInfoJSON, err := json.Marshal(info.SecurityInfo)
	if err != nil {
		return err
	}
	additionalDataJSON, err := json.Marshal(info.AdditionalData)
	if err != nil {
		return err
	}

	_, err = r.db.Exec(
		`INSERT INTO industrial_protocol_info (protocol, port, direction, timestamp, confidence, service_type, message_type, is_real_time, is_discovery, is_configuration, device_identity, security_info, additional_data) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`,
		info.Protocol,
		info.Port,
		info.Direction,
		info.Timestamp.Format(time.RFC3339Nano),
		info.Confidence,
		info.ServiceType,
		info.MessageType,
		info.IsRealTimeData,
		info.IsDiscovery,
		info.IsConfiguration,
		string(deviceIdentityJSON),
		string(securityInfoJSON),
		string(additionalDataJSON),
	)
	return err
}

// GetIndustrialProtocolInfos retrieves industrial protocol information for a device
func (r *SQLiteRepository) GetIndustrialProtocolInfos(deviceAddress string) ([]*model2.IndustrialProtocolInfo, error) {
	query := `SELECT protocol, port, direction, timestamp, confidence, service_type, message_type, is_real_time, is_discovery, is_configuration, device_identity, security_info, additional_data 
			  FROM industrial_protocol_info WHERE device_address = ?`
	rows, err := r.db.Query(query, deviceAddress)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var infos []*model2.IndustrialProtocolInfo
	for rows.Next() {
		var info model2.IndustrialProtocolInfo
		var timestampStr, deviceIdentityJSON, securityInfoJSON, additionalDataJSON string

		err := rows.Scan(
			&info.Protocol,
			&info.Port,
			&info.Direction,
			&timestampStr,
			&info.Confidence,
			&info.ServiceType,
			&info.MessageType,
			&info.IsRealTimeData,
			&info.IsDiscovery,
			&info.IsConfiguration,
			&deviceIdentityJSON,
			&securityInfoJSON,
			&additionalDataJSON,
		)
		if err != nil {
			return nil, err
		}

		info.Timestamp, _ = time.Parse(time.RFC3339Nano, timestampStr)
		if err := json.Unmarshal([]byte(deviceIdentityJSON), &info.DeviceIdentity); err != nil {
			info.DeviceIdentity = make(map[string]interface{})
		}
		if err := json.Unmarshal([]byte(securityInfoJSON), &info.SecurityInfo); err != nil {
			info.SecurityInfo = make(map[string]interface{})
		}
		if err := json.Unmarshal([]byte(additionalDataJSON), &info.AdditionalData); err != nil {
			info.AdditionalData = make(map[string]interface{})
		}

		infos = append(infos, &info)
	}

	return infos, nil
}

// GetIndustrialProtocolInfosByProtocol retrieves industrial protocol information by protocol type
func (r *SQLiteRepository) GetIndustrialProtocolInfosByProtocol(protocol string) ([]*model2.IndustrialProtocolInfo, error) {
	query := `SELECT protocol, port, direction, timestamp, confidence, service_type, message_type, is_real_time, is_discovery, is_configuration, device_identity, security_info, additional_data 
			  FROM industrial_protocol_info WHERE protocol = ?`
	rows, err := r.db.Query(query, protocol)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var infos []*model2.IndustrialProtocolInfo
	for rows.Next() {
		var info model2.IndustrialProtocolInfo
		var timestampStr, deviceIdentityJSON, securityInfoJSON, additionalDataJSON string

		err := rows.Scan(
			&info.Protocol,
			&info.Port,
			&info.Direction,
			&timestampStr,
			&info.Confidence,
			&info.ServiceType,
			&info.MessageType,
			&info.IsRealTimeData,
			&info.IsDiscovery,
			&info.IsConfiguration,
			&deviceIdentityJSON,
			&securityInfoJSON,
			&additionalDataJSON,
		)
		if err != nil {
			return nil, err
		}

		info.Timestamp, _ = time.Parse(time.RFC3339Nano, timestampStr)
		if err := json.Unmarshal([]byte(deviceIdentityJSON), &info.DeviceIdentity); err != nil {
			info.DeviceIdentity = make(map[string]interface{})
		}
		if err := json.Unmarshal([]byte(securityInfoJSON), &info.SecurityInfo); err != nil {
			info.SecurityInfo = make(map[string]interface{})
		}
		if err := json.Unmarshal([]byte(additionalDataJSON), &info.AdditionalData); err != nil {
			info.AdditionalData = make(map[string]interface{})
		}

		infos = append(infos, &info)
	}

	return infos, nil
}

// DeleteIndustrialProtocolInfos deletes industrial protocol information for a device
func (r *SQLiteRepository) DeleteIndustrialProtocolInfos(deviceAddress string) error {
	_, err := r.db.Exec("DELETE FROM industrial_protocol_info WHERE device_address = ?", deviceAddress)
	return err
}

// SaveIndustrialProtocolInfos saves multiple industrial protocol information entries
func (r *SQLiteRepository) SaveIndustrialProtocolInfos(infos []*model2.IndustrialProtocolInfo) error {
	for _, info := range infos {
		if err := r.SaveIndustrialProtocolInfo(info); err != nil {
			return err
		}
	}
	return nil
}
