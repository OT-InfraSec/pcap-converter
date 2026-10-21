package repository

import (
	"database/sql"
	"fmt"
	"time"

	model2 "github.com/InfraSecConsult/pcap-importer-go/lib/model"
)

// cdpFilterColumns whitelists filter keys because they are concatenated into the query.
var cdpFilterColumns = map[string]bool{
	"src_mac": true, "port_id": true, "vlan_id": true, "device_id": true,
	"native_vlan": true, "management_vlan": true,
}

// UpsertCDPNeighbors inserts neighbors, widening the time range of rows that already exist.
func (r *SQLiteRepository) UpsertCDPNeighbors(neighbors []*model2.CDPNeighbor) error {
	for _, n := range neighbors {
		if err := n.Validate(); err != nil {
			return err
		}
	}
	tx, err := r.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin cdp neighbor transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Prepared once: a full import writes up to 100,000 rows through these statements.
	// "IS" compares NULL vlan_id correctly, unlike "="
	find, err := tx.Prepare(`SELECT id, first_seen, last_seen FROM cdp_neighbors
		WHERE tenant_id = ? AND src_mac = ? AND port_id = ? AND vlan_id IS ? AND fingerprint = ?`)
	if err != nil {
		return fmt.Errorf("failed to prepare cdp neighbor lookup: %w", err)
	}
	defer find.Close()
	insert, err := tx.Prepare(`INSERT INTO cdp_neighbors (tenant_id, src_mac, port_id, vlan_id, device_id, platform,
		software_version, sys_name, capabilities, addresses, mgmt_addresses, native_vlan, management_vlan,
		fingerprint, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("failed to prepare cdp neighbor insert: %w", err)
	}
	defer insert.Close()
	update, err := tx.Prepare(`UPDATE cdp_neighbors SET first_seen = ?, last_seen = ? WHERE id = ?`)
	if err != nil {
		return fmt.Errorf("failed to prepare cdp neighbor update: %w", err)
	}
	defer update.Close()

	for _, n := range neighbors {
		if err = upsertCDPNeighbor(find, insert, update, n); err != nil {
			return fmt.Errorf("failed to upsert cdp neighbor %s %s: %w", n.SrcMAC, n.PortID, err)
		}
	}
	return tx.Commit()
}

func upsertCDPNeighbor(find, insert, update *sql.Stmt, n *model2.CDPNeighbor) error {
	var id int64
	var firstStr, lastStr string
	err := find.QueryRow(n.TenantID, n.SrcMAC, n.PortID, intPtrToArg(n.VlanID), n.Fingerprint).Scan(&id, &firstStr, &lastStr)
	if err == sql.ErrNoRows {
		_, err = insert.Exec(n.TenantID, n.SrcMAC, n.PortID, intPtrToArg(n.VlanID), n.DeviceID, n.Platform,
			n.SoftwareVersion, n.SysName, n.Capabilities, n.Addresses, n.MgmtAddresses,
			intPtrToArg(n.NativeVLAN), intPtrToArg(n.ManagementVLAN), n.Fingerprint,
			n.FirstSeen.Format(time.RFC3339Nano), n.LastSeen.Format(time.RFC3339Nano))
		return err
	}
	if err != nil {
		return err
	}

	// Compare as times: the stored strings may carry different zone offsets.
	first, _ := time.Parse(time.RFC3339Nano, firstStr)
	last, _ := time.Parse(time.RFC3339Nano, lastStr)
	if n.FirstSeen.Before(first) {
		first = n.FirstSeen
	}
	if n.LastSeen.After(last) {
		last = n.LastSeen
	}
	_, err = update.Exec(first.Format(time.RFC3339Nano), last.Format(time.RFC3339Nano), id)
	return err
}

// GetCDPNeighbors returns a tenant's neighbors. A nil filter value matches NULL.
func (r *SQLiteRepository) GetCDPNeighbors(tenantID string, filters map[string]interface{}) ([]*model2.CDPNeighbor, error) {
	query := `SELECT id, tenant_id, src_mac, port_id, vlan_id, device_id, platform, software_version, sys_name,
		capabilities, addresses, mgmt_addresses, native_vlan, management_vlan, fingerprint, first_seen, last_seen
		FROM cdp_neighbors WHERE tenant_id = ?`
	params := []interface{}{tenantID}
	for key, value := range filters {
		if !cdpFilterColumns[key] {
			return nil, fmt.Errorf("unsupported cdp neighbor filter %q", key)
		}
		if value == nil {
			query += " AND " + key + " IS NULL"
			continue
		}
		query += " AND " + key + " = ?"
		params = append(params, value)
	}
	query += " ORDER BY src_mac, port_id, vlan_id, last_seen, fingerprint"

	rows, err := r.db.Query(query, params...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*model2.CDPNeighbor
	for rows.Next() {
		var n model2.CDPNeighbor
		var tenant sql.NullString
		var vlan, native, mgmt sql.NullInt64
		var firstStr, lastStr string
		if err = rows.Scan(&n.ID, &tenant, &n.SrcMAC, &n.PortID, &vlan, &n.DeviceID, &n.Platform, &n.SoftwareVersion,
			&n.SysName, &n.Capabilities, &n.Addresses, &n.MgmtAddresses, &native, &mgmt, &n.Fingerprint,
			&firstStr, &lastStr); err != nil {
			return nil, err
		}
		n.TenantID = tenant.String
		n.VlanID = nullIntToPtr(vlan)
		n.NativeVLAN = nullIntToPtr(native)
		n.ManagementVLAN = nullIntToPtr(mgmt)
		n.FirstSeen, _ = time.Parse(time.RFC3339Nano, firstStr)
		n.LastSeen, _ = time.Parse(time.RFC3339Nano, lastStr)
		out = append(out, &n)
	}
	return out, rows.Err()
}
