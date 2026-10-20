package repository

import (
	"database/sql"
	"fmt"
	"time"

	model2 "github.com/InfraSecConsult/pcap-importer-go/lib/model"
)

// subnetFilterColumns whitelists filter keys because they are concatenated into the query.
var subnetFilterColumns = map[string]bool{"cidr": true, "vlan_id": true, "source": true, "kind": true}

// UpsertSubnets inserts subnets, widening the time range of rows that already exist.
func (r *SQLiteRepository) UpsertSubnets(subnets []*model2.Subnet) error {
	for _, s := range subnets {
		if err := s.Validate(); err != nil {
			return err
		}
	}
	tx, err := r.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin subnet transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, s := range subnets {
		if err = upsertSubnet(tx, s); err != nil {
			return fmt.Errorf("failed to upsert subnet %s: %w", s.CIDR, err)
		}
	}
	return tx.Commit()
}

func upsertSubnet(tx *sql.Tx, s *model2.Subnet) error {
	var id int64
	var firstStr, lastStr string
	// "IS" compares NULL vlan_id correctly, unlike "="
	err := tx.QueryRow(`SELECT id, first_seen, last_seen FROM subnets
		WHERE tenant_id = ? AND cidr = ? AND vlan_id IS ? AND source = ? AND kind = ?`,
		s.TenantID, s.CIDR, intPtrToArg(s.VlanID), s.Source, s.Kind).Scan(&id, &firstStr, &lastStr)
	if err == sql.ErrNoRows {
		_, err = tx.Exec(`INSERT INTO subnets (tenant_id, cidr, vlan_id, source, kind, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			s.TenantID, s.CIDR, intPtrToArg(s.VlanID), s.Source, s.Kind,
			s.FirstSeen.Format(time.RFC3339Nano), s.LastSeen.Format(time.RFC3339Nano))
		return err
	}
	if err != nil {
		return err
	}

	// Compare as times: the stored strings may carry different zone offsets.
	first, _ := time.Parse(time.RFC3339Nano, firstStr)
	last, _ := time.Parse(time.RFC3339Nano, lastStr)
	if s.FirstSeen.Before(first) {
		first = s.FirstSeen
	}
	if s.LastSeen.After(last) {
		last = s.LastSeen
	}
	_, err = tx.Exec(`UPDATE subnets SET first_seen = ?, last_seen = ? WHERE id = ?`,
		first.Format(time.RFC3339Nano), last.Format(time.RFC3339Nano), id)
	return err
}

// GetSubnets returns a tenant's subnets. A nil filter value matches NULL.
func (r *SQLiteRepository) GetSubnets(tenantID string, filters map[string]interface{}) ([]*model2.Subnet, error) {
	query := `SELECT id, tenant_id, cidr, vlan_id, source, kind, first_seen, last_seen FROM subnets WHERE tenant_id = ?`
	params := []interface{}{tenantID}
	for key, value := range filters {
		if !subnetFilterColumns[key] {
			return nil, fmt.Errorf("unsupported subnet filter %q", key)
		}
		if value == nil {
			query += " AND " + key + " IS NULL"
			continue
		}
		query += " AND " + key + " = ?"
		params = append(params, value)
	}
	query += " ORDER BY cidr, vlan_id, source, kind"

	rows, err := r.db.Query(query, params...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var subnets []*model2.Subnet
	for rows.Next() {
		var s model2.Subnet
		var tenant sql.NullString
		var vlan sql.NullInt64
		var firstStr, lastStr string
		if err = rows.Scan(&s.ID, &tenant, &s.CIDR, &vlan, &s.Source, &s.Kind, &firstStr, &lastStr); err != nil {
			return nil, err
		}
		s.TenantID = tenant.String
		s.VlanID = nullIntToPtr(vlan)
		s.FirstSeen, _ = time.Parse(time.RFC3339Nano, firstStr)
		s.LastSeen, _ = time.Parse(time.RFC3339Nano, lastStr)
		subnets = append(subnets, &s)
	}
	return subnets, rows.Err()
}
