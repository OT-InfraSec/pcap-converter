# VLAN data: visualizer checklist

Status: draft, 2026-11-06. For: the maintainers of `web_visualizer` (closed-source).

Purpose: confirm that the visualizer reads the VLAN data written by the converter as specified. This closes gap G6 in [VLAN_DATA_OPEN_GAPS.md](VLAN_DATA_OPEN_GAPS.md).

Sources:
- Requirements: [.10x/specs/2026-10-20-vlan-data-requirements.md](../.10x/specs/2026-10-20-vlan-data-requirements.md) (R1, R2, R3, R5)
- Design: [.10x/specs/2026-10-20-vlan-data-design.md](../.10x/specs/2026-10-20-vlan-data-design.md)
- Confirmed decisions: [.10x/decisions.md](../.10x/decisions.md), entry of 2026-11-06
- Column reference: [db_schema.md](db_schema.md)

## 1. Schema marker (R5)

- [ ] The visualizer reads `PRAGMA user_version`. A value of 1 or higher means the database has VLAN data.
- [ ] A database with `user_version = 0` (written by an older converter) disables segment grouping and shows a "please re-import" notice.
- [ ] A version-1 database may have no subnet data yet. This is expected and must not be treated as an error (decision of 2026-10-20).

## 2. Column meaning (R1, R2)

- [ ] `packets.vlan_id`, `packets.vlan_inner_id`, `flows.vlan_id` and `flows.vlan_inner_id` are nullable.
- [ ] NULL means untagged (`vlan_id`) or no QinQ (`vlan_inner_id`). NULL is never VLAN 1 in the data.
- [ ] Flows with the same 5-tuple in two VLANs are two rows. Flow views must not merge them.
- [ ] The index `idx_flows_vlan(vlan_id, vlan_inner_id)` exists.

## 3. `devices.vlans` token format (R3)

The converter writes a comma-joined text value. It has no spaces and is sorted, so the output is stable.

| Token | Meaning |
|---|---|
| `untagged` | The address was seen in a frame with no VLAN tag |
| `N` | The address was seen with outer VLAN `N` only |
| `N.M` | The address was seen with outer VLAN `N` and inner VLAN `M` (QinQ) |

Examples:
- `untagged,100,100.200`
- `untagged,10,20` (a gateway in three segments)

Checks:
- [ ] Parse the tokens. Do not depend on their order. The sort is a converter detail.
- [ ] `untagged` is accepted as a token spelling. The spelling was not confirmed by the consumer before this checklist. Confirm it here.
- [ ] An empty or NULL value does not crash the page. The visualizer must not invent a VLAN for it. Report it to the converter maintainers if it appears after a fresh import.

## 4. Display rules

- [ ] A device with more than one token is drawn once per VLAN, with a warning (R3). Example: `untagged,10,20` gives three drawings and one warning.
- [ ] `untagged` is displayed as VLAN 1 (R1).
- [ ] If the capture has no tagged frames, hide the VLAN level. Check with `SELECT 1 FROM packets WHERE vlan_id IS NOT NULL LIMIT 1`. No row means no tagged frames.
- [ ] Decide how a `N.M` token is shown. The design does not say. This is a question for the visualizer side.
- [ ] Because one device row covers all its VLANs (gap G7), the splitting happens in the visualizer. Do not assume one row per VLAN.

## 5. Test cases

Until a real capture is available (gap G3), use hand-written database rows. Cover each case:

1. `untagged` only
2. `100` only
3. `100.200` only (QinQ)
4. `untagged,10,20`
5. empty value
6. database with no tagged frames at all
7. database with `user_version = 0`

When a capture is available, import it with the converter and check the page against the rows.

## 6. Report back

For each section, say whether it passes, fails, or is not implemented, and name the visualizer version tested. Please also confirm in writing:

- the `untagged` spelling
- the sort order you rely on, if any

We will record the answer in [.10x/decisions.md](../.10x/decisions.md).
