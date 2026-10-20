# Cycle 1: VLAN data (R1, R2, R3, R5)

Part of [segment data overview](2026-10-20-segment-data-overview.md).

## R1: VLAN tags on packets
- Store the outer 802.1Q VLAN ID and, for QinQ (802.1ad), the inner VLAN ID per packet.
- Untagged frames are stored as **NULL**, not 1. The visualizer treats untagged as VLAN 1, but must be able to tell whether a capture contains any tagged frames at all (if not, the VLAN level is hidden).

## R2: VLAN on flows
- The VLAN (outer, and inner if present) becomes part of the flow key: the same 5-tuple seen in two VLANs is two flows.
- Same NULL convention as R1.

## R3: VLAN set per device
- Each device records the set of VLANs it was seen in, analogous to `mac_addresses` (including a marker for "seen untagged").
- A device seen in more than one VLAN is valid data and must not be collapsed; the visualizer draws it once per VLAN with a warning.

## R5: Schema version marker
- Set `PRAGMA user_version` to 1 or higher (visualizer ADR 0005) once the database contains the data, so the visualizer can detect databases from older converters and disable segment grouping with a "please re-import" notice.

## Open questions for design
- R5 says the marker is set once R1-R4 data exists. With the split, should cycle 1 set `user_version = 1` (VLAN only) and cycle 2 bump it to 2? Otherwise a v1 database would lack subnets. Needs confirmation against visualizer ADR 0005.
- Flow key change: how do existing flow canonicalizer and `flow_manager.go` handle the added VLAN dimension, and how are `packets.flow_id` links affected?
- Device set encoding for "seen untagged": follow `mac_addresses` text-set pattern with a sentinel, or a separate representation?
