# VLAN data: open gaps

Status as of 2026-11-06. Scope: cycle 1 of the segment data work (requirements R1, R2, R3, R5; design `.10x/specs/2026-10-20-vlan-data-design.md`; ADR-001). Subnets and CDP are out of scope here.

The VLAN work is merged (PR #15 and the commits after it). The test suite passes except five `internal/iec62443` tests. Those fail on main without the VLAN work and are not VLAN-related.

## Summary

| # | Gap | Type | Severity | Needs a decision? |
|---|---|---|---|---|
| G1 | Repository device upsert overwrites `devices.vlans` with an empty set | Latent bug, fixed 2026-11-06 (union merge in `UpsertDevice` and `UpsertDevices`, regression tests added) | Medium | No |
| G2 | Some device-creating paths never record VLAN | Resolved 2026-11-06: no code change needed, reasoning in design item 10, guard tests added | Low | No |
| G3 | No real-world VLAN capture has been tested | Verification gap | High | Needs a capture |
| G4 | Two design assumptions were never confirmed | Resolved 2026-11-06: confirmed, recorded in `decisions.md` | Medium | No |
| G5 | `devices.vlans` has no size limit | Resolved 2026-11-06: no cap for now, recorded in `decisions.md` | Low | No |
| G6 | Visualizer side of the contract is not verified | Verification gap | Medium | Needs the visualizer repo |
| G7 | A device seen in several VLANs is one row, by design | Known limitation | Info | No |

## G1: empty VLAN set can overwrite a stored set (latent bug)

**What:** `SQLiteRepository.UpsertDevice` writes `device.VLANSet.ToString()` on conflict. A device value without VLAN information therefore replaces the stored set with `""`.

**Evidence:** a temporary test (since removed) upserted a device with VLAN 10, then upserted the same address with an empty `VLANSet`. `GetDevice` returned `vlans = ""`.

**Pipeline exposure:** low. In `internal/parser/gopacket_parser.go`, the batch save at lines 1601 to 1640 runs before the post-processing calls at lines 1727, 1746 and 1806, which call `p.repo.UpsertDevice` with a bare `Device`. Those calls run only when the in-memory device manager has no entry, so the row should not exist yet. The overwrite needs a device already in the database that the manager does not hold. The code path does not show one, but nothing enforces it.

**Action:** make the device upsert merge the VLAN set (union with the stored value), or write it only when non-empty. Add a regression test for "upsert with VLAN, then upsert without VLAN keeps VLAN".

## G2: some device paths never record VLAN

**What:** `RecordVLAN` is called only in the main packet loop (`gopacket_parser.go` lines 1501 and 1507). These calls are gated on `srcMAC != ""` / `dstMAC != ""`. Other paths create or update devices without a VLAN:

- DNS query devices, lines 379 and 383
- SSDP query devices, line 471
- Additional-data upserts, lines 793 to 826
- Flow-endpoint upserts, line 1617

**Practical impact:** small. An IP address that sends an Ethernet frame gets its VLAN from the main loop, so most devices already have the correct set. The gap matters only for an IP seen in a frame without an Ethernet header, which carries no VLAN tag anyway. The remaining exposure is an IP that appears only in one of these paths.

**Action:** call `RecordVLAN` at these sites where the frame's VLAN is known, or record in the design why it is not needed. This is cleanup, not a correctness fix.

## G3: no real-world VLAN capture has been tested (high)

**What:** the QA report says "Not covered: real-world captures with VLAN tags". The repository has no `.pcap` files. All VLAN tests use synthesized packets (single 802.1Q, QinQ with 0x88a8 and 0x9100, VID 0, VID 1, untagged-only).

**Why it matters:** the parser assumes the first non-zero Dot1Q layer is outer and the second is inner. Real switch trunks, Cisco native VLANs and multi-VLAN gateways have not been checked against that assumption.

**Action:** capture or obtain traffic that covers these cases:

1. Single-tagged access traffic
2. QinQ (provider bridge) traffic
3. One IP address seen in several VLANs and in untagged frames
4. An untagged-only capture, to confirm the "no tagged frames" signal R1 depends on

Add a small committed fixture, or document the capture in `docs/` in the same format as the other synthetic capture specs.

## G4: two design assumptions were never confirmed

The design marks these as "please confirm". The `.10x/decisions.md` log has no entry that confirms them.

1. **VID 0 is treated as untagged.** A priority-tagged frame (VID 0) carries no VLAN membership, so it is stored as NULL. The assumption is reasonable, but the user has not confirmed it.
2. **Token format `untagged`, `100`, `100.200`.** The design calls this the visualizer contract. Its sort order and the spelling `untagged` were not confirmed by the consumer.

**Action:** confirm both with the user, and record the answer in `.10x/decisions.md`. If the answer changes either point, update the design, ADR-001 and `docs/db_schema.md`.

## G5: `devices.vlans` has no size limit

**What:** the cycle 3 CDP work added a 100k row cap for `subnets`. `devices.vlans` has no cap. A device seen in many VLAN IDs, or a capture with many QinQ pairs, produces a long comma-joined string, and the set is loaded in full on every `GetDevice` and `GetDevices`.

**Action:** decide whether a cap is needed. If so, pick a limit and a policy for values beyond it (drop, count, or log). If not, note in the design that the size is bounded only by the number of distinct VLAN combinations per IP.

## G6: visualizer side of the contract is not verified

**What:** the requirements say the visualizer draws a device once per VLAN with a warning, treats untagged as VLAN 1 for display, and uses `user_version >= 1` to detect the schema. The `web_visualizer_go` source in `/Users/patrick/gitRepos/pcap-importer` has no code that parses the `vlans` token format or checks `user_version` (a search for `untagged`, `user_version` and `vlans` found nothing outside the converter).

**Action:** confirm in the visualizer repository that it reads `vlans` tokens exactly as specified, handles the `untagged` token, and uses `user_version` as R5 describes.

## G7: one device row per IP across VLANs (by design)

ADR-001 keeps one row per IP and records its VLANs in a set. A gateway that sits in several VLANs appears once, with a set such as `untagged,10,20`. The requirements say the visualizer draws it once per VLAN. This is intended, but it means the visualizer must do the splitting. Listed so the consumer side is not forgotten.

## Not VLAN-related

- Five `internal/iec62443` tests fail on main without the VLAN work (`TestCommunicationPatternAnalyzer_*` and `TestDeviceClassifierImpl_AnalyzeRequestResponsePatterns`). They are heuristic disagreements and need a product decision, not a VLAN fix.

## Already fixed (for reference)

- The first packet of every capture was lost because packet IDs started at 0 (fixed, regression test added).
- Outer QinQ ethertype 0x9100 is decoded as Dot1Q (fixed).
- `GetDevice` handles NULL columns (fixed).
- `AddPackets` stores `protocol`, and `UpdatePacket` writes `flow_id` and VLAN (fixed).
- The `internal/dns` mock gained `LinkPacketsToFlows` (fixed).

## Recommended order

1. G3: obtain a real VLAN capture. It is the only check that can find a parser error the synthetic tests cannot.
2. G1: fix the upsert overwrite and add its regression test.
3. G4: get the two confirmations, then record them.
4. G6: check the visualizer in its own repository.
5. G2 and G5 as cleanup and policy.
