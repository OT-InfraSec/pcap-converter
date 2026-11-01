# Plan: Reach and Exceed Suricata's Protocol Analysis

**Goal:** match Suricata's protocol analysis, then go beyond it where IEC 62443
zone analysis needs it (OT protocols, L2 discovery, asset identification).
**Inputs:** findings F-01 to F-10 in `SURICATA_PROTOCOL_COMPARISON.md`.
**Rule for every phase:** spec first (RFC or vendor spec), then tests, then
code. Where this repo and Suricata disagree, the spec decides, and the
decision is recorded in the comparison doc.

---

## Progress

| Phase | State |
|---|---|
| 0 Test harness | **Done for local use.** `scripts/compare_suricata.py` runs Suricata 8.0.8 (midstream on) and the importer and diffs per flow. `--protocols enip,modbus,dnp3 --fail-on-miss` gates on the OT protocols and passes on the four captures. `PCAP_CORPUS=<dir> go test ./lib/detect -run 'TestCorpus'` checks the probes on real packets. **Not done:** CI job, and DNP3 / UDP 44818 / split-message traffic in the corpus. |
| 1 Detection framework | **Done for EtherNet/IP and Modbus.** `lib/detect` (registry, three-state probe, ENIP encapsulation and implicit I/O probes, Modbus probe and ADU splitter) and `internal/parser/connection_labeler.go`. F-01 to F-03 fixed and F-04 detection fixed, all checked against Suricata. DNP3 and OPC UA are registered with hint ports and no probe, so they stay port-only. |
| Data fix | **Done.** The importer dropped 90,468 of 276,653 packets (ARP requests, DNS queries and error responses, ICMP unreachable). All packets are stored now and a warning fires if read and stored differ. See "Dropped packets" in the comparison doc. |
| 2 Reassembly | Not started. Open question from the data: the Modbus and ENIP captures contain no split or pipelined messages (136,836 Modbus and 4,884 ENIP TCP payloads, all one message per segment), so there is no real traffic yet that shows reassembly changes results. Worth a capture with long responses (FC 3 with 125 registers across MSS limits, FC 23) before spending the effort. |
| 3 OT protocols | **Modbus:** decoder, validation events, lenient framing, TCP sequence tracking, all compared with Suricata on real and synthetic captures (`docs/SURICATA_PROTOCOL_COMPARISON.md`). **EtherNet/IP:** encapsulation decoder (`lib/detect/enip_decode.go`: RegisterSession, ListServices, ListIdentity with the device identity, ListInterfaces, SendRRData/SendUnitData with CIP service, class, instance, attribute, symbolic tag paths, general and extended status, Multiple Service Packet), `ENIPTracker` (TCP framing by length, sequence tracking, re-probe after a gap, UDP datagrams) and `compare_enip.py`: identical to Suricata on all three real ENIP captures. ListIdentity, UDP, SendUnitData and malformed traffic still need the synthetic captures of `docs/ENIP_SYNTHETIC_CAPTURES.md`. Next: DNP3, S7; vendor and device type name tables from the ODVA list (research). |
| 4 to 6 | Not started. |

## Guiding decisions (confirm before Phase 1)

1. **Content-based detection replaces port-based detection.** Ports become a
   hint that raises confidence, never the only evidence. This fixes F-04, F-05
   and F-06 together.
2. **One detection pipeline.** Today detection is spread over
   `industrial_parser.go`, `main.go` (`industrialPorts`) and
   `flow_canonicalizer.go`. Replace the three port tables with one registry:
   `Protocol{name, transports, hint ports, probe(payload) -> Recognized /
   Incomplete / Unrecognized, decoder}`. The three-state probe result mirrors
   Suricata and is needed for TCP streams where the first segment is short.
3. **TCP reassembly before app-layer parsing.** Suricata parses reassembled
   streams. We parse single packets, so we lose anything split across
   segments or pipelined in one. Parity needs per-flow stream buffers
   (gopacket `tcpassembly` or a small own reassembler with a size cap).
   This is the largest piece of work and is a prerequisite for the Modbus,
   DNP3, ENIP and TLS items.
4. **Differential testing against Suricata.** Run Suricata on the same PCAPs
   and compare its `eve.json` `app_proto` per flow with our result. This is
   the objective measure of "at least as good", and it also finds cases the
   spec reading misses.

## Phase 0: Test harness (do first)

- Build a corpus: Wireshark sample captures, Suricata's `qa/` and test PCAPs,
  ICS PCAPs (ICS-pcap collections, 4SICS), plus our own `test_data`.
- Script `scripts/compare_suricata.sh`: run Suricata offline (`-r`) with all
  ICS parsers enabled, read `eve.json` flow records, and diff per 5-tuple
  against our `flows`/`services` tables. Output: a table of agree, we-miss,
  we-extra.
- CI job runs it on a small fixed corpus and fails on regressions.
- Exit: baseline report committed. The numbers show what Phase 1 to 4 fix.

## Phase 1: Fix clear bugs and the detection framework (F-02, F-03)

1. Fix F-03: read the payload with `TransportLayer().LayerPayload()` in
   `isLikelyEtherNetIPPayload`. Add a regression test that fails on the old
   code (a TCP segment whose header bytes look like an ENIP header).
2. Implement the protocol registry and probe interface (decision 2).
3. Move ENIP detection to a strict probe equivalent to Suricata's:
   known command, known status, per-command length rules, accept `Nop`.
   Remove the dead `length < 0` check.
4. Keep the old port tables behind the registry as hints only, then delete
   them from `main.go` and `flow_canonicalizer.go`.
- Exit: ENIP differential results at least equal Suricata on the corpus.

## Phase 2: Stream reassembly (prerequisite for 3 and 4)

- Add per-flow, per-direction reassembly with bounded memory (cap per flow and
  total, evict by LRU), configurable depth (Suricata exposes
  `stream.reassembly.depth`).
- Respect the SQLite rule in `AGENTS.md`: no new concurrent DB writers.
  Reassembly state lives in memory, results are batch-written at the end.
- Probe and decode run on the reassembled buffer. Keep the single-packet path
  for UDP.
- Benchmarks on the large PCAP set. Set an allowed slowdown before starting.
- Exit: pipelined Modbus ADUs and split TLS records decode in tests.

## Phase 3: OT protocols (F-01, F-04, F-05)

Order by value for IEC 62443:

1. **EtherNet/IP and CIP** (F-01): match UDP 44818 and 2222, TCP 44818.
   Decode the encapsulation header (24 bytes, little endian), `ListIdentity`
   (vendor, product, serial, IP; the main device-identification source),
   `RegisterSession`, `SendRRData`, `SendUnitData`, and CIP service/class paths
   for the identity object. Suricata does not decode UDP 2222 implicit I/O, so
   decoding it gives us a lead over it.
2. **Modbus/TCP** (F-04): rewrite the decoder against the spec.
   Accept several ADUs per buffer, validate protocol ID with a recorded event
   instead of a hard failure, decode function codes, exception responses, and
   read/write addresses and quantities. Add the Suricata event set
   (invalid length, invalid protocol ID, flood, unsolicited response).
   Register on the registry with a content probe. Fetch `sawp-modbus` for the
   exact limits and compare.
3. **DNP3** (F-05): new decoder. Link layer (`0x0564`, length, control, CRC),
   transport layer, application layer (function codes, object headers,
   internal indications). Probe on start bytes and minimum length 5. Cover
   TCP and UDP. Suricata decodes objects; do the common groups first and mark
   the rest "raw".
4. **S7comm** (F-05): not in Suricata, so this is where we can lead. COTP/TPKT
   on port 102 plus S7 header and SZL reads (identity). Needed because
   `industrialPorts` already claims it. Until the decoder exists, report
   port-102 traffic as "unverified s7", not as confirmed.
5. **OPC UA**: already ahead of Suricata. Add tests against the Part 6 spec
   only; no parity work.
- Exit per protocol: spec-derived unit tests, fuzz test (the repo already has a
  fuzz pattern in `cdp_evidence_fuzz_test.go`), differential run no worse than
  Suricata.

## Phase 4: IT and discovery protocols (F-06, F-08, F-10, section 4 gaps)

Priority is asset identification and zone evidence, not full IDS coverage.

| Order | Protocol | Why |
|---|---|---|
| 1 | LLMNR (5355) | Missing hostnames. Small change on top of the DNS and mDNS code. |
| 2 | DHCP | Gives vendor class, hostname and lease data. |
| 3 | SMB 1/2/3 and NetBIOS name service (137) | Windows host identification. Register SMB on 139/445 by probe. |
| 4 | TLS | Move to content probe, SNI, certificates, JA3/JA4 (Suricata has them). Check TLS 1.3 draft and GREASE values (F-08). |
| 5 | Kerberos, LDAP | Domain controller and domain evidence. |
| 6 | SSH (HASSH), Telnet, NTP, SNMP | Service and OS fingerprints. |
| 7 | HTTP/2, QUIC, FTP, SMTP, MQTT, RDP, others | Only after the above, as demand shows. |

- mDNS (F-10): review field by field against RFC 6762 (QU bit, cache-flush
  bit, compression limits).
- Replace HTTP and HTTPS port lists (F-06) with content probes. Keep ports as
  hints.

## Phase 5: Link layer and tunnels (F-07)

- Check gopacket's EtherType table against Suricata's list and add what is
  missing: 802.1ah, E-Tag, VN-Tag, NSH, DCE.
- Remove the two-tag VLAN limit in `extractVLANTag` (or make it a documented
  cap) and check the schema for more than two tags.
- Tunnels: GRE, ERSPAN, VXLAN, Geneve, Teredo, IP-in-IP. Needed for mirrored
  OT captures (ERSPAN and GRE are common on SPAN-over-WAN setups).
- Finish STP (currently a stub): BPDU fields (root bridge, bridge ID, port
  roles) are strong evidence for L2 zone boundaries. Suricata has nothing here.
- Profinet DCP and RT (EtherType `0x8892`): neither tool decodes it. Add DCP
  (device name, role, IP) since it is the main Profinet discovery packet.

## Phase 6: Beyond Suricata (differentiators)

- Passive asset inventory from all identity sources (ENIP ListIdentity, S7 SZL,
  DHCP, SMB, CDP, LLDP, DNS) merged per device with a confidence score.
- Zone and conduit inference from VLANs, STP roots, CDP/LLDP neighbours,
  routing protocols (EIGRP) and flow matrices. This feeds the planned
  `internal/iec62443` package.
- IEC 62443 findings tied to observed protocol facts (for example Modbus
  write function codes from an IT-side address crossing a zone boundary).

## Cross-cutting rules

- **Robustness:** every new decoder joins the existing panic harness
  (`decoder_robustness_test.go`) and gets a fuzz test. Decode failures are
  counted and logged, not fatal (the repo already does this).
- **Schema:** new fields follow the regeneration approach in `AGENTS.md`;
  update `docs/db_schema.md` and the visualizer contract in the same change.
- **Documentation:** update `docs/INDUSTRIAL_PROTOCOLS.md` and this comparison
  doc as each finding closes. Each finding gets a status: open, decided,
  fixed, verified-by-differential-run.
- **Licensing:** Suricata is GPLv2 and this project is GPL (see LICENSE), but
  do not copy Suricata code. Implement from the specs and use Suricata only
  as a behaviour reference.

## Finding to phase map

| Finding | Phase |
|---|---|
| F-01 ENIP UDP port | 3.1 |
| F-02 ENIP weak heuristic | 1 |
| F-03 wrong bytes read | 1 (first commit) |
| F-04 Modbus | 2, 3.2 |
| F-05 DNP3 and S7 | 3.3, 3.4 |
| F-06 port-based labelling | 1 (registry), 4 |
| F-07 EtherTypes, VLAN depth | 5 |
| F-08 TLS | 4 |
| F-09 IGMP | confirm against RFC 3376, add DVMRP and PIM names; with Phase 5 |
| F-10 mDNS | 4 |

## Risks and open decisions

- **Reassembly cost** (Phase 2) on multi-GB captures. The database in the repo
  is 2.3 GB, so memory caps and benchmarks matter before the rollout.
- **Scope creep in Phase 4.** Suricata has about 40 parsers. "At least match"
  is best defined as: the differential run shows no flow where Suricata names
  a protocol and we name none, for the protocols we choose to support. That
  needs your decision on which of the section 4 protocols are in scope.
- **DNP3 object coverage.** Full object decoding is large. Decide whether
  parity means full objects or function codes and headers only.
- **Sequencing choice:** Phase 3 can start in parallel with Phase 2 for UDP
  protocols (ENIP over UDP, DNP3 over UDP), but Modbus and DNP3 over TCP wait
  for reassembly.
