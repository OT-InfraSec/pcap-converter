# Protocol Comparison: pcap-converter vs. Suricata

**Status:** open findings. None of these differences has been resolved. Each
one needs a look at the RFC or vendor specification before we decide which side
is correct. A difference from Suricata does not mean this repo is wrong.
Suricata is an IDS tuned for low false positives, and we are doing asset and
zone discovery, so the goals differ.

**Reference:** `/Users/patrick/gitRepos/suricata/docs/protocols.md`, checked
against the Suricata source tree (`suricata.yaml.in`, `src/decode-ethernet.h`,
`src/app-layer-*.c`, `rust/src/{enip,modbus,dnp3,mdns,llmnr,snmp,smb}`).

**Scope:** protocols that both projects handle. Protocols that only one side
implements are listed in section 3 and 4 for completeness.

---

## Finding status

Verified against Suricata 8.0.8 on the four captures in
`minicps-testbed/prototype/captures` (see "Differential results" below).
Suricata runs with `stream.midstream=true`, see "Midstream sessions".

| ID | Status | Notes |
|---|---|---|
| F-01 | **fixed** | UDP 44818 is detected (unit and integration tests; the captures contain no UDP 44818 traffic, so this is not yet checked on real data). UDP 2222 is kept and now decoded as implicit I/O. |
| F-02 | **fixed, spec review open** | Strict probe in `lib/detect/enip.go`, same rules as Suricata. Still to confirm against the ODVA spec. |
| F-03 | **fixed** | Payload comes from `tcp.Payload` / `udp.Payload`. The new tests fail on the original code for F-01, F-02 and F-03. |
| F-04 | **partly fixed** | Detection is by content now (`lib/detect/modbus.go`: MBAP header, protocol ID 0, length 2..254, valid function code), port 502 only raises confidence. Agrees with Suricata on all 13 Modbus flows in the capture. Still open: decoder rewrite (pipelined ADUs, exceptions, events), the exact `sawp-modbus` limits, and a comparison on pipelined or split traffic: the capture has exactly one ADU per segment, so it cannot show whether reassembly matters. |
| F-05 | partly addressed | S7 no longer claimed from port 102. DNP3 still port-only. No DNP3 traffic in the captures. |
| F-06 | partly addressed | Industrial port knowledge lives in the `lib/detect` registry. HTTP, TLS and DNS labelling is still port-based. |
| F-07 to F-10 | open | Phase 4 and 5. |

### Differential results (Suricata 8.0.8 vs this importer)

Flows are matched on host pair plus port sets, because one of our flow rows
aggregates every connection between two hosts that shares a label.

| Capture | Suricata OT flows | Agree | Missed (OT) | Other misses |
|---|---|---|---|---|
| m13e880-br-seg1 | 39 ENIP | 39 | 0 | 84 SNMP |
| m13e880-br-seg2 | 20 ENIP | 20 | 0 | 105 SNMP |
| m13e880-br-seg3 | 1 ENIP | 1 | 0 | 105 SNMP |
| capture_2026-06-02_11 | 13 Modbus | 13 | 0 | none (all 1,039 Suricata flows agree) |

`python3 scripts/compare_suricata.py --protocols enip,modbus,dnp3 --fail-on-miss
<pcaps>` gates on the OT protocols and passes on all four.

- **Packet level** (`PCAP_CORPUS=... go test ./lib/detect -run TestCorpusENIP`):
  all 189,140 UDP 2222 datagrams and all 4,884 TCP 44818 payload segments are
  recognised, with zero rejected. 632 payloads on other ports: zero false
  positives. 2,000,000 random payloads: zero false positives. A 20 s fuzz run
  (13 million executions) found no panic.
- **Modbus, packet level** (`go test ./lib/detect -run TestCorpusModbus`):
  all 136,836 TCP 502 payloads recognised, each exactly one ADU, none pipelined
  or split. 140,306 payloads of other traffic (including the ENIP captures):
  zero Modbus false positives. The ENIP probes see the 136,836 Modbus payloads
  as other traffic: zero false positives. Fuzzing the Modbus probe and splitter:
  10 million executions, no failure.
- **Flows we have and Suricata does not:** 22 + 8 UDP 2222 flows (implicit I/O;
  Suricata reports these as failed), ICMPv6, SSDP. These are intended
  differences, not errors.
- **Known gap:** SNMP (UDP 161). The DNS misses seen earlier in the Modbus
  capture came from the dropped packets below and are gone. Suricata parses it, we label the flows `udp`.
  Phase 4.
- **Regression found and fixed while testing:** the first Phase 1 version split
  every ENIP connection into two flows (handshake and ACK segments carry no
  payload and fell back to `tcp`), and dropped the UDP 2222 implicit I/O
  traffic, which has no encapsulation header. Both are fixed: a
  per-connection labeler (`internal/parser/connection_labeler.go`) keeps one
  label per connection, and `ProbeENIPImplicitIO` recognises the 2222 format.
  After the fix the flows, services and `industrial_devices` tables are
  identical to the pre-change importer on all three captures.

### Midstream sessions

The Modbus capture starts inside TCP sessions: hosts 192.168.24.85 and .90
(about 60,000 packets) have no SYN. With its default `stream.midstream: false`
Suricata ignores them: flow state `new`, no app protocol. We label them
Modbus, correctly, since the payload is valid Modbus. With
`stream.midstream=true` Suricata finds them too. The harness therefore runs
Suricata with midstream enabled, and this is a place where this tool is ahead
of Suricata's default configuration.

### Dropped packets (found and fixed)

The `packets` table held 186,185 of the 276,653 packets in
`capture_2026-06-02_11.pcap`. Three `continue` statements in
`internal/parser/gopacket_parser.go` threw the whole packet away, so it was
also missing from flows and its sender was never discovered:

| Skipped | Packets lost here | Why it was wrong |
|---|---|---|
| ARP requests | 89,231 | Hid ARP scans and storms, and senders that only send requests. |
| DNS packets without answers (every query, NXDOMAIN, SERVFAIL, empty responses) | 1,237 | Only answered responses were kept; failed lookups are security-relevant. |
| ICMP destination unreachable | 0 here | Same problem, no such packets in this capture. |

The two numbers add up to the gap exactly (90,468). Now all four captures store
every packet (276,653, 147,062, 50,678, 476 of the same on the wire). The
importer logs a warning if packets read and packets stored ever differ.

What changed in the data model, deliberately:
- Every packet is stored, including ARP requests and all DNS packets
  (the DNS layer now has an `rcode` field).
- `dns_queries` keeps its meaning: only answered responses (141 rows, same as
  before). Failed lookups are in `packets` and the DNS flow but not in that
  table. Recording them there is a possible follow-up.
- An ARP request creates no flow and no device for its *target*, because the
  target may not exist. A reply from it creates both, as before. An ARP probe
  (sender 0.0.0.0) creates no device. Devices are identical to the old output on
  all four captures (29, 27, 26, 24).
- DNS flows now include the queries: the DNS flow of the Modbus capture holds
  2,261 packets instead of 1,024. After this, the capture agrees with Suricata
  on all 1,039 flows it names (zero misses, all protocols).

What the old code hid: in this capture host 10.90.90.90 sent 88,613 ARP requests
for 359 different public addresses within 20 minutes. It is ARPing for Internet
hosts directly, which means no working default gateway or a netmask that is too
wide. They are in `packets` (`protocol = 'arp'`, request operation) but nothing
reports them yet. That is a candidate finding for the zone analysis.

A second bug surfaced while testing: `AddFlow` called `log.Fatalf` when a flow
endpoint had no device row. That ends the process with exit code 1, and the only
trace is a line in `importer.log`. It now returns an error naming the address,
and the parser makes sure every flow endpoint has a device before saving.

Still open, found on the way and not touched:
- The capture repeats most TCP packets (same bytes, second copy with `seq 0:n`),
  so flow packet counts are about double the real traffic. Suricata sees the
  same duplicates.
- `GetDNSQueries` cannot scan the `query_result` column into its map and returns
  an error. For responses, the querying and answering device are swapped in
  `dns_queries` (the packet's source is the resolver).

Behaviour changes from Phase 1 that the visualizer may notice:
- `protocol_usage_stats` no longer gets a zero-count row for every handshake or
  ACK segment on an EtherNet/IP or Modbus port, only for packets that carry
  protocol content. Modbus: 91,752 such rows fewer on the Modbus capture. First/last-seen per device and the flow tables are unchanged.
- Garbage on an EtherNet/IP port is no longer labelled EtherNet/IP. A
  connection on port 44818 is labelled until its content shows it is something
  else (then it is not, from that packet on; the packets before it keep the
  label).
- EtherNet/IP content on an unusual port is now labelled, from the first
  recognised packet.
- `cmd/importer` no longer maps port 102 to `s7` in the flow-based industrial
  analysis.
- The flow canonicalizer now also knows DNP3 (20000) as a service port.

Not covered by real data yet: DNP3, UDP 44818, TCP messages that are split or
pipelined (the Modbus and ENIP captures contain none), and Modbus function
code decoding.

---

## 1. Differences to resolve

Each finding has an ID, what this repo does, what Suricata does, and the
question to settle.

### F-01 EtherNet/IP UDP port: 2222 vs. 44818 (high)

| | Behaviour |
|---|---|
| This repo | UDP traffic is recognised as EtherNet/IP on port **2222**. TCP uses 44818. Places: `internal/parser/industrial_parser.go` (`isEtherNetIPPort`, `parseEtherNetIP`, `determineDirection`), `lib/helper/flow_canonicalizer.go` (2222 mapped to "EtherNet/IP"), `cmd/importer/main.go` (`industrialPorts`, "implicit_io"). |
| Suricata | The ENIP parser is registered for **UDP and TCP** with default port **44818**, `detection-ports: dp: 44818, sp: 44818`. Port 2222 appears nowhere. |

Open question: per ODVA, UDP 2222 carries implicit (class 1) I/O, and UDP 44818
carries encapsulation commands such as `ListIdentity` broadcasts. We probably
need both ports. The repo never matches UDP 44818, so it misses `ListIdentity`
discovery, which is the most useful packet for device identification.

### F-02 EtherNet/IP is detected by a weak payload heuristic (medium)

`isLikelyEtherNetIPPayload` accepts any transport payload of at least 24 bytes
whose first 16-bit little-endian value is non-zero and whose length field fits
the payload. It does this before it looks at ports.

Suricata (`rust/src/enip/enip.rs`, `probe`) is stricter:
- `command` must be one of: `Nop 0x00`, `ListServices 0x04`, `ListIdentity 0x63`,
  `ListInterfaces 0x64`, `RegisterSession 0x65`, `UnregisterSession 0x66`,
  `SendRRData 0x6F`, `SendUnitData 0x70`, `IndicateStatus 0x72`, `Cancel 0x73`.
- `status` must be a known value: `0, 1, 2, 3, 0x64, 0x65, 0x69, 0x6A`.
- `Nop` requires `options == 0`. `RegisterSession` requires length 4.
  `UnregisterSession` requires length 4 or 0. `ListInterfaces` must parse.

Differences:
- We do not check the command against the known list, so any non-zero value
  passes. Random UDP or TCP payloads are likely to be misclassified. The check
  also runs on the transport layer contents (see F-03).
- The repo requires `cmd != 0`, so it rejects `Nop (0x00)`, which Suricata
  accepts.
- `length < 0` can never be true for a `uint16`. The check is dead code.
- The repo does not validate the status field.

Open question: which commands and status codes does the ENIP spec define, and
do we want a strict or a lenient detector?

### F-03 EtherNet/IP payload check reads the wrong bytes (medium)

`isLikelyEtherNetIPPayload` uses `packet.TransportLayer().LayerContents()`. For
TCP and UDP, `LayerContents()` is the transport **header** (20 or more bytes
for TCP, 8 for UDP), not the application payload. So the 24-byte header test
reads TCP/UDP header bytes. This is probably a bug and not a protocol
difference, but it changes the F-02 results, so it is noted here.

### F-04 Modbus/TCP: recognition rules differ (high)

| | This repo | Suricata |
|---|---|---|
| Port | TCP 502, port only (`isModbusTCPPort`). | TCP 502 is the detection port. The parser is also probed on content. |
| Parser | `lib/layers/modbustcp.go` (own MBAP decoder). Not registered on any TCP port, so it is never attached automatically. | `sawp-modbus` crate (Rust, `rust/src/modbus/modbus.rs`). `src/app-layer-modbus.c` only holds registration and unit tests. |
| Protocol ID | `ModbusProtocol` stores the value. Only `0` is named "Modbus". A non-zero ID does not fail decoding. | Non-zero protocol ID raises event `modbus.invalid_protocol_id`. |
| Length bounds | Rejects data shorter than 9 bytes (`7 + 2`) or longer than 260 bytes (`7 + 253`). Both set `Truncated`. | Length handling lives in sawp-modbus (`InvalidLength` event). The exact limits were **not verified**, because the crate is not in the Suricata tree. |
| Multiple ADUs in one segment | Rejected: more than 260 bytes is an error, so a TCP segment with several pipelined ADUs fails. | Parses several messages from one buffer (`inner_rest` loop in `modbus.rs`). |
| `Length` field | Fails if `Length > len(payload)+1`. A `Length` smaller than the real payload is accepted. | Not verified. |
| Confidence | 0.7, raised to 0.8 on port match alone. | Content probe decides. |

Open questions:
- MODBUS Application Protocol V1.1b3 and the Messaging on TCP/IP Implementation
  Guide V1.0b: what is the legal maximum ADU size (260 bytes), and should
  pipelined ADUs in one segment be accepted?
- Do we need `ProtocolIdentifier != 0` to count as a decode error?
- Port-only detection can label any port-502 traffic as Modbus. Do we want a
  content probe like Suricata?

### F-05 DNP3 and S7: port-only detection, no parser (medium)

| | This repo | Suricata |
|---|---|---|
| DNP3 | Port **20000** is listed in `cmd/importer/main.go` (`industrialPorts`). No decoder in `lib/layers`. `determineServiceType` returns `"unknown"` for it. | Parser in `src/app-layer-dnp3*.c`. Probe checks the link-layer start bytes `0x05 0x64` and a minimum length field of 5 (`DNP3_MIN_LEN`). It is TCP, with UDP also registered. |
| S7 / S7comm | Port **102** is mapped to `"s7"` in `main.go`. Port 102 is also used by ISO-TSAP and by IEC 61850 MMS. | **Not supported** (see Suricata doc section 3.2). No reference exists. |

Open question: DNP3 has a defined start-byte signature (`0x0564`). A content
check would remove false positives on port 20000. The DNP3 UDP variant is not
handled here at all.

### F-06 Ports used for service identification differ (medium)

Hard-coded port to service tables in this repo and the nearest Suricata
setting.

| Port / service | This repo | Suricata |
|---|---|---|
| HTTP 80, 8080, 8000, 3000, 8888 (`lib/layers/http.go`) | Registered as HTTP on TCP. | No HTTP detection ports. HTTP is found by content, on any port. |
| HTTP 8000, 8080 in `flow_canonicalizer.go` | Labelled "HTTP". | Same as above. |
| HTTPS 443, 8443 (`flow_canonicalizer.go`) | Labelled "HTTPS". | TLS is found by content. `suricata.yaml.in` lists 443 as the TLS detection port (line ~971). 8443 is not listed. |
| DNS 53 | Labelled "DNS". | DNS detection port 53, TCP and UDP. |
| SNMP 161, 162 | Labelled "SNMP". | Default ports 161 and 162, same. |
| SSH 22, Telnet 23 | Labelled. | Detected by content. |
| mDNS 5353 | `RegisterUDPPortLayerType(5353, LayerTypeMDNS)`. | UDP, default port `[5353]`. Same. |
| LLMNR 5355 | **Not implemented.** | Parser, detection port 5355 (TCP and UDP). |
| SMB 139, 445 | `lib/layers/smb_protocol.go` has an own decoder. Port registration was **not found** in `lib/layers`. | Detection ports `139, 445`. |
| NetBIOS Datagram UDP 138 | Registered. Port 137 (name service) is checked by the industrial parser, but no layer is registered for it. | No NetBIOS parser at all. |
| SSDP 1900 | Registered. | **No SSDP parser.** |

Open question: the repo labels services by port, so a service on a non-standard
port is missed, and a different service on 80/8080 is labelled HTTP. Do we want
content-based detection, as Suricata does, at least for the protocols we parse?

### F-07 Link layer: EtherType coverage (low to medium)

Suricata's decoders (`src/decode-ethernet.h` and the table in Suricata's
`docs/protocols.md` section 1.2) against this repo. This repo uses gopacket's
own EtherType table, plus one local addition (`0x9100`).

| EtherType | Suricata | This repo |
|---|---|---|
| `0x0800` IPv4, `0x86DD` IPv6, `0x0806` ARP | Decoded. | Decoded by gopacket. |
| `0x8100` 802.1Q, `0x88A8` 802.1ad | Decoded as VLAN. | Decoded by gopacket. |
| `0x9100` legacy QinQ | `ETHERNET_TYPE_8021QINQ`, decoded as VLAN. | Added by us in `gopacket_parser.go` (`ethernetTypeQinQLegacy`). **Same.** |
| `0x88E7` 802.1ah (PBB) | Decoded. | No explicit handling. |
| `0x8863` / `0x8864` PPPoE | Decoded. | gopacket default. |
| `0x8847` / `0x8848` MPLS | Decoded. | gopacket default. |
| `0x8903` DCE, `0x893F` E-Tag, `0x8926` VN-Tag, `0x894F` NSH | Decoded. | No explicit handling. Not checked against gopacket's table. |
| `0x8892` Profinet | Not decoded. | Not decoded. **Same.** |

VLAN depth is another difference. This repo records the outer and one inner
tag only (`extractVLANTag`, the third and later tags are dropped). Suricata
has a configurable limit and no fixed cap of two in the decoder (limit not
verified here). Open question: do we need to keep a third tag?

### F-08 TLS: versions and detection (low)

- `lib/layers/tls.go` names versions `0x0200` (SSLv2), `0x0300`, `0x0301`,
  `0x0302`, `0x0303`, `0x0304`. Suricata (`app-layer-ssl`) covers SSLv2/v3 and
  TLS 1.0 to 1.3, so the set matches. Not compared: how each handles TLS 1.3
  draft versions (`0x7Fxx`) and GREASE values.
- The repo has no port registration for TLS. Suricata detects by content
  (with 443 as a hint). Whether `tls.go` attempts decoding on every TCP payload
  was not checked.

### F-09 IGMP: message type values (low)

`lib/layers/igmp.go` defines `0x11` query, `0x12` v1 report, `0x16` v2 report,
`0x17` leave, `0x22` v3 report. These agree with RFC 2236 and RFC 3376 as far
as I know. Suricata's `decode-igmp.h` carries no type table (it exposes a
header struct only), so there is nothing to compare against. No difference
found, listed so nobody re-checks it. Please confirm against RFC 3376 before
relying on it (for example, DVMRP `0x13` and PIM-in-IGMP `0x14` are not named).

### F-10 mDNS: parsed on a port, Suricata decodes differently (low)

Both use UDP 5353. Suricata's `mdns` is a separate parser from `dns`, with its
own transaction logic. This repo's mDNS decoder is separate from DNS, so the
design is the same. The record types and flag handling (QU bit, cache-flush
bit, name compression limits) were **not compared field by field**. This is
worth a second pass against RFC 6762.

---

## 2. Things that match

- Modbus port 502, ENIP TCP 44818, mDNS 5353, SNMP 161/162, DNS 53.
- Legacy QinQ EtherType `0x9100` is treated as a VLAN tag in both.
- Profinet (`0x8892`) and OPC UA are not decoded at link/flow level by Suricata,
  and this repo does not rely on Suricata for them.

---

## 3. In this repo, no Suricata equivalent (no reference available)

| Protocol | Location | Note |
|---|---|---|
| OPC UA binary (TCP 4840) | `lib/layers/opcua.go`, `internal/parser/industrial_parser.go` | Suricata does not recognise OPC UA, so any check must come from the OPC UA specification (Part 6). |
| CDP | `lib/layers/ciscoDiscovery.go`, `internal/parser/cdp_*.go` | No Suricata decoder. |
| LLDP | `lib/layers/lldp.go` | No Suricata decoder. |
| EIGRP | `lib/layers/eigrp.go` | Raw IP protocol 88. Suricata has no EIGRP decoder. |
| STP | `lib/layers/stp.go` | Stub only: `DecodeFromBytes` is a TODO and `decodeSTP` does not parse any field. |
| SSDP | `lib/layers/ssdp.go` | No Suricata parser. |
| NetBIOS, CIFS Browser, SMB mailslot | `lib/layers/netbios.go`, `cifsbrowser.go`, `smb_mailslot.go` | Suricata has an SMB parser, but no NetBIOS datagram or browser parser. |

## 4. In Suricata, not in this repo

SCTP, GRE/ERSPAN, VXLAN, Geneve, Teredo, IPsec ESP/AH header decode,
FTP, SMTP, IMAP, POP3, SSH (HASSH), Telnet, NFS, DCE/RPC, DHCP, NTP, TFTP,
Kerberos, LDAP, SIP, IKE, QUIC, MQTT, PostgreSQL, RDP, RFB, BitTorrent DHT,
HTTP/2, LLMNR. Not all of them matter for IEC 62443 zone analysis.
LLMNR, DHCP, Kerberos and LDAP are the likely candidates for device
identification.

---

## 5. Notes on the Suricata document

While checking, I found points in `suricata/docs/protocols.md` that do not
match the source. We should not rely on those lines until corrected.

- **Modbus** is listed as `C` (`app-layer-modbus.c`). The parser is Rust:
  `rust/src/modbus/modbus.rs`, built on the `sawp-modbus` crate. The C file
  only registers it and holds unit tests.
- **DNP3** is listed as C only. There is also `rust/src/dnp3` (detect and log).
  The parser itself is still C.
- **ENIP** transport is given as "T and U". The registration code in
  `rust/src/enip/enip.rs` sets `ipproto: IPPROTO_UDP` for the first
  registration. The TCP registration follows later in the same function and
  was not read in full.
- The Suricata document itself says its transport and port details were
  not checked line by line.

## 6. What I did not check

- `sawp-modbus` source (not in the tree), so Modbus length limits and probe
  rules are unverified.
- The TCP ENIP registration in full, and CIP service decoding.
- gopacket's EtherType table against Suricata for the rarely used types.
- Field-level decoding for DNS, mDNS, SMB and TLS handshake parsing. Only port
  and detection behaviour were compared.
- Test coverage for any item above.

## 7. Suggested next steps

1. Decide F-01, F-02 and F-03 first. They affect the main target protocol
   (EtherNet/IP) and F-03 looks like a plain bug.
2. Read the Modbus spec for F-04, then fetch `sawp-modbus` for the exact limits.
3. Add content probes for DNP3 (`0x0564`) and Modbus, to cut port-only guesses.
4. After the RFC review, record each decision in this file with its outcome.

## Modbus message-level differential (`scripts/compare_modbus.py`)

Runs Suricata 8.0.8 with the `modbus` eve logger and `scripts/modbus_dump`
(our `lib/detect` decoder) on one capture and compares requests by (client,
server, transaction id, unit, function, address) and responses by (server,
client, transaction id, function, exception). Capture:
`capture_2026-06-02_11.pcap` (only capture with Modbus).

| | Suricata | Ours | Both |
|---|---|---|---|
| Requests | 12,307 | 12,356 | 12,307 |
| Responses | 12,303 | 12,356 | 12,303 |

Everything Suricata logs, we decode identically (function, unit, address,
exception). The first run showed 662 FC23 mismatches: our decoder did not read
the address of Read/Write Multiple Registers. Fixed (read range in
`Address/Quantity`, write range in `WriteAddress/WriteQuantity`).

Remaining difference: 49 requests and 53 responses of FC16 (qty 62, host
192.168.24.111) exist only on our side. Cause: Suricata logs a `modbus.flooded`
anomaly (pcap packet 168139) and gives up on that flow after its transaction
limit (`request-flood`) is reached. The capture contains every packet twice,
so unanswered duplicates pile up. Suricata stops tracking Modbus on that flow;
we still decode it. **Suricata limitation, not a bug here.**

Anomaly events: our decoder raised none (`unknown_function`,
`invalid_exception_code`). Suricata raised `value_mismatch` 25,885 times, on
every FC3 response, although the raw bytes are well formed (MBAP length 11,
byte count 8, 4 registers). Cause found in `sawp-modbus` (`Message::matches`,
main branch, not verified against the 0.13.1 Suricata pins): for a plain read
the response size is checked as a bit-packed size, `ceil(quantity / 8)` bytes,
whichever function it is. A register read of 4 registers has 8 data bytes
and 1 expected, so every valid FC3/FC4 response is flagged. Only the
read/write variant (FC23) uses `2 * quantity`, which is why FC23 is clean.
This is a Suricata false positive. Do not copy it. The consequence for
analysis: alerts or rules on `modbus.value_mismatch` fire on every register
read.

Not covered by real traffic: exception responses, FC1/2/4/5/6/15, diagnostics,
`invalid_length`, `invalid_value`, `unsolicited_response`, `invalid_protocol_id`.
Those need synthetic captures.

## Modbus synthetic captures: results

Captures: `minicps-testbed/build/modbus_synthetic` (generated from
`MODBUS_SYNTHETIC_CAPTURES.md`, 9 pcaps, 41 connections), compared with
`scripts/compare_modbus.py` (Suricata 8.0.8, midstream on). Transactions and
events agree on groups A and B and on every well-formed row of the others.

| Class | Scenarios | What differs | Status |
|---|---|---|---|
| Validation events | D1-D3, D5-D10, D12-D17 | none: `invalid_length` / `invalid_value` agree on all 15 | **Done, matches Suricata** |
| Exception codes | B | `invalid_exception_code` 2 = 2 (incl. 08 on FC3, 02 on FC7) | Matches |
| Framing: protocol id, length outside 2..254 | D11, E1-E5, E8 | Suricata keeps decoding inside a connection it already recognised and raises `invalid_protocol_id` / `invalid_length`. We drop the ADU, so those transactions and events are missing | **Gap**, needs a lenient framing mode for connections already labelled Modbus |
| Function codes in requests | C | Requests with fc `0x80`-`0xFF` (and 0): we read the high bit as an exception and report `invalid_exception_code`; Suricata calls them `invalid_function_code` and keeps the raw code | **Bug**: no exceptions exist in the request direction |
| Unassigned codes (`0x09`...) | C | we raise `unknown_function`, Suricata nothing | Intended divergence |
| TCP reassembly | E9, G2-G5, G9, H5 | ADUs split across segments are not decoded by us (11 transactions on these connections) | **Evidence for Phase 2** |
| Retransmission | I1, I2, I4 | we count a retransmitted ADU twice, Suricata once | Needs TCP sequence tracking (Phase 2) |
| Transaction pairing | F1-F4, F8, H3, I5, E-group | `unsolicited_response` raised only by Suricata, as is `value_mismatch` (F5-F7; also fires on every register read, see above) | We do not pair requests with responses |
| Request flood | F9 | Suricata stops at 501 of 600 requests (`flooded`); we decode all 600 | Suricata limit |
| HTTP then Modbus on 502 | H4 | Suricata recognises no Modbus on that connection; we decode both exchanges (content probe per packet) | We are better here |
| First packet | H1-H3, H6-H9 | agree (IPv6 and VLAN included) | Matches |

Manifest notes: the D rows' `expect_our_events` are stale (generated before
the validation rules existed); D11 in the capture is the old "qty 124,
MBAP length 255" case, which is a framing case, not `invalid_value`.
