# Synthetic EtherNet/IP captures: specification

Audience: an agent in the simulation environment that produces the captures.
Purpose: the real captures (`m13e880-br-seg1..3.pcap`) hold only RegisterSession
and SendRRData over TCP 44818 with a handful of CIP services. They have no
ListIdentity (normally UDP), no ListServices/ListInterfaces, no SendUnitData,
no Multiple Service Packet, no extended status, no malformed or split messages.
These captures cover them, so `scripts/compare_enip.py` can compare our decoder
(`lib/detect/enip_decode.go`, `enip_stream.go`) with Suricata 8.0.8.

Deliver one `.pcap` per group (A to I) and a `manifest.json`, in the same form as
the Modbus captures (`MODBUS_SYNTHETIC_CAPTURES.md`, sections 1, 4 and 5). **All
rules of that document's section 1 apply** (classic pcap, no duplicated frames,
complete TCP sessions, one scenario per connection, fixed timestamps, manifest
as the source of truth), with these changes: server port is **44818** (TCP and
UDP), client `10.20.0.10`, server `10.20.0.20`; a warm-up is one RegisterSession
exchange, not two Modbus reads; every connection that carries a malformed
message starts with a valid RegisterSession exchange (Suricata's probe rejects a
malformed first message, so it would never parse it).

## Notation

All fields are **little endian** except the socket address inside a ListIdentity
item (big endian, as in a `sockaddr_in`).

- `ENC(cmd, session, status, data)`: 24-byte header (command u16, length u16 =
  len(data), session u32, status u32, sender context 8 bytes (use the request
  number), options u32 = 0) followed by data. Length is correct unless a case
  says otherwise.
- `CPF(items)`: item count u16, then per item type u16, length u16, data.
- `RR(cip)`: SendRRData data = interface handle u32 0, timeout u16 0, then
  `CPF([ (0x0000, empty), (0x00B2, cip) ])`.
- `UD(connid, seq, cip)`: SendUnitData data = handle 0, timeout 0, then
  `CPF([ (0x00A1, connid u32), (0x00B1, seq u16 + cip) ])`.
- `CIP request`: service u8, path size in 16-bit words u8, path, data.
  Logical segments: class `20 xx` (8 bit) / `21 00 xx xx` (16 bit) / `22 00
  xx xx xx xx` (32 bit), instance `24`/`25`/`26`, attribute `30`/`31`/`32`.
- `CIP response`: service|0x80, reserved 0, general status u8, extended status
  size in **words** u8, extended status words, data.

Session handle: RegisterSession request carries session 0, the reply assigns
`0x00000001` (use distinct ones per connection); every later message carries it.

## Group A: encapsulation commands over TCP (one connection, warm-up first)

| # | Message (request then reply) | Notes |
|---|---|---|
| A1 | Nop (cmd `0000`), data 4 bytes | no reply; options 0 |
| A2 | ListServices: empty request; reply with one item type `0100`: version 1, capabilities `0120`, name `"Communications"` NUL-padded to 16 bytes | |
| A3 | ListIdentity over TCP: empty request; reply with one identity item (see B) | |
| A4 | ListInterfaces: empty request; reply with item count 0 | and a second exchange with count 2, two items type `0x00FF`, 4 data bytes each |
| A5 | RegisterSession version 1 (done as warm-up), then **version 3**: reply status `0x69` | |
| A6 | UnregisterSession (cmd `0066`), data empty and a second connection with data 4 bytes | |
| A7 | IndicateStatus (`0072`) and Cancel (`0073`) with 4 data bytes | |
| A8 | Reply headers carrying each status: `01 02 03 64 65 69 6A` and an unknown `1234`, to a SendRRData (valid CIP request, error reply with empty data) | one request per status |
| A9 | Unknown command `0x0077` mid-connection, 4 data bytes | |
| A10 | Sender context and options non-zero (`options = 1`) on a SendRRData | options is logged by neither tool as compared |

## Group B: UDP 44818 (own capture group, no TCP)

| # | Datagram | Notes |
|---|---|---|
| B1 | ListIdentity request, empty, client to `10.20.0.255` broadcast and to the server unicast, source port 44818 once and an ephemeral port once | |
| B2 | ListIdentity replies from three devices (10.20.0.20, .21, .22) with different identities | vendor ids `1`, `47`, `243`; device types `12`, `14`, `2`; product codes `0x36`, `1`, `65535`; revisions `5.1`, `0.0`, `255.255`; serial `0`, `0x12345678`, `0xFFFFFFFF`; status `0`, `0x30`, `0xFFFF`; state `0`, `3`, `255` |
| B3 | Product name lengths 0, 1, 31 and 255 (name byte) | |
| B4 | Identity with socket address IP `0.0.0.0`, port 0, and family not 2 | we expose address and port, Suricata ignores them |
| B5 | One reply holding **two** identity items | Suricata logs the first only |
| B6 | Identity item of an unknown vendor id (65000) and device type (999) | Suricata prints `unknown-N` |
| B7 | ListServices and ListInterfaces replies, Nop | |
| B8 | A datagram that is **not** ENIP on 44818 (random bytes, an HTTP request) | neither tool decodes it |
| B9 | A datagram with the message followed by 4 extra bytes | trailing bytes ignored |
| B10 | Implicit I/O (class 1) on UDP **2222**: sequenced address item + connected data item, 3 datagrams | not decoded by either (no encapsulation header) |

## Group C: CIP services and paths over SendRRData (warm-up first)

One request and a normal reply (status 0) each unless noted.

| # | Request |
|---|---|
| C1 | Every common service on class 1 (Identity), instance 1: `01` Get Attributes All, `02` Set Attributes All (data 4), `03` Get Attribute List (count 3: 1,2,3), `04` Set Attribute List (count 1, attribute 7 + 2 bytes), `05` Reset, `06` Start, `07` Stop, `08` Create, `09` Delete, `0D` Apply Attributes, `0E` Get Attribute Single (attribute 1, 7), `10` Set Attribute Single (attribute 9), `11` Find Next Object Instance, `15` Restore, `16` Save, `17` No Operation, `18` Get Member, `19` Set Member, `1A` Insert Member, `1B` Remove Member, `1C` Group Sync |
| C2 | Classes: Identity `01`, Message Router `02`, Assembly `04` (instance `0x64`, `0x65`, attribute 3), Connection Manager `06`, TCP/IP Interface `F5`, Ethernet Link `F6`, and an unknown class `0x00FF` and `0x1234` (16-bit) and `0x00010002` (32-bit); each with Get Attribute Single |
| C3 | Path forms: no path (size 0); class only; class and instance only; attribute without class; 8-bit, 16-bit and 32-bit values for each segment type; the same segment twice (two classes); path of 20 words |
| C4 | Connection Manager (class 6, instance 1): `54` Forward Open (real 36-byte body as in the captures), `4E` Forward Close, `52` Unconnected Send (embedding a Get Attribute Single), `5B` Large Forward Open, `56`/`57`/`5A` |
| C5 | Logix tags: `4C` Read Tag with an ANSI symbolic path `91 04 "Tag1"` (words: 3) and `91 03 "Foo"` (odd length, padded), `4D` Write Tag, `52` Read Tag Fragmented, `53` Write Tag Fragmented, `4E` Read Modify Write Tag, `55` Get Instance Attribute List on class `6B`; a tag path with an array index (`28 05` member segment) |
| C6 | Segment types the logical decoder does not read: a port segment (`01 ..`), an electronic key (`34 04 ..`), a data segment (`80 ..`) at the start and in the middle of a path |
| C7 | Vendor-specific service codes `0x32` and `0x4B` (class `0x67`) |

Expected: both tools agree on service code, class, instance, attribute for every
logical path. **Divergences** (record them, do not fix the traffic): C4/C5 name
the services differently (we name `4E` Forward Close in class 6, Suricata always
"Read Write Modify Data"; the comparison is on codes, so no difference shows);
C5 symbolic paths and C6: Suricata fails to parse a non-logical segment, raises
`invalid_pdu` and logs no CIP; we keep the message, decode the symbol and mark
the path truncated at a type we do not read.

## Group D: CIP status (warm-up first)

| # | Reply to a Get Attribute Single |
|---|---|
| D1 | General status `0x00` to `0x2C` (45 replies), plus `0xFF` and `0x80`, extended size 0 |
| D2 | Status 1 (Connection Failure) to a Forward Open with extended status of one word: `0x0100` (connection in use), `0x0111` (RPI not supported), `0x0113` (out of connections), `0x0204` (timeout), `0x0205` (parameter error) |
| D3 | Extended status of **two** words; extended status size 3 with 6 bytes; extended status size 0 with data following |
| D4 | Status `0x1E` (embedded service error) inside a Multiple Service reply (see E) |
| D5 | Reply to a Get Attribute List with status `0x0A` and attribute list in the data |

**Divergence**: the extended status size counts words (ODVA); Suricata reads it as
bytes, so for sizes 1 and above its extended status (not compared) and its
parsing of any Multiple Service body that follows differ from ours.

## Group E: Multiple Service Packet (service `0A`, class 2, instance 1)

| # | Traffic |
|---|---|
| E1 | Request with 2 embedded services (Get Attribute Single on class 1 and 4); reply with 2 replies |
| E2 | 5 embedded services of mixed kinds (Get Attribute List, Set Attribute Single, Get Attribute Single) |
| E3 | Embedded replies with different statuses (0, 5, 0x1E) |
| E4 | Count 0 |
| E5 | A Multiple Service Packet embedded in a Multiple Service Packet (nested) | 
| E6 | Offsets not increasing; an offset beyond the data; an offset pointing into the offset table |
| E7 | An embedded request with a path longer than the remaining data |

Expected: agree on E1 to E4. Suricata follows one level only (so do we): in E5
neither decodes the inner one. E6 and E7: both raise `invalid_pdu`.

## Group F: connected messaging

| # | Traffic |
|---|---|
| F1 | Forward Open (RR), then 4 SendUnitData exchanges with sequence numbers 1 to 4, then Forward Close (RR). Connection ids differ per direction |
| F2 | Connected Multiple Service Packet |
| F3 | Reply with a sequence number that does not match the request |
| F4 | SendUnitData without a preceding Forward Open |

## Group G: malformed messages (warm-up first; each in its own connection)

All have a correct header length, so the frame boundaries are known.

| # | Payload | Both tools |
|---|---|---|
| G1 | RegisterSession reply with 2 data bytes (length 2) | `invalid_pdu` (note: as a first message the probe rejects it) |
| G2 | ListIdentity reply with item count 5 and no items; count 1 with item length 200 and 2 bytes; identity item of 4 bytes; services item of 2 bytes | `invalid_pdu` |
| G3 | SendRRData with 6 data bytes (no items); with item count 2 and one item | `invalid_pdu` |
| G4 | CIP item with no service byte; path size 9 with 2 words of data; Get Attribute List count 100 with 2 attributes; Set Attribute List with count 1 and no attribute | `invalid_pdu` |
| G5 | Connected data item (`B1`) with 1 byte | `invalid_pdu` |
| G6 | Header length 65535 with a short body, connection then idle, FIN | frame never completes: no message |
| G7 | Header length **larger** than the bytes sent, followed by the next valid message in the next segment | the next message is swallowed into the first (both tools): record what each does |
| G8 | Length smaller than the real payload (2 trailing bytes) | the next 24-byte header is misaligned by 2: record |

## Group H: stream shape

| # | Traffic |
|---|---|
| H1 | Pipelining: 3 RegisterSession or Get Attribute Single requests in one segment, 3 replies in one segment |
| H2 | A message split after the header (24 bytes), after 1 byte, in the middle of an item, and one byte per segment |
| H3 | A large reply: Get Attribute List reply of about 1200 bytes with MSS clamped to 200 |
| H4 | Retransmission of a request; retransmission of one segment of a split message |
| H5 | Segments reordered inside one message |
| H6 | A lost segment (never retransmitted) in the middle of a long reply, followed by 40 more messages in later segments (Suricata re-probes after the gap; we do too) |
| H7 | A session that starts after the handshake (capture begins mid-connection) |
| H8 | RST in the middle of a reply; port reuse: a second connection on the same source port after FIN/ACK |

## Group I: detection

| # | Traffic |
|---|---|
| I1 | A valid first message on 44818: detected. The same on port 12345 (content only) |
| I2 | HTTP text on 44818, then valid ENIP: record |
| I3 | A first message with an unknown command on 44818, then valid ENIP: probe rejects the first |
| I4 | ENIP over TCP **2222** (explicit messaging on the implicit port) |
| I5 | Modbus traffic on 502 and ENIP on 44818 in one capture: no cross-detection |
| I6 | VLAN-tagged and IPv6 (`fd00::10` to `fd00::20`) ENIP |

## Manifest and checks

As in the Modbus document: per connection, per message, `raw_hex`, the
expectation fields `expect_decoded`, `expect_suricata_events` (`invalid_pdu`,
`too_many_transactions`) and `expect_our_events`, set from this document, not
from observation. Before handing over: no duplicate frames (except group H4 on
purpose), `file x.pcap` says "pcap capture file", `tshark -r x.pcap -Y enip`
shows the messages in the manifest.

## What we do with the result (not for the agent)

`scripts/compare_enip.py <pcap>` compares requests, responses and `invalid_pdu`
per connection. Both tools must agree on every row except those marked
"Divergence". Group B is the first evidence for ListIdentity, the device
identification that matters for IEC 62443 asset inventory.
