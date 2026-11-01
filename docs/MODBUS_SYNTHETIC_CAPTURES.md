# Synthetic Modbus/TCP captures: specification

Audience: an agent in the simulation environment that produces the captures.
Purpose: the one real Modbus capture we have covers only FC3, FC16 and FC23
with no errors (see "Modbus message-level differential" in
`SURICATA_PROTOCOL_COMPARISON.md`). These captures cover every other function
code, exception, malformed framing and stream shape, so that
`scripts/compare_modbus.py` can compare our decoder (`lib/detect/modbus_decode.go`)
with Suricata 8.0.8 on them.

Deliver: one `.pcap` per scenario group (A to I below) plus `manifest.json`.
Nothing here needs a real PLC. A scripted client and server (for example
Python `socket` or `pymodbus` with a raw-bytes override, or Scapy) is fine, as
long as the **bytes on the wire are exactly as specified**. Libraries that
"fix" malformed frames defeat the purpose; craft those with raw sockets.

## 1. Rules for every capture

1. **Format**: classic pcap (not pcapng), link type Ethernet, snaplen 65535.
   Our dumper reads only classic pcap.
2. **No duplicated packets.** The existing capture contains every frame twice
   and it distorted the comparison. Capture on one interface only (not on both
   ends of a bridge, no mirror port plus tap). Check:
   `tcpdump -nn -r x.pcap | sort | uniq -d` must print nothing, ignoring
   timestamps. Group I does duplicate frames on purpose.
3. **Complete TCP sessions.** Every connection starts with SYN, SYN-ACK, ACK
   and ends with FIN or RST (as stated per case). Suricata ignores sessions
   without SYN unless `midstream` is on; we want both behaviours tested only in
   case I3.
4. **Addresses**: client `10.20.0.10`, server `10.20.0.20`, server port 502
   unless a case says otherwise. Client source port: a fresh ephemeral port
   per connection (50000 and up, increasing).
5. **Transaction ids** increase by 1 per request within a connection, starting
   at 1, except where a case says otherwise. Unit id 1 unless stated.
6. **One ADU per TCP segment** (PSH set), the request in one segment, the
   response in one segment, with the exchange completed before the next
   request. Pipelining and splitting only where a case says so.
7. **Warm-up first.** Suricata's probe rejects an ADU that carries any error
   (non-zero protocol id, bad quantity, bad length) when it is the first thing
   on a connection, so Suricata would never parse it. Every connection that
   carries a malformed ADU therefore starts with **two valid exchanges** (FC3,
   4 registers, address 0, then FC3 again) before the first malformed ADU. The
   first malformed ADU in a connection is the third request. This also tells
   us how each tool treats the same bytes first-in-connection (group H).
8. **Timestamps** increase, 1 ms to 50 ms apart, no gaps over 1 s inside a
   connection. Capture start 2026-01-01T00:00:00Z or later (any fixed time is
   fine, but fixed, so reruns give identical files).
9. **One scenario per connection**, so a malformed ADU cannot change how the
   tools treat a later one (Suricata gives up on a flow after some errors).
   A pcap holds several connections, each with its own source port.
10. **Record what you sent** in `manifest.json` (section 4). The manifest, not
    either tool, is the source of truth for the comparison.

## 2. Notation

`ADU(txn, unit, fc, data)`: MBAP header + PDU. Header = txn (2 bytes), protocol
id `0000`, length (2 bytes, = 2 + len(data)) unless the case overrides it, unit
(1), then fc (1), then data. All values big endian. Registers use values
`0001 0002 ...` unless stated. `n regs` = `2n` data bytes, `n coils` =
`ceil(n/8)` bytes.

Each row: request, response, then what each tool should report. "Ours" is the
decoder in `lib/detect`. "Suri" is Suricata. `-` = nothing. "Divergence" marks
a place where we expect the two to differ and why; the agent does not need to
resolve those, only to produce the traffic.

## 3. Scenarios

### Group A: every public function code, well formed (one connection each is not needed; one connection, requests in this order)

Connection A1, all requests answered normally:

| # | Request | Response data |
|---|---|---|
| A1.1 | FC1 Read Coils, addr 0, qty 8 | count 1, 1 byte |
| A1.2 | FC1, addr 0, qty 20 | count 3, 3 bytes |
| A1.3 | FC2 Read Discrete Inputs, addr 0, qty 16 | count 2 |
| A1.4 | FC4 Read Input Registers, addr 0, qty 4 | count 8 |
| A1.5 | FC4, addr 0, qty 125 (maximum) | count 250 |
| A1.6 | FC5 Write Single Coil, addr 5, value `FF00` | echo of request |
| A1.7 | FC5, addr 5, value `0000` | echo |
| A1.8 | FC6 Write Single Register, addr 9, value `1234` | echo |
| A1.9 | FC15 Write Multiple Coils, addr 0, qty 10, count 2, data `CD01` | addr 0, qty 10 |
| A1.10 | FC16 Write Multiple Registers, addr 1, qty 2, count 4 | addr 1, qty 2 |
| A1.11 | FC16, addr 0, qty 123 (maximum), count 246 | addr 0, qty 123 |
| A1.12 | FC22 Mask Write Register, addr 4, and `00F2`, or `0025` | echo |
| A1.13 | FC7 Read Exception Status, no data | 1 byte `6D` |
| A1.14 | FC11 Get Comm Event Counter, no data | status `FFFF`, count `0108` |
| A1.15 | FC12 Get Comm Event Log, no data | byte count `08`, status `0000`, event count `0108`, message count `0021`, events `20 00` |
| A1.16 | FC17 Report Server ID, no data | count 3, 3 bytes |
| A1.17 | FC24 Read FIFO Queue, addr `04DE` | byte count `0006`, fifo count `0002`, 2 values |
| A1.18 | FC20 Read File Record: byte count 7, ref 6, file 4, rec 1, len 2 | resp length 6, then group length 5, ref 6, 2 regs |
| A1.19 | FC21 Write File Record: byte count 13 (spec example) | echo |
| A1.20 | FC8 Diagnostics sub 0000 (Return Query Data), data `A537` | echo |
| A1.21 | FC8 sub 0001 (Restart Comm), data `FF00` | echo |
| A1.22 | FC8 sub 000A (Clear Counters), data `0000` | echo |
| A1.23 | FC43 MEI 14 (Read Device Identification), `0E 01 00` | `0E 01 01 00 00 01 00 03 "ABC"` |

Expected: ours decodes function name, access class and (requests) address and
quantity for every row, no events. Suri logs one transaction per row, no
events, except the known `value_mismatch` on A1.4/A1.5 (sawp checks register
reads as bit reads; see the comparison doc).
Ours does not yet decode FC15/16 byte counts, FC20/21/24 and FC43 bodies: for
those rows only function and access class are checked.

### Group B: exceptions (one connection, warm-up first, then these)

For each row the response is `ADU(txn, unit, fc|0x80, code)`.

| # | Request | Exception code | Ours | Suri |
|---|---|---|---|---|
| B1 | FC3 addr 0 qty 4 | 01 Illegal Function | none | none |
| B2 | FC3 addr 65000 qty 4 | 02 Illegal Data Address | none | none |
| B3 | FC3 addr 0 qty 4 | 03 Illegal Data Value | none | none |
| B4 | FC16 addr 0 qty 2 | 04 Server Device Failure | none | none |
| B5 | FC1 addr 0 qty 8 | 05 Acknowledge | none | none |
| B6 | FC6 addr 1 value 1 | 06 Server Busy | none | none |
| B7 | FC3 addr 0 qty 4 | 08 Memory Parity Error | none | `invalid_exception_code` (sawp rejects 08 on non-file functions). **Divergence**: ours accepts 08 everywhere |
| B8 | FC3 addr 0 qty 4 | 0A Gateway Path Unavailable | none | none |
| B9 | FC3 addr 0 qty 4 | 0B Gateway Target No Response | none | none |
| B10 | FC3 addr 0 qty 4 | 07 (reserved/unassigned) | `invalid_exception_code` | `invalid_exception_code` |
| B11 | FC3 addr 0 qty 4 | 42 (arbitrary) | `invalid_exception_code` | `invalid_exception_code` |
| B12 | FC7 (no data) | 02 Illegal Data Address | none | `invalid_exception_code` (sawp: illegal address on FC 7-14, 17-19). **Divergence** |
| B13 | FC17 | 03 Illegal Data Value | none | `invalid_exception_code`. **Divergence** |
| B14 | FC20 Read File Record (valid body) | 08 Memory Parity Error | none | none (allowed on file functions) |
| B15 | FC3 | exception response with **no code byte** (MBAP length 2: unit and `83` only) | no exception code | Suri: `invalid_length` or none; record what happens |

### Group C: function codes outside the public set (one connection, warm-up first)

| # | Request fc | Data | Ours | Suri |
|---|---|---|---|---|
| C1 | `09`, `0D`, `0E`, `29`, `2A` (unassigned public codes, one request each) | `0001` | `unknown_function` | none for requests. **Divergence**: sawp flags only 0 and >= 0x80 |
| C2 | `41`, `48`, `64`, `6E` (user defined ranges 65-72, 100-110) | `0001` | none, name "User Defined" | none |
| C3 | `00` | `0001` | not decoded (ADU rejected) | `invalid_function_code` |
| C4 | `80` | `0001` | not decoded | `invalid_function_code` |
| C5 | `FF` | `0001` | not decoded | `invalid_function_code` |
| C6 | `73`-`7F` and `C8`-`FE`, sample 5 values | `0001` | record | record |

Server answers C1/C2 with exception 01 (`fc|0x80`, `01`) except C2 `41`
which gets an echo.

### Group D: malformed requests (each row its own connection, warm-up first, then the bad request, then if the server still answers, one more valid exchange)

The server answers each bad request with exception 03 where it would
normally reject, so the stream continues.

| # | Bad request | Expected on the wire | Suri event | Ours |
|---|---|---|---|---|
| D1 | FC3 addr 0 qty **0** | `0300 0000 0000` data | `invalid_value` | none yet (**gap: add quantity range checks**) |
| D2 | FC3 addr 0 qty **126** | | `invalid_value` | gap |
| D3 | FC1 addr 0 qty **2001** | | `invalid_value` | gap |
| D4 | FC1 addr 0 qty **2000** | valid maximum | none | none |
| D5 | FC3 with **6** data bytes (qty plus 2 extra) | `0000 0004 FFFF` | `invalid_length` | gap |
| D6 | FC3 with **2** data bytes | | `invalid_length` or Incomplete handling; record | no address/quantity |
| D7 | FC5 value `1234` (neither 0000 nor FF00) | | `invalid_value` | gap |
| D8 | FC16 qty 2, count **6** (should be 4), data 6 bytes | | `invalid_value` | gap |
| D9 | FC16 qty 2, count 4, **2** data bytes after the count | | `invalid_length` | gap |
| D10 | FC16 qty **0** | | `invalid_length` | gap |
| D11 | FC16 qty **124** | | `invalid_value` | gap |
| D12 | FC15 qty 10, count **1** | | `invalid_value` | gap |
| D13 | FC7 with **1** data byte | | `invalid_length` | gap |
| D14 | FC8 with 6 data bytes | | `invalid_length` | gap |
| D15 | FC8 sub 0001 data `1234` (should be 0000/FF00) | | `invalid_value` | gap |
| D16 | FC24 with 4 data bytes | | `invalid_length` | gap |
| D17 | FC23 read qty **126** | | `invalid_value` | gap |

"gap" = our decoder does not raise this yet. These are the cases that decide
what we add. Record what Suricata reports; do not edit the traffic to make
tools agree.

### Group E: malformed framing (own connection each, warm-up first)

| # | Bad ADU | Notes | Suri | Ours |
|---|---|---|---|---|
| E1 | protocol id `0001`, otherwise a valid FC3 request | server replies normally | `invalid_protocol_id` | ADU not decoded |
| E2 | protocol id `FFFF` | same | `invalid_protocol_id` | not decoded |
| E3 | length field **1** (no function code) | send 8 bytes total | `invalid_length` | not decoded |
| E4 | length field **0** | | `invalid_length` | not decoded |
| E5 | length field **255** with 255 bytes following | | `invalid_length` | not decoded |
| E6 | length field **254** with 254 bytes after it (maximum legal) FC16 | valid | none | decoded |
| E7 | length field **larger than** the bytes sent, connection then goes quiet 2 s, then FIN | a truncated ADU | Incomplete, no tx | not decoded |
| E8 | length field **smaller than** the bytes sent (two extra bytes after the PDU, same segment) | trailing garbage | `invalid_length` | extra bytes ignored; record |
| E9 | MBAP header only (7 bytes), then the PDU in a **second** segment | split across segments | reassembled: one tx | **ours: not decoded** (Phase 2 reassembly) |

### Group F: transaction matching

| # | Traffic | Suri | Ours |
|---|---|---|---|
| F1 | Response with no request (server speaks first, txn 99, FC3, 4 regs), after warm-up | `unsolicited_response` | decoded as response |
| F2 | Request txn 50, response txn **51** | `unsolicited_response`, request stays open | decoded |
| F3 | Request unit 1, response unit **2**, same txn | unsolicited | decoded |
| F4 | Request FC3 txn 60, response FC4 txn 60 | unsolicited | decoded |
| F5 | FC3 qty 4 request, response with **6** bytes (count 6) | `value_mismatch` | none (we do not pair) |
| F6 | FC1 qty 16 request, response count **1** | `value_mismatch` | none |
| F7 | FC3 qty 4 request, response count **8** (the valid case) | `value_mismatch` on every tool run (sawp bug) | none |
| F8 | Response arrives twice (two **different segments**, same bytes, different TCP seq) | second one `unsolicited_response` | both decoded |
| F9 | **600 requests** (txn 1..600, FC3 qty 1) with no response at all, then FIN | `flooded` after 500 | all 600 decoded |

### Group G: stream shape

| # | Traffic | Why |
|---|---|---|
| G1 | **Pipelining**: 3 requests (txn 1,2,3) in **one** segment, then the 3 responses in one segment | Suri parses several messages per buffer; our splitter handles it. Compare counts. |
| G2 | Pipelining with the third request cut in half at the segment boundary (second half in the next segment) | partial ADU at the end |
| G3 | Long response: FC3 qty 125 (response ADU 259 bytes) with the server's MSS clamped to **100**, so the response arrives in three segments | needs reassembly; Phase 2 evidence |
| G4 | Long request: FC16 qty 123 (ADU 260 bytes) with the client's MSS clamped to 100 | same, request side |
| G5 | Segments out of order inside G3 (swap segments 2 and 3, then send them) | |
| G6 | Two connections open at once, packets interleaved, same host pair, different source ports, different txn spaces | flow keying |
| G7 | Keepalive: connection idle 30 s with TCP keepalives, then more requests | |
| G8 | RST from the server in the middle of a response (after 4 bytes of the response) | partial ADU then reset |
| G9 | Zero-window or 1-byte segments: the response sent one byte per segment | extreme reassembly |

### Group H: detection on first packet (own connection each)

| # | Traffic | Suri recognises? | Ours |
|---|---|---|---|
| H1 | Valid FC3 request as the **first** payload on port 502 | yes | yes |
| H2 | Valid FC3 request as first payload on port **1502** | by content only | yes (by content) |
| H3 | Non-zero protocol id as the **first** payload on 502, then valid exchanges | probably not, record | not decoded, then yes |
| H4 | HTTP text (`GET / HTTP/1.1`) on 502, then valid Modbus | record | HTTP is not Modbus, then yes |
| H5 | 7 bytes first (header only), then the rest | Incomplete then recognised | |
| H6 | Valid Modbus request on UDP 502 | not Modbus/TCP | not decoded |
| H7 | Valid Modbus on TCP 502 with **VLAN tag** (802.1Q) | yes | yes |
| H8 | Valid Modbus on **IPv6** (`fd00::10` to `fd00::20`) | yes | yes |
| H9 | Valid Modbus across **two unit ids** (1 and 255, plus 0 broadcast writes without a response) | yes | decoded; broadcast write has no response |

### Group I: capture artefacts (deliberate)

| # | Traffic |
|---|---|
| I1 | One valid exchange where every frame is sent **twice** (like our real capture). Tells how each tool counts duplicates now that we know the rest is clean. |
| I2 | A TCP **retransmission** of one request (same seq, later timestamp) |
| I3 | A session **without SYN** (start the capture after the handshake): three valid exchanges. Needs `stream.midstream=true` in Suricata. |
| I4 | A request in a frame with a **bad TCP checksum** |
| I5 | A **truncated frame** (snaplen cut at 60 bytes, so the ADU is cut) |

## 4. Manifest

`manifest.json` lists, per connection, in order:

```json
{
  "pcap": "D_malformed_requests.pcap",
  "connection": {"client": "10.20.0.10:50003", "server": "10.20.0.20:502"},
  "scenario": "D1",
  "messages": [
    {"index": 1, "dir": "request", "txn": 1, "unit": 1, "fc": 3,
     "raw_hex": "0001000000060103000000 04", "expect_decoded": true,
     "note": "warm-up"},
    {"index": 3, "dir": "request", "txn": 3, "unit": 1, "fc": 3,
     "raw_hex": "...", "expect_decoded": true,
     "expect_suricata_events": ["invalid_value"],
     "expect_our_events": []}
  ]
}
```

`raw_hex` is the exact ADU bytes. `expect_*` fields are what the specification
above says, not what you observed. Also write per pcap its SHA-256 and the
tool you used to produce it.

## 5. Checking the output before handing it over

1. `tcpdump -nn -r x.pcap | sort | uniq -d` prints nothing (not for group I).
2. `tshark -r x.pcap -Y mbtcp` shows the ADUs you listed in the manifest (it
   reads malformed ones too, with an expert warning).
3. Each pcap opens as classic pcap: `file x.pcap` says "pcap capture file".
4. Counts: group A is one connection with 23 exchanges; B and C are one
   connection each; every row of D to I is its own connection.

## 6. What we do with the result (not for the agent)

`scripts/compare_modbus.py <pcap>` compares transactions today. It does not
yet compare Suricata anomaly events with ours; that, and the gaps marked
"gap" and "Divergence" above, is the follow-up. Cases E9, G3 to G5 and G9 are
the evidence for or against building TCP reassembly (Phase 2).
