# S7comm captures: specification

Audience: an agent in the simulation environment that produces the captures.
Purpose: Suricata has no S7comm parser, so the reference is **tshark** (Wireshark
4.6, `s7comm`, `cotp`, `tpkt` dissectors), and none of our real captures carries
port 102. `scripts/s7_demo_pcap.py` builds frames by hand and checks the decoder
(`lib/detect/s7_decode.go`, `s7_stream.go`) against tshark, but hand-built frames
only prove we agree with the dissector on frames *we* thought of. Real client
and server stacks send what the specification does not spell out. Produce
captures from a real implementation.

Deliver one `.pcap` per group (A to H) and a `manifest.json`, with the rules of
`MODBUS_SYNTHETIC_CAPTURES.md` section 1 (classic pcap, no duplicated frames,
complete TCP sessions, fixed timestamps) and section 4 (manifest: per connection
and message the exact bytes). Server port 102, client `10.20.0.10`, server
`10.20.0.20`.

## How to generate

Use real stacks, not a byte generator:

- **Server:** `python-snap7` `snap7.server` (a software S7 server: it answers
  Setup communication, Read/Write Var for registered areas, SZL reads, block
  functions, PLC control) and, if the testbed has it, the S7-1200 simulation
  (branch `fix/s71200-firmware-version-37`). A real CPU is better still.
- **Client:** `snap7.client` for the ordinary services, plus a few raw frames
  (for the malformed cases) over a plain socket.
- Capture on one interface only, so no frame is duplicated.

## Groups

### A: connection and session (one connection per row)

| # | Traffic |
|---|---|
| A1 | `snap7` `connect(ip, rack=0, slot=2)` (S7-300/400 style), then disconnect |
| A2 | `connect(ip, 0, 1)` (S7-1200/1500 style) |
| A3 | Rack 1 slot 3, rack 2 slot 5 |
| A4 | Connection types PG, OP and basic (`set_connection_type`), which change the calling TSAP |
| A5 | Setup communication proposing PDU sizes 240, 480, 960 and the server's answer |
| A6 | A connection refused: CR answered by a Disconnect Request (DR) |

### B: Read Var and Write Var

| # | Traffic |
|---|---|
| B1 | Read a byte, word, dword, real, bit from each area: inputs (PE), outputs (PA), flags (MK), data blocks (DB1, DB10), counters, timers |
| B2 | Multi-item reads: 2, 5, 12 items in one request, mixed areas |
| B3 | A read whose answer exceeds the negotiated PDU, done by the client as several requests; and a single large read (200 bytes, 400 bytes) |
| B4 | Writes of the same types, a bit write (`write_area` with bit address), a multi-item write (`write_multi_vars`) |
| B5 | Errors: a DB that does not exist (`0x0A`), an address out of range (`0x05`), a write to a read-only area (`0x03`), an unsupported data type (`0x06`) |
| B6 | Reply with an Ack_Data error class and code (header error): a server that refuses the service |

### C: system state list (SZL) and identification

The decoder reads SZL `0x0011` (module identification) and `0x001C` (component
identification) into the CPU identity.

| # | Traffic |
|---|---|
| C1 | `get_cpu_info()` (SZL `0x001C`): system name, module name, plant id, copyright, serial number, module type |
| C2 | `get_order_code()` (SZL `0x0011`): order number and version |
| C3 | SZL `0x0000` (list of SZL ids), `0x0131`, `0x0132`, `0x0424` (CPU state), `0x0011` index `0x0001` and `0x0007` |
| C4 | An SZL reply in several data units (last data unit 0, then 1), and an SZL read that fails (error code in the userdata parameter) |
| C5 | Identity strings at their limits: 32 characters, empty, with non-ASCII bytes |

### D: control and system functions

| # | Traffic |
|---|---|
| D1 | `plc_stop()`, `plc_hot_start()`, `plc_cold_start()`, `compress()`, `copy_ram_to_rom()` |
| D2 | `get_plc_datetime()`, `set_plc_datetime()`, `set_plc_system_datetime()` |
| D3 | `list_blocks()`, `list_blocks_of_type()`, `get_block_info()` |
| D4 | Upload and download of a block (`full_upload`, `upload`, `download`): the Request download, Download block, Download ended and Start upload, Upload, End upload functions |
| D5 | Password and security functions (`set_session_password`, `clear_session_password`: userdata group 5) |
| D6 | Diagnostic and message services (`read_szl_list`, alarm subscription if the stack offers it) |

### E: stream shape

| # | Traffic |
|---|---|
| E1 | Several requests pipelined in one segment |
| E2 | A request and a reply split across segments (set a small `TCP_MAXSEG` or `TCP_NODELAY` with short writes) |
| E3 | COTP segmentation: a PDU larger than the COTP TPDU size negotiated in the CR/CC (TPDU size 128 or 256) so data TPDUs without the EOT bit occur |
| E4 | Retransmission and reordering (use a network emulator such as `tc netem` on Linux for loss, duplication and reordering) |
| E5 | A connection that starts after the handshake (capture begins mid-session) |
| E6 | RST in the middle of a reply; two sessions in a row on the same client port |

### F: not S7 on port 102

| # | Traffic |
|---|---|
| F1 | An MMS (IEC 61850) client and server on 102: libiec61850 example client and server, or any ISO-on-TCP stack with a different upper protocol |
| F2 | ICCP/TASE.2 if available |
| F3 | A COTP connection that never carries data |

### G: S7CommPlus (S7-1200 firmware 4 and later, S7-1500)

Newer CPUs speak S7CommPlus (protocol id `0x72`), not S7comm (`0x32`), over the
same TPKT/COTP. Capture a TIA Portal or `python-snap7`-independent client
(Wireshark's `s7comm_plus` dissector decodes it) connecting to an S7-1200 or
S7-1500: the four-step handshake (InitSsl, then encrypted data when TLS is on),
and with the "PUT/GET communication allowed" option on, plain S7comm requests too.
This is not decoded yet: the decoder does not recognise `0x72`, so such
connections are labelled by the port hint only until a probe exists.

### H: malformed (raw frames over a socket, warm-up first)

| # | Frame |
|---|---|
| H1 | S7 PDU with parameter length larger than the PDU; data length larger than the PDU |
| H2 | Read Var counting 3 items with 1 present; an item with a wrong specification length; Setup communication cut short |
| H3 | Userdata parameter shorter than its length byte; a data item longer than the data section |
| H4 | A TPKT length smaller than the COTP header; COTP length larger than the TPKT frame; TPKT version 2 mid-stream |
| H5 | A valid S7 PDU after each malformed one in the same connection: the stream must go on |

## What we compare

`scripts/compare_s7.py <pcap>` runs tshark and our `s7_dump` on the capture and
compares per PDU: ROSCTR, PDU reference, function (or userdata group and
subfunction), error class and code, the request items (area, DB, bit address,
length, transport size), the data return codes, the SZL id and index, and the
identity strings of SZL `0x001C` and `0x0011` replies. COTP connection frames are
compared by their TSAPs. Counts are exact. Agreement is expected on groups A to F
and on the well-formed part of H. Known differences: an invalid PDU is reported
by us with the event `invalid_s7` and the items that decoded before the failure;
tshark's tolerance differs in places.
