# Code review findings, branch `feat/suricata-parity-detection`

Two `/code-review` passes (Standards and Spec axes), the first at `e33a745`
over the whole branch, the second over `851d31c` and `53af930`. This file keeps
what was **not** fixed, so it can be judged later, and records what was, so
nothing is reported twice. Reviewers were model agents reading the diff; items
marked *verified* were checked by hand.

State at the time of writing: PR #13, head `f77086c`.

## Fixed

| Finding | Fix |
|---|---|
| Four copies of the TCP tracker (Duplicated Code, Shotgun Surgery) | `lib/detect/tcptrack.go`, generic `tcpTracker[C, M]`; each protocol keeps framing and decoding |
| `NewS7Tracker` used `defaultModbusTrackerLimit` | renamed `defaultTrackerLimit` |
| Port 102 lost its `s7` label in `industrialPortLabels` (*verified*) | restored, test added |
| Committed `scripts/__pycache__/*.pyc` (*verified*) | untracked, `.gitignore` entry (the first attempt was lost; fixed in `f77086c`) |
| Wrong comment on `startsS7` | corrected |
| Probes and decoders missing from the fuzz and random-input tests | `decodeAllNoPanic`, `FuzzProbes`, all four trackers fed whole and split |
| `connectionLabeler` not injectable | `ConnectionLabeler` interface, `SetConnectionLabeler` |
| Labeler ignored the `Enable*` flags | `labelerRegistry(cfg)`, `Registry.Without`, `GopacketParser.SetIndustrialConfig` |
| `Label()` repeated its "create state if room" guard | `connectionLabeler.entry` |
| `fmt.Printf` in the parser | zerolog |
| `industrial_parser.go` held every protocol mapper | split into `industrial_{enip,modbus,dnp3,s7}.go` (1731 to 1156 lines) |
| `AGENTS.md`, `INDUSTRIAL_PROTOCOLS.md`, `db_schema.md` out of date | updated |

## Open, for later judgement

### Needs a design decision

1. **FIXED (option C): label before content (S7CommPlus on port 102).** Shared hint ports now get the neutral flow label `s7+s7commplus` for the whole connection. Original finding: Handshake and ACK
   packets carry no payload, so they get the hint port's label (`s7`, first
   registered) and the data packets `s7commplus`. One connection can become
   two flow records, because the flow key includes the label. Fixing it needs
   deferred flow accounting (Suricata labels the whole flow). The plan
   tracks it; docs mention it.
   *Options:* defer flow creation until the first decisive payload; or merge
   flow rows afterwards; or label shared hint ports with a neutral name.
2. **Largely addressed by 1** (port 102 is no longer asserted as `s7`; the flow label is neutral). **No "unverified s7" state.** The plan said port-102 traffic should be
   reported as unverified until a decoder confirms it. The code labels `s7`
   from the hint alone before the first payload. Related to 1.
3. **S7CommPlus is unvalidated.** Header layout, function numbers and the
   accepted versions (1 to 3) come from memory; tshark 4.6.9 has no S7CommPlus
   dissector and no capture exists. A wrong version range makes the probe reject
   real connections. Flows labelled `s7commplus` have no marker saying so.
   *Needs:* a real capture (`docs/S7_SYNTHETIC_CAPTURES.md`, group G).
4. **S7comm and DNP3 are validated only against hand-built captures** written by
   the same author as the decoders. Real stacks may expose object sizes, TSAP
   forms and framing the demos do not (`docs/S7_SYNTHETIC_CAPTURES.md`,
   `docs/DNP3_SYNTHETIC_CAPTURES.md`).
5. **FIXED: flags had no CLI.** `importer import --disable-protocols s7commplus,dnp3` now applies the flags, and `EnableS7CommPlus` is separate from `EnableS7`. Original finding: `SetIndustrialConfig` exists, but the importer CLI
   cannot set `Enable*`; it runs with everything on. S7 and S7CommPlus share
   `EnableS7`. Decide whether to add flags and a separate S7CommPlus switch.
6. **DECIDED: stays in this PR, no split** (entangled in `gopacket_parser.go`, already reviewed together). Scope that rode along and the plan did not ask for: `AddFlow` returns
   errors instead of `log.Fatalf`; ARP-request and 0.0.0.0 device rules and a
   synthesised device row per flow endpoint (`gopacket_parser.go`); the
   per-protocol dump tools. Decide whether to split them into their own PRs.

### Code quality, judgement calls

7. **FIXED:** `detect.Protocol` now carries `Key`, `Label` and `UDPLabel`; `flowLabel`, `industrialPortLabels`, `labelerRegistry` and the unused `enabledProtocols` maps are gone, and `protocolSwitches` is the one table that ties the configuration to the registry. Original finding: protocol names as bare strings (Primitive Obsession, Repeated
   Switches): `flowLabel`, `industrialPortLabels`, `labelerRegistry`,
   `detectProtocol` and the registry all match "S7", "DNP3" and so on. A new
   protocol means editing each. *Option:* a stored `Label` field on
   `detect.Protocol`.
8. **FIXED** (`type streamDir`). Original finding: direction as a bare int (`dir int`, `dirToClient=0`, `dirToServer=1`
   indexing `[2]` arrays). *Option:* `type dir int`.
9. **FIXED:** `FeedTCP` lives on the shared tracker and the protocol feed is passed to `newTCPTracker`; the direction is no longer converted back and forth, except in Modbus's public `Feed`. Original finding: per-protocol `FeedTCP` wrappers (Middle Man, mild): each is a closure
   over `feedTCP`, and the direction is converted to a bool and back.
10. **FIXED:** the types are inferred in `newTCPTracker(max, maxPartial, newConn, feed)`. `M` stays because the feed returns `[]M`. Original finding: type parameter `M` appears only in the feed callback's return type, so
    every call site spells `[*xConn, XMessage]` (mild).
11. **FIXED** (`tc := c.tcp()`, `keep` and `hint` documented). Original finding: `tcpTracker` details: `c.tcp().…` is repeated about six times in
    `feedTCP` (assign once); `keep` writes `*c` only when it creates the entry
    and does not say so; `hint` is unexplained in `feedTCP`'s doc.
12. **FIXED:** `defaultMaxConnections`, `maxLabelerConnections`, `trackedConn` (detect) and `labelState` (parser). Original finding: similar names for different things: `defaultTrackerLimit` (200k) versus
    `maxTrackedConnections` (500k, labeler); `connState` is an interface in
    `lib/detect` and a struct in `internal/parser`.
13. **FIXED:** Modbus now re-probes after lost bytes like the other trackers (test added). Original finding: Modbus sets `needProbe` on a gap but never reads it (dead state there).
14. **FIXED:** `tcptrack_test.go` is table-driven with no panics, and the gap is forced with `tcpseq.MaxWindow`; the labeler fake is `testutil.MockConnectionLabeler` and records its calls. Original finding: tests: `tcptrack_test.go` uses `panic` inside table closures, mixes
    `Fatal` and `Errorf`, and the gap subtest loops up to 40 times, which ties it
    to tcpseq's window size. `fakeLabeler` is inline rather than a
    `testutil/mock_*.go` and only checks assignment.
15. **`industrial_parser.go` is still 1156 lines**, mostly OPC UA, CIFS and
    device and pattern analysis; the protocol split was partial.
16. **PARTLY FIXED:** the dump tools share `scripts/internal/dumpcap`; the long `Label()` function is untouched. Original finding: duplicated boilerplate in `scripts/*_dump/main.go` (usage check, open,
    reader, exit), and the `Label()` function is still long.
17. **FIXED:** every protocol has a `Key`, so the owner of a shared port always has a label; `Registry.HintPortOwners` documents the earliest-wins rule and a test covers 102 with and without S7. Original finding: port-102 hint ownership: `HintPorts()` gives a shared port to the
    earliest-registered protocol. With S7 removed and S7CommPlus kept, 102 would
    map to S7CommPlus, which has no CLI label. Unreachable today because both
    follow `EnableS7`; the separate `EnableS7CommPlus` flag now exists (see 5), so check this item against it.

### Process

18. **FIXED:** `.github/workflows/ci.yml` runs build, vet, tests and a tshark differential job (S7, DNP3) with the corpus tests; DNP3 and S7 corpus tests added. The CI file has not run on GitHub yet, and the Suricata comparisons (ENIP, Modbus) are not in CI. Original finding: no CI job runs the differential scripts or the corpus tests; DNP3 is not
    in the corpus. The plan lists both as not done.
19. **FIXED:** plan phases 0, 2 and the port-table step and `docs/API_REFERENCE.md` brought up to date. Original finding, plan text out of step with the code: it says Phase 2 (reassembly) is
    "not started" while TCP sequence tracking exists, and that old port tables
    are deleted while they remain as hints in `main.go` and
    `flow_canonicalizer.go`. `docs/API_REFERENCE.md` was not updated.
20. **Pre-existing, not from this branch:** 5 failing tests in
    `internal/iec62443`, and `TestDeviceClassifierImpl_ClassifyDevice` fails
    intermittently on `main` too (about 2 runs in 10).

### Found while working on later items (not from the original review)

21. **OPEN: `GetDevices` does not load `tenant_id`.** The list query selects no
    tenant column, so a device read back from it and saved with `UpsertDevices`
    is written with an empty tenant and then no longer matches
    `GetDevice(tenant, address)`. `NewGopacketParser` loads existing devices
    this way, so a re-import into a multi-tenant database may blank tenants.
    Not verified end to end; a round-trip test showed the effect on the
    repository (`sqlite_repository_vlan_test.go`, comment in
    `TestSQLiteRepository_UpsertDevicesKeepsHostname`). *Fix:* select
    `tenant_id` in `GetDevices` and add a test.
22. **FIXED: `UpsertDevices` and `GetDevices` ignored `devices.hostname`.**
    The column existed and `AddDevice` wrote it, but the batch path the parser
    uses did not, so hostnames could never be stored. Fixed with the DHCP and
    LLMNR change (`dde3792`). `AddDevices` (batch insert) still does not write
    it; it is not on the parser's path, so left as is.
23. **OPEN: "invalid communication role" on off-port industrial traffic.**
    `CollectProtocolUsageStats` rejects direction "unknown". DNP3 now sets the
    direction from the link DIR bit; EtherNet/IP and S7 found off their usual
    ports can still hit it and fail the import. From the handoff notes, not
    reproduced in this session.
24. **OPEN: baseline test failures** in `internal/iec62443` (see 20) are not in
    CI (`ci.yml` leaves the package out).

## Claims and how far they hold

- "Identical to tshark" (S7 62 PDUs, DNP3 88 frames): holds for hand-built
  traffic only. DNP3 normalises tshark's differences on Assign Class and groups
  110 to 113 and leaves the 1-byte object-size prefix out of the comparison.
- "Identical to Suricata on three real ENIP captures": the only real-traffic
  claim; Modbus has real and synthetic captures.
- "The label follows content": after the first decisive payload only; empty and
  incomplete payloads keep the hint label (see 1).
- Mutation checks left one equivalent mutant per area (for example, the early
  `continue` for an invalid DNP3 frame), accepted.
