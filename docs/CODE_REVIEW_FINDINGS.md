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

7. **Protocol names as bare strings** (Primitive Obsession, Repeated
   Switches): `flowLabel`, `industrialPortLabels`, `labelerRegistry`,
   `detectProtocol` and the registry all match "S7", "DNP3" and so on. A new
   protocol means editing each. *Option:* a stored `Label` field on
   `detect.Protocol`.
8. **Direction as a bare int** (`dir int`, `dirToClient=0`, `dirToServer=1`
   indexing `[2]` arrays). *Option:* `type dir int`.
9. **Per-protocol `FeedTCP` wrappers** (Middle Man, mild): each is a closure
   over `feedTCP`, and the direction is converted to a bool and back.
10. **Type parameter `M`** appears only in the feed callback's return type, so
    every call site spells `[*xConn, XMessage]` (mild).
11. **`tcpTracker` details:** `c.tcp().…` is repeated about six times in
    `feedTCP` (assign once); `keep` writes `*c` only when it creates the entry
    and does not say so; `hint` is unexplained in `feedTCP`'s doc.
12. **Similar names for different things:** `defaultTrackerLimit` (200k) versus
    `maxTrackedConnections` (500k, labeler); `connState` is an interface in
    `lib/detect` and a struct in `internal/parser`.
13. **Modbus sets `needProbe` on a gap** but never reads it (dead state there).
14. **Tests:** `tcptrack_test.go` uses `panic` inside table closures, mixes
    `Fatal` and `Errorf`, and the gap subtest loops up to 40 times, which ties it
    to tcpseq's window size. `fakeLabeler` is inline rather than a
    `testutil/mock_*.go` and only checks assignment.
15. **`industrial_parser.go` is still 1156 lines**, mostly OPC UA, CIFS and
    device and pattern analysis; the protocol split was partial.
16. **Duplicated boilerplate** in `scripts/*_dump/main.go` (usage check, open,
    reader, exit), and the `Label()` function is still long.
17. **Port-102 hint ownership:** `HintPorts()` gives a shared port to the
    earliest-registered protocol. With S7 removed and S7CommPlus kept, 102 would
    map to S7CommPlus, which has no CLI label. Unreachable today because both
    follow `EnableS7`; the separate `EnableS7CommPlus` flag now exists (see 5), so check this item against it.

### Process

18. **No CI job** runs the differential scripts or the corpus tests; DNP3 is not
    in the corpus. The plan lists both as not done.
19. **Plan text out of step with the code:** it says Phase 2 (reassembly) is
    "not started" while TCP sequence tracking exists, and that old port tables
    are deleted while they remain as hints in `main.go` and
    `flow_canonicalizer.go`. `docs/API_REFERENCE.md` was not updated.
20. **Pre-existing, not from this branch:** 5 failing tests in
    `internal/iec62443`, and `TestDeviceClassifierImpl_ClassifyDevice` fails
    intermittently on `main` too (about 2 runs in 10).

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
