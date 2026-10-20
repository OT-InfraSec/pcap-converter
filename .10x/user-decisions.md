# User decision log: cycles 2 and 3 (subnets, CDP)

Every decision the user made, the options that were offered and not chosen, and **why they were probably declined**.

> **Reading the "assumed reason" lines:** the user chose from options without stating reasons. Every reason below is an inference by 10x-team from the context at the time, not the user's own words. Where the chosen option was *not* the one recommended, that is marked **(against recommendation)** and the reason is the least certain. Please correct any reason that is wrong; this file is the place to fix it.

Related records: `decisions.md` (shared log), `adrs/001..004`, `specs/*-design.md`.

---

## A. Decisions carried in before this work (cycle 1 / handoff)
Taken earlier and not re-asked. Alternatives are from ADR-001 and `decisions.md`.

| # | Decision | Alternatives | Assumed reason declined |
|---|---|---|---|
| A1 | Breaking schema changes are fine: no migrations, no per-cycle `user_version` bump (stays 1) | Per-cycle version bumps (v1 VLAN, v2 subnets); migrations that keep old data | No existing data worth keeping; databases are regenerated anyway (AGENTS.md); intermediate versions add code and states for nobody |
| A2 | Untagged VLAN is NULL, never 1; VID 0 counts as untagged | Store untagged as VLAN 1 | Cannot tell "untagged-only capture" from "VLAN 1" and would draw a VLAN that does not exist |
| A3 | `subnets.vlan_id` follows A2: the same prefix in two VLANs is two rows | One row per prefix with a VLAN list | Keeps the longest-prefix match within a VLAN simple and the table queryable |
| A4 | Device membership in a subnet is not stored | Store device-to-subnet links | Goes stale when several capture files are merged; the visualizer can compute it |
| A5 | `source` values `dhcp`, `cdp`, `eigrp`, `ospf`, `inferred`; IPv4 and IPv6 both required | A smaller set; IPv4 only | Taken from the visualizer's requirements document |

---

## B. Cycle 2: subnets

### B1. Which evidence sources in the first delivery?
- **Chosen: DHCP only** (recommended). Later widened by B3 (IPv6) to DHCPv4, DHCPv6 and RA.
- DHCP + CDP: declined. *Assumed:* CDP would pull part of cycle 3 forward and the CDP layer was not wired into the parser; keep cycle 2 small.
- DHCP + CDP + EIGRP: declined. *Assumed:* EIGRP route TLV decoding is a sizeable job of its own.
- All four incl. OSPF: declined. *Assumed:* OSPF is unsupported today and would turn one cycle into several.
- Note: "DHCP only" was answered before the IPv6 question; it is read as "no CDP/EIGRP/OSPF", not "no RA".

### B2. Inference of `inferred` subnets?
- **Chosen: no inference** (recommended). `inferred` stays reserved.
- Infer for devices not covered by any DHCP subnet (e.g. /24, /64 guesses): declined. *Assumed:* guessing prefix lengths produces wrong boxes in an audit tool where evidence matters.
- Infer from ARP / router advertisements: declined. *Assumed:* needs more parser work and a confidence rule; RA was handled as real evidence under B3 instead.

### B3. IPv6 evidence
- **Chosen: both DHCPv6 and RA** **(against recommendation; recommended was RA only).**
- RA only (recommended): declined. *Assumed:* the user wanted DHCPv6 covered too so IPv6 is not left to a single mechanism, and R4 says IPv6 is required.
- DHCPv6 only: declined. *Assumed:* IA_NA has no prefix length, so it yields almost nothing alone.
- Defer IPv6: declined. *Assumed:* contradicts the requirement that IPv4 and IPv6 are both required.

### B4. How DHCPv4 evidence becomes a subnet row
- **Chosen: mask + offered address, validated with the router option** **(against recommendation; recommended skipped the router check).**
- Mask + offered address without router validation (recommended): declined. *Assumed:* the user preferred fewer false rows over completeness, at the cost of missing networks with no gateway option (the trade-off was stated).
- Also use server ID / giaddr as hints: declined. *Assumed:* more code for little benefit to the stored columns.

### B5. `source` value for IPv6 evidence
- **Chosen: add `ra`; DHCPv6 uses `dhcp`** (recommended).
- Add `ra` and `dhcpv6`: declined. *Assumed:* one extra label for the visualizer with no real gain; DHCP is one family.
- Map RA to `inferred`: declined. *Assumed:* RA is authoritative; calling it inferred understates it.

### B6. How DHCPv6 contributes
- **Chosen: parse IA_PD, store as `dhcp` rows** (recommended). The caveat that delegated prefixes may not be on-link was later resolved by B9.
- Skip DHCPv6, RA only: declined. *Assumed:* contradicts B3 (user wanted both).
- New source `dhcp-pd`: declined. *Assumed:* an extra source value for the visualizer beyond the approved `ra`; at that point the caveat was seen as acceptable if documented.

### B7. Approval of the cycle 2 design
- **Chosen: approve as presented.** Declined: approve with changes, not yet. *Assumed:* the design matched B1 to B6.

### B8. Spec approval and go-ahead
- **Chosen:** "Spec approved, start implementing", then "yes and make sure that these gaps are addressed". No alternatives were offered (free text). The second message made closing the three known gaps (relay unwrapping, schema diagram, delegated-vs-on-link) part of the job, not optional follow-ups.

### B9. How to resolve the IA_PD (delegated prefix) ambiguity
- **Chosen: `kind` column, `on-link` | `delegated`** (recommended). Recorded as ADR-003.
- New source value `dhcp-pd`: declined. *Assumed:* reverses the earlier B5/B6 choice to keep DHCPv6 under `dhcp`, and mixes mechanism and meaning in one field.
- Documentation only: declined. *Assumed:* leaves the visualizer unable to tell the rows apart, and B8 asked for the gaps to be addressed.

---

## C. Cycle 3: CDP

### C1. Start cycle 3 and brainstorm it
- **Chosen:** yes, brainstorm. (Cycle 3 is optional; the alternative was to stop after cycle 2.)

### C2. What to extract from CDP frames
- **Chosen: VLANs + prefixes + device identity** **(against recommendation; recommended was native/management VLAN only).**
- Native + management VLAN only (recommended): declined. *Assumed:* the user wants the CDP data collected once and fully, since the layer already provides it and a later cycle would reopen the same parser code.
- VLANs + IPPrefixes into subnets: declined. *Assumed:* identity data (switch vs router, platform) is also useful to the analyst and costs little more.

### C3. Where to store CDP data
- **Chosen: separate `cdp_neighbors` table keyed by source MAC** **(against recommendation; recommended was columns on `devices`).**
- Columns on `devices` keyed by the Addresses TLV IPs (recommended): declined. *Assumed:* CDP is per-interface data, not per-IP; writing it onto device rows would create devices from CDP frames and mix two identities (devices are keyed by IP, CDP by MAC).
- Match by source MAC to existing devices: declined. *Assumed:* routers reuse one MAC across many IPs, so it can mislabel devices.

### C4. How CDP IPPrefixes appear in `subnets`
- **Chosen: new kind `advertised`, VLAN = the frame's VLAN** (recommended). Recorded in ADR-004.
- Kind `on-link`: declined. *Assumed:* over-claims; a router's connected prefixes on other interfaces would be drawn in the wrong VLAN.
- Skip prefixes: declined. *Assumed:* contradicts the scope chosen in C2.

### C5. `cdp_neighbors` row identity and value changes
- **Chosen: key (source MAC, port ID, all advertised values)** **(against recommendation; recommended was (MAC, port ID), last value wins).**
- (MAC, port ID), last value wins (recommended): declined. *Assumed:* losing a mid-capture reconfiguration (e.g. native VLAN change) is a real audit finding in an IEC 62443 context; extra rows are an acceptable cost.
- Key source MAC only: declined. *Assumed:* merges ports that share a MAC and loses per-port native VLAN.

### C6. Approval of the cycle 3 design
- **Chosen: approve as presented.** Declined: approve with changes, not yet. *Assumed:* the design matched C2 to C5, including the details left to my judgement (capabilities encoding, 100k row cap, 0 as NULL, string sanitizing).

---

## Pattern worth knowing
Where you went against my recommendation (B3, B4, C2, C3, C5), the choice was consistently the **more complete or more cautious about evidence** one: more sources, stricter validation, no information loss. If that is the standing preference, say so and I will default to it in future cycles and stop offering the smaller option as the recommended one.
