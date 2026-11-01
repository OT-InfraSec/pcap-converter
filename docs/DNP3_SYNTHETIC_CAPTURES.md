# DNP3 synthetic captures

What the simulation environment should capture so the DNP3 decoder can be
checked against real stacks. Run `scripts/compare_dnp3.py <pcap> --all` on each
file and record the result in `SURICATA_PROTOCOL_COMPARISON.md`.

Use at least two real or independent stacks (for example OpenDNP3 and a
vendor RTU simulator), master and outstation on different hosts, TCP port 20000.

| Group | Traffic |
|---|---|
| A | Startup: link reset, request link status, integrity poll (class 0123), disable unsolicited, enable unsolicited, time sync (delay measurement, write time) |
| B | Polling for an hour at 1 s and 10 s periods: event polls, responses with events (g2, g4, g22, g32 with and without time), IIN changes (class 1/2/3 events, need time, device restart) |
| C | Controls: select-before-operate and direct operate on binary outputs (CROB), analog outputs (g41), with error statuses and an outstation that refuses |
| D | Large responses: more than 2048 bytes in several transport segments and several fragments with confirms; frames split across TCP segments |
| E | Unsolicited responses with confirm, including a master that does not confirm |
| F | Secure Authentication (IEEE 1815-2012): challenge, reply, aggressive mode (groups 120 and 121) |
| G | File transfer and cold or warm restart, if the stack supports them |
| H | DNP3 over UDP (master to outstation and back), and a second master on one outstation |
| I | Capture artefacts: retransmissions, reordering, a connection captured mid-stream, a dropped segment inside a fragment |
| J | Non-standard ports (any port other than 20000), with the capture starting before and after the handshake |

Record, for each file, the stack, version and configuration, so differences
from the decoder can be traced to a stack's choices rather than to a bug.
