#!/usr/bin/env python3
"""Compare our Modbus decoding with Suricata's modbus eve records.

  scripts/compare_modbus.py capture.pcap [--suricata-yaml su.yaml]

Needs a Suricata config whose eve-log types include `modbus`; without
--suricata-yaml one is derived from the installed suricata.yaml.
Anomaly events are compared per connection (client ip, client port) and name.
Only names with the same meaning in both tools are compared strictly
(SHARED_EVENTS); the others are listed so that a divergence is visible, never
silently dropped. Event counts per connection are compared exactly, so run it
on captures without duplicate frames; --events-as-sets compares only which
names occur per connection, for captures with retransmits or duplicates.
Transaction keys include the client port, so connections do not merge.
Requests are compared per (client, client port, server, transaction id, unit,
function, address); responses per (server, client, client port, transaction
id, function, exception). Retransmitted segments make us see an ADU twice where Suricata
sees one, so keys are compared as sets and the repeat counts are shown apart.
"""
import argparse, collections, ipaddress, json, os, re, subprocess, sys, tempfile

LIMIT = 5

def norm_ip(ip):
    """Suricata prints IPv6 expanded, we print it compressed."""
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return ip


FUNC = {"RdCoils":1,"RdDiscreteInputs":2,"RdHoldRegs":3,"RdInputRegs":4,"WrSingleCoil":5,"WrSingleReg":6,
        "RdExcStatus":7,"Diagnostic":8,"GetCommEventCtr":11,"GetCommEventLog":12,"WrMultCoils":15,
        "WrMultRegs":16,"ReportServerID":17,"RdFileRec":20,"WrFileRec":21,"MaskWrReg":22,"RdWrMultRegs":23,
        "RdFIFOQueue":24,"EncIface":43}

def suricata_yaml(path, tmp):
    if path:
        return path
    s = open("/opt/homebrew/etc/suricata/suricata.yaml").read()
    s = re.sub(r"^(\s+)- anomaly:", r"\1- modbus\n\1- anomaly:", s, count=1, flags=re.M)
    out = os.path.join(tmp, "su.yaml")
    open(out, "w").write(s)
    return out

# Event names that mean the same in both tools. Ours (lib/detect) on the left.
# Everything else is reported but does not fail the run:
#   ours:     unknown_function   (any unassigned public code, e.g. 0x09)
#   suricata: invalid_function_code (only code 0 and >= 0x80),
#             invalid_protocol_id, unsolicited_response,
#             value_mismatch (false positive on register reads, see the
#             comparison doc), flooded
SHARED_EVENTS = {"invalid_exception_code", "invalid_length", "invalid_value"}

def client_of(e):
    """(client ip, client port) of an eve record; the server is on port 502."""
    if e.get("dest_port") == 502:
        return norm_ip(e["src_ip"]), e["src_port"]
    return norm_ip(e["dest_ip"]), e["dest_port"]

def addr_qty(side):
    for k in ("read", "write"):
        d = side.get(k)
        if d and "address" in d:
            return d["address"], d.get("quantity", 1 if "and_mask" in d or "data" not in d else None)
    return -1, -1

def read_suricata(eve):
    req, resp = collections.Counter(), collections.Counter()
    events = collections.Counter()
    for line in open(eve):
        e = json.loads(line)
        if e["event_type"] == "anomaly" and e.get("anomaly", {}).get("app_proto") == "modbus":
            events[client_of(e) + (e["anomaly"]["event"],)] += 1
        if e["event_type"] != "modbus":
            continue
        m = e["modbus"]
        (c, cp), s = client_of(e), norm_ip(e["dest_ip"] if e["dest_port"] == 502 else e["src_ip"])
        if "request" in m:
            q = m["request"]
            a, n = addr_qty(q)
            req[(c, cp, s, q["transaction_id"], q["unit_id"], q["function_raw"], a)] += 1
        if "response" in m:
            q = m["response"]
            exc = q.get("exception", {}).get("raw", 0)
            resp[(s, c, cp, q["transaction_id"], q["function_raw"] & 0x7f, exc)] += 1
    return req, resp, events

def read_ours(jsonl):
    req, resp, events = collections.Counter(), collections.Counter(), collections.Counter()
    for line in open(jsonl):
        e = json.loads(line)
        cport = e["sport"] if e["request"] else e["dport"]
        cip = e["src"] if e["request"] else e["dst"]
        for ev in e.get("events") or []:
            events[(cip, cport, ev)] += 1
        if e["request"]:
            req[(e["src"], e["sport"], e["dst"], e["txn"], e["unit"], e["fc"], e["addr"])] += 1
        else:
            resp[(e["src"], e["dst"], e["dport"], e["txn"], e["fc"], e["exc_code"] if e["exception"] else 0)] += 1
    return req, resp, events

def diff(name, theirs, ours):
    ts, os_ = set(theirs), set(ours)
    print(f"{name}: suricata={len(ts)} ours={len(os_)} both={len(ts & os_)} "
          f"suricata-only={len(ts - os_)} ours-only={len(os_ - ts)}")
    for label, keys in (("suricata-only", ts - os_), ("ours-only", os_ - ts)):
        for k in sorted(keys, key=str)[:LIMIT]:
            print(f"  {label}: {k}")
    rep = sum(1 for k, n in ours.items() if n > 1)
    print(f"  keys we see more than once (retransmits/duplicates): {rep}")
    return ts == os_

def diff_events(theirs, ours, as_sets):
    """Compare anomaly events per connection. Returns True when the shared
    names agree. Names only one tool can raise are listed, not judged."""
    def per_conn(c):
        d = collections.defaultdict(collections.Counter)
        for (ip, port, ev), n in c.items():
            if ev in SHARED_EVENTS:
                d[(ip, port)][ev] += 1 if as_sets else n
        return d
    ts, os_ = per_conn(theirs), per_conn(ours)
    bad = 0
    for conn in sorted(set(ts) | set(os_), key=str):
        if ts.get(conn, {}) != os_.get(conn, {}):
            bad += 1
            if bad <= LIMIT * 2:
                print(f"  event mismatch {conn[0]}:{conn[1]} suricata={dict(ts.get(conn, {}))} "
                      f"ours={dict(os_.get(conn, {}))}")
    print(f"events (shared names {sorted(SHARED_EVENTS)}): connections with a difference: {bad}")
    for label, c in (("suricata", theirs), ("ours", ours)):
        tot = collections.Counter()
        conns = collections.defaultdict(set)
        for (ip, port, ev), n in c.items():
            tot[ev] += n
            conns[ev].add((ip, port))
        shown = {ev: f"{tot[ev]} events on {len(conns[ev])} connections" for ev in sorted(tot)}
        print(f"  {label} events: {shown or 'none'}")
    return bad == 0

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--suricata-yaml")
    ap.add_argument("--all", action="store_true", help="list every difference, not the first few")
    ap.add_argument("--events-as-sets", action="store_true",
                    help="compare which event names occur per connection, not how often")
    a = ap.parse_args()
    global LIMIT
    if a.all:
        LIMIT = 10**9
    with tempfile.TemporaryDirectory() as tmp:
        yaml = suricata_yaml(a.suricata_yaml, tmp)
        subprocess.run(["suricata", "-c", yaml, "-r", a.pcap, "-l", tmp, "-k", "none",
                        "--set", "stream.midstream=true", "--set", "app-layer.protocols.modbus.enabled=yes"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ours = os.path.join(tmp, "ours.jsonl")
        with open(ours, "w") as f:
            subprocess.run(["go", "run", "./scripts/modbus_dump", a.pcap], check=True, stdout=f)
        sreq, sresp, sevents = read_suricata(os.path.join(tmp, "eve.json"))
        oreq, oresp, events = read_ours(ours)
    ok = diff("requests", sreq, oreq)
    ok &= diff("responses", sresp, oresp)
    ok &= diff_events(sevents, events, a.events_as_sets)
    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
