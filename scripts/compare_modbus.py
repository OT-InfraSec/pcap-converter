#!/usr/bin/env python3
"""Compare our Modbus decoding with Suricata's modbus eve records.

  scripts/compare_modbus.py capture.pcap [--suricata-yaml su.yaml]

Needs a Suricata config whose eve-log types include `modbus`; without
--suricata-yaml one is derived from the installed suricata.yaml.
Requests are compared per (client, server, transaction id, unit, function,
address, quantity); responses per (server, client, transaction id, function,
exception). Retransmitted segments make us see an ADU twice where Suricata
sees one, so keys are compared as sets and the repeat counts are shown apart.
"""
import argparse, collections, json, os, re, subprocess, sys, tempfile

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

def addr_qty(side):
    for k in ("read", "write"):
        d = side.get(k)
        if d and "address" in d:
            return d["address"], d.get("quantity", 1 if "and_mask" in d or "data" not in d else None)
    return -1, -1

def read_suricata(eve):
    req, resp = collections.Counter(), collections.Counter()
    for line in open(eve):
        e = json.loads(line)
        if e["event_type"] != "modbus":
            continue
        m = e["modbus"]
        c, s = e["src_ip"], e["dest_ip"]
        if "request" in m:
            q = m["request"]
            a, n = addr_qty(q)
            req[(c, s, q["transaction_id"], q["unit_id"], q["function_raw"], a)] += 1
        if "response" in m:
            q = m["response"]
            exc = q.get("exception", {}).get("raw", 0)
            resp[(s, c, q["transaction_id"], q["function_raw"] & 0x7f, exc)] += 1
    return req, resp

def read_ours(jsonl):
    req, resp, events = collections.Counter(), collections.Counter(), collections.Counter()
    for line in open(jsonl):
        e = json.loads(line)
        for ev in e.get("events") or []:
            events[ev] += 1
        if e["request"]:
            req[(e["src"], e["dst"], e["txn"], e["unit"], e["fc"], e["addr"])] += 1
        else:
            resp[(e["src"], e["dst"], e["txn"], e["fc"], e["exc_code"] if e["exception"] else 0)] += 1
    return req, resp, events

def diff(name, theirs, ours):
    ts, os_ = set(theirs), set(ours)
    print(f"{name}: suricata={len(ts)} ours={len(os_)} both={len(ts & os_)} "
          f"suricata-only={len(ts - os_)} ours-only={len(os_ - ts)}")
    for label, keys in (("suricata-only", ts - os_), ("ours-only", os_ - ts)):
        for k in sorted(keys, key=str)[:5]:
            print(f"  {label}: {k}")
    rep = sum(1 for k, n in ours.items() if n > 1)
    print(f"  keys we see more than once (retransmits/duplicates): {rep}")
    return ts == os_

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--suricata-yaml")
    a = ap.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        yaml = suricata_yaml(a.suricata_yaml, tmp)
        subprocess.run(["suricata", "-c", yaml, "-r", a.pcap, "-l", tmp, "-k", "none",
                        "--set", "stream.midstream=true", "--set", "app-layer.protocols.modbus.enabled=yes"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ours = os.path.join(tmp, "ours.jsonl")
        with open(ours, "w") as f:
            subprocess.run(["go", "run", "./scripts/modbus_dump", a.pcap], check=True, stdout=f)
        sreq, sresp = read_suricata(os.path.join(tmp, "eve.json"))
        oreq, oresp, events = read_ours(ours)
    ok = diff("requests", sreq, oreq)
    ok &= diff("responses", sresp, oresp)
    print("our anomaly events:", dict(events) or "none")
    sys.exit(0 if ok else 1)

main()
