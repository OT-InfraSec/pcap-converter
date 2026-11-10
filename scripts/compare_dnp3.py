#!/usr/bin/env python3
"""Compare our DNP3 decoding with tshark's DNP3 dissector.

  scripts/compare_dnp3.py capture.pcap [--all] [--sets]

Suricata's DNP3 parser only logs, so tshark is the reference here. Per link
frame the key is (client, client port, transport, direction, control byte,
destination, source, length) and, for the frame that completes an application
fragment, (application control, function, IIN, objects as group, variation,
prefix code, range code, start, stop, quantity). tshark differs from us, on
purpose, in two places: it lists no objects for Assign Class (function 22), and
it reports groups 110 to 113 with variation 0 (the variation is a length), so
both sides are normalised. Counts are exact unless
--sets. tshark reassembles TCP itself.
"""
import argparse, collections, io, json, os, subprocess, sys, tempfile
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import compare_modbus as cm

PORT = 20000


def num(s):
    return int(s, 0)


def packets(pcap):
    out = cm.tshark_pdml(pcap, "dnp3")
    for _, pk in ET.iterparse(io.StringIO(out), events=("end",)):
        if pk.tag != "packet":
            continue
        src = dst = sport = dport = None
        transport = "tcp"
        frames = []
        for proto in pk.findall("proto"):
            name = proto.get("name")
            if name in ("ip", "ipv6"):
                f = {x.get("name"): x.get("show") for x in proto.iter("field")}
                src, dst = f.get("ip.src") or f.get("ipv6.src"), f.get("ip.dst") or f.get("ipv6.dst")
            elif name in ("tcp", "udp"):
                f = {x.get("name"): x.get("show") for x in proto.iter("field")}
                transport = name
                sport, dport = int(f[name + ".srcport"]), int(f[name + ".dstport"])
            elif name == "dnp3":
                frames.append([(x.get("name"), x.get("show")) for x in proto.iter("field")])
        if src is not None:
            yield cm.norm_ip(src), cm.norm_ip(dst), transport, sport, dport, frames
        pk.clear()


def frame_key(fields):
    d = collections.defaultdict(list)
    for k, v in fields:
        d[k].append(v)
    first = lambda k, default=0: num(d[k][0]) if d.get(k) and d[k][0] not in ("", "True", "False") else default
    link = (first("dnp3.ctl"), first("dnp3.dst"), first("dnp3.src"), first("dnp3.len"))
    app = None
    if d.get("dnp3.al.func"):
        objs, cur = [], None
        for k, v in fields:
            if k == "dnp3.al.obj":
                cur = {"gv": num(v), "prefix": 0, "range": 0, "start": 0, "stop": 0, "qty": 0}
                objs.append(cur)
            elif cur is not None:
                if k == "dnp3.al.objq.prefix":
                    cur["prefix"] = num(v)
                elif k == "dnp3.al.objq.range":
                    cur["range"] = num(v)
                elif k == "dnp3.al.range.start":
                    cur["start"] = num(v)
                elif k == "dnp3.al.range.stop":
                    cur["stop"] = num(v)
                elif k == "dnp3.al.range.quantity":
                    cur["qty"] = num(v)
        func = first("dnp3.al.func")
        if func == 22:
            objs = []   # tshark lists no objects for Assign Class
        app = (first("dnp3.al.ctl"), func, first("dnp3.al.iin") if func in (129, 130, 131) else 0,
               tuple((o["gv"] >> 8, 0 if 110 <= o["gv"] >> 8 <= 113 else o["gv"] & 0xff, o["prefix"], o["range"], o["start"], o["stop"], o["qty"]) for o in objs))
    return link, app


def read_tshark(pcap):
    c = collections.Counter()
    for src, dst, tr, sp, dp, frames in packets(pcap):
        request = dp == PORT
        cl, cp, srv = (src, sp, dst) if request else (dst, dp, src)
        for f in frames:
            link, app = frame_key(f)
            c[(cl, cp, tr, request, link, app)] += 1
    return c


def read_ours(jsonl):
    c, events = collections.Counter(), collections.Counter()
    for line in open(jsonl):
        e = json.loads(line)
        if e.get("invalid") or (not e["has_transport"] and e["len"] < 5):
            for ev in e.get("events") or []:
                events[("", 0, ev)] += 1
            continue
        request = e["request"]
        cl, cp, srv = (e["src"], e["sport"], e["dst"]) if request else (e["dst"], e["dport"], e["src"])
        cl = cm.norm_ip(cl)
        a = e.get("app")
        app = None
        if a:
            app = (a["ctl"], a["func"], a["iin"] if a["func"] in (129, 130, 131) else 0, () if a["func"] == 22 else tuple((o[0], 0 if 110 <= o[0] <= 113 else o[1]) + tuple(o[2:]) for o in (a["objects"] or ())))
        link = (e["ctl"], e["dest"], e["source"], e["len"])
        c[(cl, cp, e["transport"], request, link, app)] += 1
        for ev in e.get("events") or []:
            events[(cl, cp, ev)] += 1
    return c, events


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--sets", action="store_true")
    a = ap.parse_args()
    if a.all:
        cm.LIMIT = 10**9
    with tempfile.TemporaryDirectory() as tmp:
        ours = os.path.join(tmp, "ours.jsonl")
        with open(ours, "w") as f:
            subprocess.run(["go", "run", "./scripts/dnp3_dump", a.pcap], check=True, stdout=f)
        t = read_tshark(a.pcap)
        o, events = read_ours(ours)
    ok = cm.diff("DNP3 frames (tshark vs ours)", t, o, a.sets)
    if events:
        tot = collections.Counter()
        for (_, _, ev), n in events.items():
            tot[ev] += n
        print("our events:", dict(tot))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
