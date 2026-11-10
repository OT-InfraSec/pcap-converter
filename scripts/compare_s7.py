#!/usr/bin/env python3
"""Compare our S7comm decoding with tshark's S7comm dissector.

  scripts/compare_s7.py capture.pcap [--all] [--sets]

Suricata has no S7comm parser, so tshark is the independent reference. For each
S7 PDU the key is (client, client port, direction, ROSCTR, PDU reference,
function or userdata group and subfunction, error class and code, request
items as (area, DB, bit address, length, transport size), data return codes,
SZL id and index). COTP connection frames are compared by their TSAPs, and
SZL 0x001C / 0x0011 replies by the identity strings. Counts are exact unless
--sets. tshark reassembles TCP itself, so a split or retransmitted segment
should not change either side.
"""
import argparse, collections, json, os, subprocess, sys, tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import compare_modbus as cm

PORT = 102
COTP_TYPES = {0x0e: "CR", 0x0d: "CC", 0x0f: "DT", 0x08: "DR", 0x0c: "DC", 0x07: "ER"}
SZL_STRINGS = {1: "s7comm.szl.001c.0001.name", 2: "s7comm.szl.001c.0002.name", 3: "s7comm.szl.001c.0003.tag",
               4: "s7comm.szl.001c.0004.copyright", 5: "s7comm.szl.001c.0005.serialn", 7: "s7comm.szl.001c.0007.cputypname",
               8: "s7comm.szl.001c.0008.snmcmmc"}


def num(s):
    return int(s, 0)


def first(v, default=0):
    return num(v[0]) if v else default


def packets(pcap):
    """Yield (src, dst, sport, dport, cotp_fields, [s7comm field dicts]) per
    packet from tshark's PDML, one dict per S7 PDU in order."""
    import xml.etree.ElementTree as ET
    out = cm.tshark_pdml(pcap, "s7comm or cotp.type == 0x0e or cotp.type == 0x0d")
    for _, pk in ET.iterparse(__import__("io").StringIO(out), events=("end",)):
        if pk.tag != "packet":
            continue
        src = dst = sport = dport = None
        cotp = {}
        pdus = []
        for proto in pk.findall("proto"):
            name = proto.get("name")
            flat = collections.defaultdict(list)
            for fld in proto.iter("field"):
                flat[fld.get("name")].append(fld.get("show") if fld.get("show") is not None else "")
                if fld.get("name", "").endswith("tsap-bytes"):
                    flat[fld.get("name")][-1] = fld.get("value") or ""
            if name in ("ip", "ipv6"):
                src, dst = flat["ip.src" if name == "ip" else "ipv6.src"][0], flat["ip.dst" if name == "ip" else "ipv6.dst"][0]
            elif name == "tcp":
                sport, dport = int(flat["tcp.srcport"][0]), int(flat["tcp.dstport"][0])
            elif name == "cotp":
                cotp = flat
            elif name == "s7comm":
                pdus.append(flat)
        if src is not None and dport is not None:
            yield cm.norm_ip(src), cm.norm_ip(dst), sport, dport, cotp, pdus
        pk.clear()


def ident_t(f):
    d = {}
    for idx, name in SZL_STRINGS.items():
        if f.get(name):
            d[f"s{idx}"] = f[name][0].rstrip(" \0")
    if f.get("s7comm.szl.xy11.0001.anz"):
        d["order_number"] = f["s7comm.szl.xy11.0001.anz"][0].rstrip(" \0")
        d["module_type"] = first(f["s7comm.szl.xy11.0001.bgtyp"])
        d["ausbg"] = first(f["s7comm.szl.xy11.0001.ausbg"])
        d["ausbe"] = first(f["s7comm.szl.xy11.0001.ausbe"])
    return tuple(sorted(d.items()))


def read_tshark(pcap):
    pdus, conns = collections.Counter(), collections.Counter()
    for src, dst, sp, dp, cotp, ps in packets(pcap):
        request = dp == PORT
        c, cp, s = (src, sp, dst) if request else (dst, dp, src)
        if not ps:
            t = COTP_TYPES.get(first(cotp.get("cotp.type", [])), "?")
            conns[(c, cp, s, request, t, "".join(cotp.get("cotp.src-tsap-bytes", [""])[:1]), "".join(cotp.get("cotp.dst-tsap-bytes", [""])[:1]))] += 1
            continue
        for f in ps:
            rosctr = first(f["s7comm.header.rosctr"])
            if rosctr == 7 and f.get("s7comm.param.userdata.funcgroup"):
                func = ("ud", first(f["s7comm.param.userdata.funcgroup"]), first(f["s7comm.param.userdata.subfunc"]))
            else:
                func = ("fn", first(f.get("s7comm.param.func", [])))
            n = len(f.get("s7comm.param.item.area", []))
            cols = [[num(x) for x in f.get(k, [])] or [0] * n for k in
                    ("s7comm.param.item.area", "s7comm.param.item.db", "s7comm.param.item.address", "s7comm.param.item.length",
                     "s7comm.param.item.transp_size")]
            items = tuple(zip(*cols)) if n else ()
            szl = (first(f.get("s7comm.data.userdata.szl_id", [])), first(f.get("s7comm.data.userdata.szl_index", [])))
            pdus[(c, cp, s, request, rosctr, first(f["s7comm.header.pduref"]), func,
                  (first(f.get("s7comm.header.errcls", [])), first(f.get("s7comm.header.errcod", []))), items,
                  tuple(num(x) for x in f.get("s7comm.data.returncode", [])), szl, ident_t(f))] += 1
    return pdus, conns


def read_ours(jsonl):
    pdus, conns = collections.Counter(), collections.Counter()
    for line in open(jsonl):
        e = json.loads(line)
        request = e["request"]
        c, cp, s = (e["src"], e["sport"], e["dst"]) if request else (e["dst"], e["dport"], e["src"])
        c, s = cm.norm_ip(c), cm.norm_ip(s)
        if not e["has_s7"]:
            if e["cotp"] in ("CR", "CC"):
                conns[(c, cp, s, request, e["cotp"], e.get("src_tsap", ""), e.get("dst_tsap", ""))] += 1
            continue
        u = e.get("userdata")
        func = ("ud", u["group"], u["sub"]) if u else ("fn", e["function"])
        items = tuple(tuple(i) for i in (e["items"] or ()))
        ident = tuple(sorted((e.get("identity") or {}).items()))
        pdus[(c, cp, s, request, e["rosctr"], e["pduref"], func, (e["error_class"], e["error_code"]), items,
              tuple(e["return_codes"] or ()), (u["szl_id"], u["szl_index"]) if u else (0, 0), ident)] += 1
        for ev in e.get("events") or []:
            conns[("event", c, cp, ev)] += 1
    return pdus, conns


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
            subprocess.run(["go", "run", "./scripts/s7_dump", a.pcap], check=True, stdout=f)
        tp, tc = read_tshark(a.pcap)
        op, oc = read_ours(ours)
    events = {k: v for k, v in oc.items() if k[0] == "event"}
    oc = collections.Counter({k: v for k, v in oc.items() if k[0] != "event"})
    ok = cm.diff("S7 PDUs", tp, op, a.sets)
    ok &= cm.diff("COTP connection frames", tc, oc, a.sets)
    if events:
        print("our events:", {f"{k[1]}:{k[2]} {k[3]}": v for k, v in events.items()})
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
