#!/usr/bin/env python3
"""Compare our EtherNet/IP decoding with Suricata's enip eve records.

  scripts/compare_enip.py capture.pcap [--all] [--sets] [--suricata-src DIR]

Suricata names CIP services, statuses, vendors and device types. Its names are
mapped back to codes with the tables in its own source (rust/src/enip/logger.rs
under --suricata-src, default ~/gitRepos/suricata), so the comparison is on
numbers and does not depend on how either side spells a name.

Requests are compared per (client, client port, server, command, CIP service,
class, instance, attribute, embedded services); responses per (server, client,
client port, command, status, CIP service and status, identity, register
session, list services). Counts are exact unless --sets. invalid_pdu events are
compared per connection.
"""
import argparse, collections, json, os, re, subprocess, sys, tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import compare_modbus as cm

PORT = 44818


def table(src, func, value_type=int):
    """Parse `fn <func>` of Suricata's logger.rs into {name: code}."""
    text = open(os.path.join(src, "rust/src/enip/logger.rs")).read()
    body = text[text.index(f"fn {func}"):]
    body = body[:body.index("\n}\n")]
    out = {}
    for m in re.finditer(r'(0x[0-9A-Fa-f]+|\d+)\s*=>\s*Some\("((?:[^"\\]|\\.)*)"\)', body):
        out.setdefault(m.group(2), int(m.group(1), 0))
    return out


class Names:
    def __init__(self, src):
        self.svc = table(src, "cip_service_string")
        self.status = table(src, "cip_status_string")
        self.vendor = table(src, "enip_vendorid_string")
        self.dtype = table(src, "enip_devicetype_string")

    @staticmethod
    def code(m, name):
        if name is None:
            return None
        if name.startswith("unknown-"):
            return int(name[8:])
        return m.get(name, "?" + name)


def suricata_config(tmp):
    s = open("/opt/homebrew/etc/suricata/suricata.yaml").read()
    s = re.sub(r"^(\s+)- anomaly:", r"\1- enip\n\1- anomaly:", s, count=1, flags=re.M)
    out = os.path.join(tmp, "su.yaml")
    open(out, "w").write(s)
    return out


def cip_path(q):
    cls = inst = attr = -1
    for seg in q.get("path", []):
        if seg["segment_type"] == "class":
            cls = seg["value"]
        elif seg["segment_type"] == "instance":
            inst = seg["value"]
        elif seg["segment_type"] == "attribute":
            attr = seg["value"]
    return cls, inst, attr


def cip_key_s(c, n):
    svc = n.code(n.svc, c.get("service"))
    cls, inst, attr = cip_path(c)
    multi = tuple(cip_key_s(x, n) for x in c.get("multiple", []))
    if "status" in c:
        return ("resp", svc, n.code(n.status, c["status"]), multi)
    return ("req", svc, cls, inst, attr, multi)


def cip_key_o(c):
    multi = tuple(cip_key_o(x) for x in c.get("multiple", []))
    if c["response"]:
        return ("resp", c["service"], c["status"], multi)
    return ("req", c["service"], c["class"], c["instance"], c["attribute"], multi)


def ident_s(i, n):
    return (i["protocol_version"], i["revision"], n.code(n.vendor, i["vendor_id"]), n.code(n.dtype, i["device_type"]),
            i["product_code"], i["status"], i["serial"], i["product_name"], i["state"])


def ident_o(i):
    return (i["protocol_version"], i["revision"], i["vendor_id"], i["device_type"], i["product_code"],
            i["status"], i["serial"], i["product_name"], i["state"])


def client_of(e):
    if e.get("dest_port") == PORT and (e.get("src_port") != PORT):
        return cm.norm_ip(e["src_ip"]), e["src_port"]
    if e.get("src_port") == PORT and e.get("dest_port") != PORT:
        return cm.norm_ip(e["dest_ip"]), e["dest_port"]
    return cm.norm_ip(e["src_ip"]), e["src_port"]


def read_suricata(eve, n):
    req, resp, events = collections.Counter(), collections.Counter(), collections.Counter()
    for line in open(eve):
        e = json.loads(line)
        if e["event_type"] == "anomaly" and e.get("anomaly", {}).get("app_proto") == "enip":
            events[client_of(e) + (e["anomaly"]["event"],)] += 1
        if e["event_type"] != "enip":
            continue
        (c, cp) = client_of(e)
        s = cm.norm_ip(e["dest_ip"] if client_of(e)[0] == cm.norm_ip(e["src_ip"]) else e["src_ip"])
        for side, bucket in (("request", req), ("response", resp)):
            q = e["enip"].get(side)
            if q is None:
                continue
            extra = ()
            if "register_session" in q:
                r = q["register_session"]
                extra += (("reg", r["protocol_version"], r["options"]),)
            if "identity" in q:
                extra += (("id",) + ident_s(q["identity"], n),)
            if "list_services" in q:
                r = q["list_services"]
                extra += (("svc", r["protocol_version"], r["capabilities"], r["service_name"]),)
            cip = cip_key_s(q["cip"], n) if "cip" in q else None
            if side == "request":
                bucket[(c, cp, s, q["command"], q["status"], cip, extra)] += 1
            else:
                bucket[(s, c, cp, q["command"], q["status"], cip, extra)] += 1
    return req, resp, events


def read_ours(jsonl):
    req, resp, events = collections.Counter(), collections.Counter(), collections.Counter()
    for line in open(jsonl):
        e = json.loads(line)
        c, cp, s = (e["src"], e["sport"], e["dst"]) if e["request"] else (e["dst"], e["dport"], e["src"])
        c, s = cm.norm_ip(c), cm.norm_ip(s)
        for ev in e.get("events") or []:
            events[(c, cp, ev)] += 1
        extra = ()
        if "register_session" in e:
            r = e["register_session"]
            extra += (("reg", r["protocol_version"], r["options"]),)
        if "identity" in e:
            extra += (("id",) + ident_o(e["identity"]),)
        if "list_services" in e:
            r = e["list_services"]
            extra += (("svc", r["protocol_version"], r["capabilities"], r["service_name"]),)
        cip = cip_key_o(e["cip"]) if "cip" in e else None
        if e["request"]:
            req[(c, cp, s, e["command"], e["status"], cip, extra)] += 1
        else:
            resp[(s, c, cp, e["command"], e["status"], cip, extra)] += 1
    return req, resp, events


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--sets", action="store_true")
    ap.add_argument("--suricata-src", default=os.path.expanduser("~/gitRepos/suricata"))
    a = ap.parse_args()
    if a.all:
        cm.LIMIT = 10**9
    n = Names(a.suricata_src)
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(["suricata", "-c", suricata_config(tmp), "-r", a.pcap, "-l", tmp, "-k", "none",
                        "--set", "stream.midstream=true", "--set", "app-layer.protocols.enip.enabled=yes"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ours = os.path.join(tmp, "ours.jsonl")
        with open(ours, "w") as f:
            subprocess.run(["go", "run", "./scripts/enip_dump", a.pcap], check=True, stdout=f)
        sreq, sresp, sev = read_suricata(os.path.join(tmp, "eve.json"), n)
        oreq, oresp, oev = read_ours(ours)
    ok = cm.diff("requests", sreq, oreq, a.sets)
    ok &= cm.diff("responses", sresp, oresp, a.sets)
    cm.SHARED_EVENTS = {"invalid_pdu"}
    ok &= cm.diff_events(sev, oev, a.sets)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
