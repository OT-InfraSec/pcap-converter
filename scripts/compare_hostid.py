#!/usr/bin/env python3
"""Compare lib/hostid with tshark's NBNS, NBSS, SMB2 and NTLMSSP dissectors.

  scripts/compare_hostid.py capture.pcap [--all]

Per packet, both sides give a set of facts and the sets are diffed:

  NBNS   the names an NB record binds to an address (answers of a name query,
         registrations and refreshes), the names of a node status reply with
         their group flags, and the adapter address
  NBSS   the called and calling names of a session request
  SMB2   command, response flag, and for a negotiate the dialects, signing
         mode, GUID and the server's clock and start time
  NTLM   for CHALLENGE: target name, NetBIOS and DNS names, version; for
         AUTHENTICATE: domain, user, workstation, version

tshark is the reference. Our SMB decoder reads the first PDU of a segment and
does not reassemble; the demo capture is built accordingly.
"""
import argparse, io, os, re, subprocess, sys
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import compare_modbus as cm

DIALECTS = {0x0202: "2.0.2", 0x0210: "2.1", 0x0300: "3.0", 0x0302: "3.0.2", 0x0311: "3.1.1", 0x02ff: "2.x"}
NAME_RE = re.compile(r"^(.*?<[0-9a-f]{2}>)")


def nbname(s):
    m = NAME_RE.match(s)
    return m.group(1) if m else s


def hostlike(ip):
    return ip not in ("0.0.0.0", "255.255.255.255") and not ip.startswith("224.")


def tshark_facts(pcap):
    out = subprocess.run(["tshark", "-r", pcap, "-Y", "nbns || smb2 || nbss", "-T", "pdml"],
                         check=True, capture_output=True, text=True).stdout
    facts = set()
    for _, pk in ET.iterparse(io.StringIO(out), events=("end",)):
        if pk.tag != "packet":
            continue
        fields = [(f.get("name"), f) for f in pk.iter("field") if f.get("name")]
        frame = next(int(f.get("show")) for n, f in fields if n == "frame.number")
        nbns(frame, fields, facts)
        smb(frame, fields, facts)
    return facts


def nbns(frame, fields, facts):
    names = [n for n, _ in fields]
    if "nbns.flags.opcode" not in names:
        return
    show = lambda key: next(f.get("show") for n, f in fields if n == key)
    opcode, response = int(show("nbns.flags.opcode")), show("nbns.flags.response") == "True"
    binds = (response and opcode == 0) or (not response and opcode in (5, 8))
    rec = None          # the NB record being read
    status = None       # the node status name being read
    for n, f in fields:
        v = f.get("show")
        if n == "nbns.name":
            rec = {"name": nbname(v), "type": None, "answer": False, "group": False}
        elif rec and n == "nbns.type":
            rec["type"] = int(v)
        elif rec and n == "nbns.ttl":
            rec["answer"] = True
        elif rec and n == "nbns.nb_flags.group":
            rec["group"] = v == "True"
        elif rec and n == "nbns.addr":
            if binds and rec["answer"] and rec["type"] == 32 and hostlike(v):
                facts.add(("nbns", frame, "bind", rec["name"], rec["group"], v))
        elif n == "nbns.netbios_name":
            status = nbname(f.get("showname").split("Name: ", 1)[1])
        elif status and n == "nbns.name_flags.group":
            if response and opcode == 0:
                facts.add(("nbns", frame, "status", status, v == "True"))
            status = None
        elif n == "nbns.unit_id" and response and opcode == 0 and v != "00:00:00:00:00:00":
            facts.add(("nbns", frame, "mac", v))


def smb(frame, fields, facts):
    names = [n for n, _ in fields]
    first = lambda key: next((f for n, f in fields if n == key), None)
    t = first("nbss.type")
    if t is not None and int(t.get("show"), 0) == 0x81:
        facts.add(("nbss", frame, "called", first("nbss.called_name").get("show")))
        facts.add(("nbss", frame, "calling", first("nbss.calling_name").get("show")))
    if "smb2.cmd" in names:
        cmd = int(first("smb2.cmd").get("show"))
        response = first("smb2.flags.response").get("show") == "True"
        facts.add(("smb", frame, "cmd", cmd))
        facts.add(("smb", frame, "response", response))
        if cmd == 0:
            dialects = tuple(DIALECTS.get(int(f.get("show"), 0), f.get("show")) for n, f in fields if n == "smb2.dialect")
            facts.add(("smb", frame, "dialect" if response else "offered", dialects[0] if response else dialects))
            facts.add(("smb", frame, "sign", first("smb2.sec_mode.sign_enabled").get("show") == "True",
                       first("smb2.sec_mode.sign_required").get("show") == "True"))
            g = first("smb2.server_guid" if response else "smb2.client_guid")
            if g is not None and set(g.get("show")) - set("0-"):
                facts.add(("smb", frame, "guid", g.get("show")))
            if response:
                for key, label in (("smb2.current_time", "systime"), ("smb2.boot_time", "boottime")):
                    f = first(key)
                    if f is not None:
                        facts.add(("smb", frame, label, int.from_bytes(bytes.fromhex(f.get("value")), "little")))
    mt = first("ntlmssp.messagetype")
    if mt is not None:
        typ = int(mt.get("show"), 0)
        ntlm = lambda key, label: [facts.add(("ntlm", frame, typ, label, first(key).get("show")))] if first(key) is not None and first(key).get("show") else None
        if typ == 2:
            ntlm("ntlmssp.challenge.target_name", "target")
            ntlm("ntlmssp.challenge.target_info.nb_computer_name", "nb_computer")
            ntlm("ntlmssp.challenge.target_info.nb_domain_name", "nb_domain")
            ntlm("ntlmssp.challenge.target_info.dns_computer_name", "dns_computer")
            ntlm("ntlmssp.challenge.target_info.dns_domain_name", "dns_domain")
        elif typ == 3:
            ntlm("ntlmssp.auth.domain", "domain")
            ntlm("ntlmssp.auth.username", "user")
            ntlm("ntlmssp.auth.hostname", "workstation")
        if typ in (2, 3) and first("ntlmssp.version.major") is not None:
            facts.add(("ntlm", frame, typ, "version", int(first("ntlmssp.version.major").get("show")),
                       int(first("ntlmssp.version.minor").get("show")), int(first("ntlmssp.version.build_number").get("show"))))


def our_facts(pcap):
    import json
    out = subprocess.run(["go", "run", "./scripts/hostid_dump", pcap], check=True, capture_output=True, text=True).stdout
    facts = set()
    for line in out.splitlines():
        e = json.loads(line)
        n = e["pkt"]
        if e["kind"] == "nbns":
            for name, group, ip in e["bind"] or []:
                facts.add(("nbns", n, "bind", name, group, ip))
            for name, group in e["status"] or []:
                facts.add(("nbns", n, "status", name, group))
            if e["mac"]:
                facts.add(("nbns", n, "mac", e["mac"]))
        elif e["nbss"] == 0x81:
            facts.add(("nbss", n, "called", e["called"]))
            facts.add(("nbss", n, "calling", e["calling"]))
        elif e["smb_kind"] == 2:
            facts.add(("smb", n, "cmd", e["command"]))
            facts.add(("smb", n, "response", e["response"]))
            if e["command"] == 0:
                if e["response"]:
                    facts.add(("smb", n, "dialect", e["dialect"]))
                    facts.add(("smb", n, "systime", e["system_time"]))
                    facts.add(("smb", n, "boottime", e["start_time"]))
                else:
                    facts.add(("smb", n, "offered", tuple(e["offered"] or [])))
                facts.add(("smb", n, "sign", e["signing_enabled"], e["signing_required"]))
                if e["guid"]:
                    facts.add(("smb", n, "guid", e["guid"]))
            m = e.get("ntlm")
            if m:
                t = m["type"]
                keys = {2: ("target", "nb_computer", "nb_domain", "dns_computer", "dns_domain"), 3: ("domain", "user", "workstation")}[t]
                for k in keys:
                    if m[k]:
                        facts.add(("ntlm", n, t, k, m[k]))
                if m.get("version"):
                    facts.add(("ntlm", n, t, "version", *m["version"]))
    return facts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--all", action="store_true")
    a = ap.parse_args()
    if a.all:
        cm.LIMIT = 10**9
    ok = cm.diff("host identity facts (tshark vs ours)", tshark_facts(a.pcap), our_facts(a.pcap), True)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
