#!/usr/bin/env python3
"""Compare application-protocol detection with Suricata, flow by flow.

Usage:
  scripts/compare_suricata.py capture.pcap [capture2.pcap ...]
  scripts/compare_suricata.py --eve eve.json --db database.sqlite   # skip running the tools

For each pcap the script runs Suricata offline (all OT parsers enabled) and the
importer, then joins the results on (transport, unordered endpoint pair) and
prints three groups:
  agree     both name the same protocol
  we-miss   Suricata names a protocol, we name none (or a different one)
  we-extra  we name a protocol, Suricata names none

Exit status is 1 if --fail-on-miss is given and any flow is in we-miss.
Protocol labels are normalised through ALIASES below; extend it when a new
label shows up in the report.
"""
import argparse, collections, ipaddress, json, os, shutil, sqlite3, subprocess, sys, tempfile

# Suricata app_proto -> canonical name; our label (lower-case) -> canonical name.
SURICATA_ALIASES = {
    "failed": None, "unknown": None,
    "http": "http", "http2": "http2", "tls": "tls", "dns": "dns", "mdns": "mdns",
    "llmnr": "llmnr", "dhcp": "dhcp", "ntp": "ntp", "ssh": "ssh", "smb": "smb",
    "snmp": "snmp", "krb5": "kerberos", "ldap": "ldap", "enip": "enip",
    "modbus": "modbus", "dnp3": "dnp3", "ftp": "ftp", "smtp": "smtp",
}
OUR_ALIASES = {
    "ethernet/ip": "enip", "ethernetip": "enip", "ethernet/ip(tcp)": "enip",
    "ethernet/ip(udp)": "enip", "enip": "enip",
    "modbus": "modbus", "modbus tcp": "modbus", "dnp3": "dnp3",
    "http": "http", "https": "tls", "tls": "tls", "dns": "dns", "mdns": "mdns",
    "llmnr": "llmnr", "dhcp": "dhcp", "dhcpv4": "dhcp", "dhcpv6": "dhcp", "ntp": "ntp", "ssh": "ssh", "smb": "smb",
    "snmp": "snmp", "kerberos": "kerberos", "ldap": "ldap", "ftp": "ftp", "smtp": "smtp",
    # Transport-only labels carry no application information.
    "tcp": None, "udp": None, "icmp": None, "arp": None, "igmp": None,
}

def norm_ip(ip):
    """Suricata prints IPv6 expanded, we store it compressed."""
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return ip

def parse_ports(text):
    """Port set from a flows.source_ports / destination_ports cell."""
    out = set()
    for tok in (text or "").replace("[", "").replace("]", "").split(","):
        tok = tok.strip()
        if tok.isdigit():
            out.add(int(tok))
    return out

def read_suricata(eve_path):
    """Return a list of (src_ip, src_port, dst_ip, dst_port, canonical app proto).

    A flow Suricata labels failed/unknown is kept with proto None so it counts
    as a flow Suricata has no opinion on."""
    out = []
    with open(eve_path) as f:
        for line in f:
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            if ev.get("event_type") != "flow":
                continue
            if ev.get("proto", "").lower() not in ("tcp", "udp"):
                continue
            name = ev.get("app_proto", "").lower()
            canon = SURICATA_ALIASES.get(name, name) if name else None
            out.append((norm_ip(ev["src_ip"]), int(ev.get("src_port") or 0),
                        norm_ip(ev["dest_ip"]), int(ev.get("dest_port") or 0), canon))
    return out

def read_ours(db_path):
    """Return flows as dicts. Our flow rows aggregate every connection between
    two hosts that shares a label, so ports are sets."""
    con = sqlite3.connect(db_path)
    flows = []
    try:
        for src, dst, sp, dp, proto, sps, dps in con.execute(
                "SELECT src_ip, dst_ip, src_port, dst_port, protocol, source_ports, destination_ports FROM flows"):
            label = (proto or "").lower()
            canon = OUR_ALIASES.get(label, label)
            flows.append({"src": norm_ip(src), "dst": norm_ip(dst), "label": canon, "raw": proto,
                          "sports": parse_ports(sps) | ({int(sp)} if sp else set()),
                          "dports": parse_ports(dps) | ({int(dp)} if dp else set())})
    finally:
        con.close()
    return flows

def find_ours(index, sip, sport, dip, dport):
    """Our flow rows covering one Suricata flow. The best match is the one with
    an application label; a plain tcp/udp row is the fallback."""
    best = None
    for f in index.get(frozenset((sip, dip)), []):
        if f["src"] == sip:
            ok = sport in f["sports"] and dport in f["dports"]
        else:
            ok = sport in f["dports"] and dport in f["sports"]
        if ok and (best is None or (best["label"] is None and f["label"] is not None)):
            best = f
    return best

def compare(suri, ours):
    index = collections.defaultdict(list)
    for f in ours:
        index[frozenset((f["src"], f["dst"]))].append(f)
    agree, miss, unmatched = [], [], []
    covered = set()
    for sip, sport, dip, dport, name in suri:
        f = find_ours(index, sip, sport, dip, dport)
        mine = f["label"] if f else None
        if f:
            covered.add(id(f))
        if name is None:
            continue
        label = f"{sip}:{sport} <-> {dip}:{dport}"
        (agree if mine == name else miss).append((label, name, mine))
    # Our labelled rows that no Suricata app-layer flow supports, checked per
    # port so UDP 2222 implicit I/O (which Suricata fails on) shows up.
    named = collections.defaultdict(list)
    for sip, sport, dip, dport, name in suri:
        if name:
            named[frozenset((sip, dip))].append((sip, sport, dport, name))
    extra = []
    for f in ours:
        if not f["label"]:
            continue
        supported = False
        for sip, sport, dport, name in named.get(frozenset((f["src"], f["dst"])), []):
            if name != f["label"]:
                continue
            if sip == f["src"]:
                supported |= sport in f["sports"] and dport in f["dports"]
            else:
                supported |= sport in f["dports"] and dport in f["sports"]
        if not supported:
            ports = f"{sorted(f['sports'])[:3]}->{sorted(f['dports'])[:3]}"
            extra.append((f"{f['src']} <-> {f['dst']} {ports}", None, f["label"]))
    return agree, miss, extra

def run_tools(pcap, workdir, importer, suricata):
    eve_dir = os.path.join(workdir, "suricata")
    os.makedirs(eve_dir, exist_ok=True)
    # midstream: captures often start inside a TCP session. Suricata ignores
    # such sessions by default; we label them, so compare like with like.
    cmd = [suricata, "-r", pcap, "-l", eve_dir, "-k", "none", "--set", "stream.midstream=true"]
    for name in ("modbus", "dnp3", "enip"):
        cmd += ["--set", f"app-layer.protocols.{name}.enabled=yes"]
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    db = os.path.join(workdir, "ours.sqlite")
    subprocess.run([importer, "import", pcap, "--db-path", db, "--clear", "--industrial"],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return os.path.join(eve_dir, "eve.json"), db

def report(label, agree, miss, extra):
    print(f"== {label}")
    print(f"agree={len(agree)} we-miss={len(miss)} we-extra={len(extra)}")
    by = collections.Counter((s, m) for _, s, m in miss)
    for (s, m), n in by.most_common():
        print(f"  we-miss  suricata={s:<10} ours={m or '-':<10} flows={n}")
    for k, s, m in miss[:20]:
        print(f"    {k}  suricata={s} ours={m}")
    by = collections.Counter(m for _, _, m in extra)
    for m, n in by.most_common():
        print(f"  we-extra ours={m:<10} flows={n}")
        for k, _, mm in [e for e in extra if e[2] == m][:2]:
            print(f"    {k}")

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcaps", nargs="*")
    ap.add_argument("--eve")
    ap.add_argument("--db")
    ap.add_argument("--importer", default="./pcap-importer")
    ap.add_argument("--suricata", default="suricata")
    ap.add_argument("--fail-on-miss", action="store_true")
    ap.add_argument("--protocols", help="comma-separated protocols to count for --fail-on-miss, "
                    "for example enip,modbus,dnp3 (default: all)")
    args = ap.parse_args()

    jobs = []  # (label, eve path, db path)
    tmp = None
    if args.eve or args.db:
        if not (args.eve and args.db):
            ap.error("--eve and --db go together")
        jobs.append(("given", args.eve, args.db))
    else:
        if not args.pcaps:
            ap.error("give pcap files, or --eve and --db")
        if not shutil.which(args.suricata):
            sys.exit(f"suricata not found ({args.suricata}); install it or pass --eve/--db")
        if not os.path.exists(args.importer):
            sys.exit(f"importer not found ({args.importer}); run: go build -o pcap-importer ./cmd/importer")
        tmp = tempfile.mkdtemp(prefix="suricata-compare-")
        for pcap in args.pcaps:
            wd = os.path.join(tmp, os.path.basename(pcap))
            os.makedirs(wd)
            eve, db = run_tools(os.path.abspath(pcap), wd, os.path.abspath(args.importer), args.suricata)
            jobs.append((pcap, eve, db))

    gate = set(args.protocols.split(",")) if args.protocols else None
    total_miss = 0
    for label, eve, db in jobs:
        a, m, e = compare(read_suricata(eve), read_ours(db))
        report(label, a, m, e)
        total_miss += len([x for x in m if gate is None or x[1] in gate])
    if tmp:
        shutil.rmtree(tmp, ignore_errors=True)
    if args.fail_on_miss and total_miss:
        sys.exit(1)

if __name__ == "__main__":
    main()
