#!/usr/bin/env python3
"""Write a classic pcap with NetBIOS name service, NetBIOS session service and
SMB2 traffic, to test lib/hostid against tshark:

  scripts/hostid_demo_pcap.py demo.pcap && scripts/compare_hostid.py demo.pcap

UDP 137 datagrams, and one TCP connection per client port to 445 or 139. Frames
are built by hand from RFC 1001/1002, MS-SMB2 and MS-NLMP, so tshark is an
independent check of both the frames and our decoder.
"""
import struct, sys

C, S = bytes([10, 20, 0, 10]), bytes([10, 20, 0, 20])
frames, now = [], [1767225600.0]


def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b)); s = (s >> 16) + (s & 0xffff); s += s >> 16
    return ~s & 0xffff


def eth_for(dst):
    a, b = bytes.fromhex("020000000001"), bytes.fromhex("020000000002")
    return (b + a if dst == S else a + b) + b"\x08\x00"


def ip_packet(src, dst, proto, l4):
    ip = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(l4), 1, 0, 64, proto, 0) + src + dst
    return ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]


def tcp_frame(src, dst, sp, dp, seq, ack, flags, payload=b""):
    tcp = struct.pack("!HHIIBBHHH", sp, dp, seq & 0xffffffff, ack & 0xffffffff, 5 << 4, flags, 65535, 0, 0)
    ph = src + dst + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
    tcp = tcp[:16] + struct.pack("!H", csum(ph + tcp + payload)) + tcp[18:]
    now[0] += 0.005
    return (now[0], eth_for(dst) + ip_packet(src, dst, 6, tcp + payload) + tcp + payload)


def udp_frame(src, dst, sp, dp, payload):
    udp = struct.pack("!HHHH", sp, dp, 8 + len(payload), 0)
    now[0] += 0.005
    return (now[0], eth_for(dst) + ip_packet(src, dst, 17, udp + payload) + udp + payload)


class Conn:
    def __init__(self, port, server_port):
        self.port, self.sp, self.cseq, self.sseq = port, server_port, 1000, 5000
        frames.append(tcp_frame(C, S, port, server_port, self.cseq, 0, 0x02))
        frames.append(tcp_frame(S, C, server_port, port, self.sseq, self.cseq + 1, 0x12))
        frames.append(tcp_frame(C, S, port, server_port, self.cseq + 1, self.sseq + 1, 0x10))
        self.cseq += 1; self.sseq += 1

    def send(self, who, payload):
        if who == "c":
            frames.append(tcp_frame(C, S, self.port, self.sp, self.cseq, self.sseq, 0x18, payload)); self.cseq += len(payload)
        else:
            frames.append(tcp_frame(S, C, self.sp, self.port, self.sseq, self.cseq, 0x18, payload)); self.sseq += len(payload)


# ---- NetBIOS (RFC 1001/1002) ----

def nbname(name, suffix, scope=b""):
    raw = name.encode().ljust(15, b" ") + bytes([suffix])
    enc = b"".join(bytes([0x41 + (c >> 4), 0x41 + (c & 15)]) for c in raw)
    return b"\x20" + enc + scope + b"\x00"


def nbns(flags, qd, an, ns, ar, body, tid=0x1234):
    return struct.pack("!HHHHHH", tid, flags, qd, an, ns, ar) + body


def rr(name, typ, rdata, ttl=300):
    return name + struct.pack("!HHIH", typ, 1, ttl, len(rdata)) + rdata


def nb_addr(group, ip, ont=0):
    return struct.pack("!H", (0x8000 if group else 0) | ont << 13) + ip


def entry(name, suffix, flags):
    return name.encode().ljust(15, b" ") + bytes([suffix]) + struct.pack("!H", flags)


# ---- NTLMSSP (MS-NLMP) ----

def u16(s): return s.encode("utf-16-le")


def secbuf(n, off): return struct.pack("<HHI", n, n, off)


def av(i, v): return struct.pack("<HH", i, len(v)) + v


def ntlm_challenge(nbc, nbd, dnsc, dnsd, ver, flags=0x62898215):
    tn = u16(nbd)
    avs = av(2, u16(nbd)) + av(1, u16(nbc)) + av(4, u16(dnsd)) + av(3, u16(dnsc)) + av(7, struct.pack("<Q", 133800000000000000)) + av(0, b"")
    version = struct.pack("<BBHxxxB", ver[0], ver[1], ver[2], 15)
    return (b"NTLMSSP\0" + struct.pack("<I", 2) + secbuf(len(tn), 56) + struct.pack("<I", flags) + b"\x11" * 8 + b"\0" * 8 +
            secbuf(len(avs), 56 + len(tn)) + version + tn + avs)


def ntlm_authenticate(domain, user, ws, ver, flags=0x62888215):
    d, u, w = u16(domain), u16(user), u16(ws)
    base = 88
    version = struct.pack("<BBHxxxB", ver[0], ver[1], ver[2], 15)
    return (b"NTLMSSP\0" + struct.pack("<I", 3) + secbuf(0, base) + secbuf(0, base) + secbuf(len(d), base) +
            secbuf(len(u), base + len(d)) + secbuf(len(w), base + len(d) + len(u)) + secbuf(0, base) +
            struct.pack("<I", flags) + version + b"\0" * 16 + d + u + w)


# ---- SMB2 (MS-SMB2) ----

def smb2_header(cmd, response, status=0, session=0):
    flags = 1 if response else 0
    return (b"\xfeSMB" + struct.pack("<HHIHHIIQIIQ", 64, 1, status, cmd, 1, flags, 0, 1, 0, 0, session) + b"\0" * 16)


def nbss(payload, typ=0): return bytes([typ, 0]) + struct.pack("!H", len(payload)) + payload


def neg_request(dialects, sign_required, guid):
    mode = 3 if sign_required else 1
    body = struct.pack("<HHHHI", 36, len(dialects), mode, 0, 0) + guid + b"\0" * 8 + b"".join(struct.pack("<H", d) for d in dialects)
    return nbss(smb2_header(0, False) + body)


def neg_response(dialect, sign_required, guid, now_ft, boot_ft):
    mode = 3 if sign_required else 1
    body = (struct.pack("<HHHH", 65, mode, dialect, 0) + guid + struct.pack("<IIII", 0x7f, 8388608, 8388608, 8388608) +
            struct.pack("<QQ", now_ft, boot_ft) + struct.pack("<HHI", 128, 0, 0))
    return nbss(smb2_header(0, True) + body)


def der(tag, content):
    n = len(content)
    ln = bytes([n]) if n < 128 else (bytes([0x81, n]) if n < 256 else bytes([0x82, n >> 8, n & 255]))
    return bytes([tag]) + ln + content


NTLMSSP_OID = bytes.fromhex("2b06010401823702020a")


def spnego(ntlm, response):
    """SPNEGO NegTokenResp (RFC 4178 4.2.2) carrying an NTLMSSP message: the
    server's first reply also names the mechanism and says accept-incomplete."""
    inner = b""
    if response:
        inner += der(0xa0, der(0x0a, b"\x01")) + der(0xa1, der(0x06, NTLMSSP_OID))
    inner += der(0xa2, der(0x04, ntlm))
    return der(0xa1, der(0x30, inner))


SPNEGO_OID = bytes.fromhex("2b0601050502")


def ntlm_negotiate(flags=0x62088215):
    return b"NTLMSSP\0" + struct.pack("<I", 1) + struct.pack("<I", flags) + secbuf(0, 40) + secbuf(0, 40) + struct.pack("<BBHxxxB", 10, 0, 19045, 15)


def spnego_init(ntlm):
    """SPNEGO NegTokenInit (RFC 4178 4.2.1) offering NTLMSSP: the first token of
    a session setup, which tells the dissector what the later tokens are."""
    mech_types = der(0xa0, der(0x30, der(0x06, NTLMSSP_OID)))
    mech_token = der(0xa2, der(0x04, ntlm))
    return der(0x60, der(0x06, SPNEGO_OID) + der(0xa0, der(0x30, mech_types + mech_token)))


def session_setup(response, ntlm, init=False):
    blob = spnego_init(ntlm) if init else spnego(ntlm, response)
    status = 0xC0000016 if response else 0
    if response:   # MS-SMB2 2.2.6: StructureSize 9, SessionFlags, security buffer offset and length
        body = struct.pack("<HHHH", 9, 0, 72, len(blob)) + blob
    else:          # MS-SMB2 2.2.5: StructureSize 25, flags, mode, capabilities, channel, buffer, previous session id
        body = struct.pack("<HBBIIHHQ", 25, 0, 1, 0, 0, 88, len(blob), 0) + blob
    return nbss(smb2_header(1, response, status) + body)


def main(path):
    ports = iter(range(50000, 51000))
    GUID1 = bytes.fromhex("78563412bc9af0de0102030405060708")
    GUID2 = bytes.fromhex("00112233445566778899aabbccddeeff")
    NOW, DAY = 133800000000000000, 864000000000

    # NetBIOS name service on UDP 137.
    nbns_msgs = [
        (C, S, nbns(5 << 11 | 0x0110, 1, 0, 0, 1, nbname("HMI01", 0) + struct.pack("!HH", 0x20, 1) + rr(b"\xc0\x0c", 0x20, nb_addr(False, C)))),
        (C, S, nbns(5 << 11 | 0x0110, 1, 0, 0, 1, nbname("PLANT", 0) + struct.pack("!HH", 0x20, 1) + rr(b"\xc0\x0c", 0x20, nb_addr(True, C)))),
        (C, S, nbns(8 << 11 | 0x0110, 1, 0, 0, 1, nbname("HMI01", 0x20) + struct.pack("!HH", 0x20, 1) + rr(b"\xc0\x0c", 0x20, nb_addr(False, C)))),
        (C, S, nbns(0x0110, 1, 0, 0, 0, nbname("FILESRV", 0x20) + struct.pack("!HH", 0x20, 1))),
        (S, C, nbns(0x8500, 0, 1, 0, 0, rr(nbname("FILESRV", 0x20), 0x20, nb_addr(False, S)))),
        (S, C, nbns(0x8500, 0, 1, 0, 0, rr(nbname("WORKGROUP", 0x1c, scope=b"\x05plant\x07example"), 0x20, nb_addr(True, S) + nb_addr(True, C)))),
        (S, C, nbns(0x8500, 0, 1, 0, 0, rr(nbname("*", 0), 0x21,
            bytes([4]) + entry("FILESRV", 0x00, 0x0400) + entry("PLANT", 0x00, 0x8400) + entry("FILESRV", 0x20, 0x0400) + entry("PLANT", 0x1c, 0x8400) +
            bytes.fromhex("0a1b2c3d4e5f") + b"\0" * 40, ttl=0))),
        (S, C, nbns(0x8500, 0, 1, 0, 0, rr(nbname("*", 0), 0x21, bytes([1]) + entry("QUIET", 0x00, 0x0400) + b"\0" * 46, ttl=0))),
        (C, S, nbns(6 << 11 | 0x0110, 1, 0, 0, 1, nbname("HMI01", 0) + struct.pack("!HH", 0x20, 1) + rr(b"\xc0\x0c", 0x20, nb_addr(False, C)))),
    ]
    for src, dst, p in nbns_msgs:
        frames.append(udp_frame(src, dst, 137, 137, p))

    # SMB2 with signing required, Windows 10 / Server 2019 versions.
    c = Conn(next(ports), 445)
    c.send("c", neg_request([0x0202, 0x0210, 0x0300, 0x0302, 0x0311], False, GUID1))
    c.send("s", neg_response(0x0311, True, GUID2, NOW, NOW - 5 * DAY))
    c.send("c", session_setup(False, ntlm_negotiate(), init=True))
    c.send("s", session_setup(True, ntlm_challenge("FILESRV", "PLANT", "filesrv.plant.example", "plant.example", (10, 0, 17763))))
    c.send("c", session_setup(False, ntlm_authenticate("PLANT", "operator", "HMI01", (10, 0, 19045))))

    # An older server: SMB 2.1, signing off, Windows 7 version.
    c = Conn(next(ports), 445)
    c.send("c", neg_request([0x0202, 0x0210], True, GUID2))
    c.send("s", neg_response(0x0210, False, GUID1, NOW, NOW - 90 * DAY))
    c.send("c", session_setup(False, ntlm_negotiate(), init=True))
    c.send("s", session_setup(True, ntlm_challenge("OLDBOX", "WORKGROUP", "oldbox", "workgroup", (6, 1, 7601))))

    # NetBIOS session service on 139: a session request, then the same SMB2 exchange.
    c = Conn(next(ports), 139)
    c.send("c", nbss(nbname("FILESRV", 0x20) + nbname("HMI01", 0x00), typ=0x81))
    c.send("s", bytes([0x82, 0, 0, 0]))
    c.send("c", neg_request([0x0202], False, GUID1))

    # Not SMB on 445, and an SMB1 negotiate response header.
    c = Conn(next(ports), 445)
    c.send("c", b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"); c.send("s", b"HTTP/1.1 200 OK\r\n\r\n")

    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for ts, fr in frames:
            f.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(fr), len(fr)) + fr)


if __name__ == "__main__":
    main(sys.argv[1])
