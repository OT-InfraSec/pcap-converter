#!/usr/bin/env python3
"""Write a classic pcap with a mix of DNP3 traffic, to test the DNP3 decoder
against tshark:

  scripts/dnp3_demo_pcap.py demo.pcap && scripts/compare_dnp3.py demo.pcap

Every TCP connection is its own session from a different client port to port
20000; UDP datagrams use their own ports. Frames and CRCs are built by hand,
so tshark is an independent check of both the frames and our decoder.
"""
import struct, sys

C, S = bytes([10, 20, 0, 10]), bytes([10, 20, 0, 20])
PORT = 20000
frames, now = [], [1767225600.0]


def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b)); s = (s >> 16) + (s & 0xffff); s += s >> 16
    return ~s & 0xffff


def eth_for(dst):
    a, b = bytes.fromhex("020000000001"), bytes.fromhex("020000000002")
    return (b + a if dst == S else a + b) + b"\x08\x00"


def frame(src, dst, sp, dp, seq, ack, flags, payload=b""):
    tcp = struct.pack("!HHIIBBHHH", sp, dp, seq & 0xffffffff, ack & 0xffffffff, 5 << 4, flags, 65535, 0, 0)
    ph = src + dst + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
    tcp = tcp[:16] + struct.pack("!H", csum(ph + tcp + payload)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(tcp) + len(payload), 1, 0, 64, 6, 0) + src + dst
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    now[0] += 0.005
    return (now[0], eth_for(dst) + ip + tcp + payload)


def udp_frame(src, dst, sp, dp, payload):
    udp = struct.pack("!HHHH", sp, dp, 8 + len(payload), 0)
    ip = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(udp) + len(payload), 1, 0, 64, 17, 0) + src + dst
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    now[0] += 0.005
    return (now[0], eth_for(dst) + ip + udp + payload)


class Conn:
    def __init__(self, port, cseq=1000, sseq=5000):
        self.port, self.cseq, self.sseq = port, cseq, sseq
        frames.append(frame(C, S, port, PORT, cseq, 0, 0x02))
        frames.append(frame(S, C, PORT, port, sseq, cseq + 1, 0x12))
        frames.append(frame(C, S, port, PORT, cseq + 1, sseq + 1, 0x10))
        self.cseq += 1; self.sseq += 1

    def send(self, who, payload, flags=0x18):
        if who == "c":
            frames.append(frame(C, S, self.port, PORT, self.cseq, self.sseq, flags, payload)); self.cseq += len(payload)
        else:
            frames.append(frame(S, C, PORT, self.port, self.sseq, self.cseq, flags, payload)); self.sseq += len(payload)

    def raw(self, who, seq, payload):
        if who == "c":
            frames.append(frame(C, S, self.port, PORT, seq, self.sseq, 0x18, payload))
        else:
            frames.append(frame(S, C, PORT, self.port, seq, self.cseq, 0x18, payload))

    def close(self):
        frames.append(frame(C, S, self.port, PORT, self.cseq, self.sseq, 0x11)); self.cseq += 1
        frames.append(frame(S, C, PORT, self.port, self.sseq, self.cseq, 0x11)); self.sseq += 1


def crc(b):
    c = 0
    for x in b:
        c ^= x
        for _ in range(8):
            c = (c >> 1) ^ 0xA6BC if c & 1 else c >> 1
    return ~c & 0xffff


def link(ctl, dst, src, user=b""):
    h = bytes([5, 0x64, 5 + len(user), ctl]) + struct.pack("<HH", dst, src)
    out = h + struct.pack("<H", crc(h))
    for i in range(0, len(user), 16):
        blk = user[i:i + 16]
        out += blk + struct.pack("<H", crc(blk))
    return out


MASTER, OUT = 3, 10
TO_OUT, TO_MASTER = 0xc4, 0x44      # DIR+PRM unconfirmed user data / PRM unconfirmed user data
CONF_TO_OUT = 0xc3                  # DIR+PRM confirmed user data


def seg(ctl, dst, src, app, seq, fir=True, fin=True):
    th = (seq & 0x3f) | (0x40 if fir else 0) | (0x80 if fin else 0)
    return link(ctl, dst, src, bytes([th]) + app)


def req(fc, objs=b"", seq=0, ctl=0xc0): return bytes([ctl | (seq & 0xf), fc]) + objs
def rsp(objs=b"", seq=0, iin=0, fc=0x81, ctl=0xc0): return bytes([ctl | (seq & 0xf), fc]) + struct.pack(">H", iin) + objs


def obj(g, v, q, rng=b"", data=b""): return bytes([g, v, q]) + rng + data


CLASS0, CLASS123 = obj(60, 1, 0x06), obj(60, 2, 0x06) + obj(60, 3, 0x06) + obj(60, 4, 0x06)


def main(path):
    ports = iter(range(50000, 51000))
    new = lambda: Conn(next(ports))
    ob = lambda seq, app, ctl=TO_OUT: seg(ctl, OUT, MASTER, app, seq)
    om = lambda seq, app: seg(TO_MASTER, MASTER, OUT, app, seq)

    # 1. Integrity poll and a response with binary and analog inputs.
    c = new()
    c.send("c", ob(0, req(1, CLASS0 + CLASS123, seq=1)))
    c.send("s", om(0, rsp(obj(1, 2, 0x00, b"\x00\x03", bytes([0x81, 0x01, 0x81, 0x01])) +
                          obj(30, 1, 0x00, b"\x00\x01", bytes([1, 0x10, 0x00, 0, 0, 2, 0x20, 0x00, 0, 0]))
                          + obj(20, 5, 0x00, b"\x00\x00", b"\x01\x00\x00\x00"), seq=1, iin=0x0200)))
    c.send("c", ob(1, req(0, seq=1)))   # confirm
    # 2. Event poll: class 1 with a count; response with timestamped events.
    c.send("c", ob(2, req(1, obj(60, 2, 0x06), seq=2)))
    c.send("s", om(1, rsp(obj(2, 2, 0x17, b"\x02", b"\x00\x81\x10\x20\x30\x40\x50\x00" + b"\x01\x01\x10\x20\x30\x40\x50\x00"), seq=2)))
    # 3. Controls: select, operate (CROB with index prefix), direct operate, analog output block.
    crob = bytes([0x03, 0x01, 0x64, 0, 0, 0, 0xe8, 0x03, 0, 0, 0])      # latch on, count 1, on/off time, status
    c.send("c", ob(3, req(3, obj(12, 1, 0x17, b"\x01", b"\x05" + crob), seq=3)))
    c.send("s", om(2, rsp(obj(12, 1, 0x17, b"\x01", b"\x05" + crob), seq=3, fc=0x81)))
    c.send("c", ob(4, req(4, obj(12, 1, 0x17, b"\x01", b"\x05" + crob), seq=4)))
    c.send("c", ob(5, req(5, obj(12, 1, 0x28, b"\x01\x00", b"\x0a\x00" + crob), seq=5)))
    c.send("c", ob(6, req(5, obj(41, 2, 0x17, b"\x01", b"\x02" + struct.pack("<hB", 1234, 0)), seq=6)))
    # 4. Administration: restarts, time, unsolicited, class assignment, delay measure.
    for i, fc in enumerate((13, 14, 15, 16, 17, 18, 19, 23, 24)):
        c.send("c", ob(7 + i, req(fc, seq=7 + i)))
    c.send("c", ob(20, req(20, obj(60, 2, 0x06) + obj(60, 3, 0x06) + obj(60, 4, 0x06), seq=1)))
    c.send("c", ob(21, req(21, obj(60, 2, 0x06), seq=2)))
    c.send("c", ob(22, req(22, obj(60, 2, 0x06) + obj(1, 0, 0x06), seq=3)))
    c.send("c", ob(23, req(2, obj(50, 1, 0x07, b"\x01", b"\x00\x10\x20\x30\x40\x50"), seq=4)))
    c.send("c", ob(24, req(2, obj(80, 1, 0x00, b"\x07\x07", b"\x00"), seq=5)))   # clear restart IIN
    c.send("s", om(3, rsp(obj(52, 2, 0x07, b"\x01", b"\x10\x00"), seq=4, fc=0x81)))
    c.close()

    # 5. Unsolicited response, with confirm request; link layer functions.
    c = new()
    c.send("s", om(0, rsp(obj(2, 1, 0x17, b"\x01", b"\x00\x81"), seq=0, fc=0x82, ctl=0xf0)))
    c.send("c", ob(0, req(0, seq=0, ctl=0xd0)))
    c.send("c", link(0xc0 | 0x00, OUT, MASTER))              # reset link
    c.send("s", link(0x00, MASTER, OUT))                     # ACK
    c.send("c", link(0xc9, OUT, MASTER))                     # request link status
    c.send("s", link(0x0b, MASTER, OUT))                     # link status
    c.send("c", link(0xc2, OUT, MASTER))                     # test link
    c.send("c", ob(0, req(1, CLASS0, seq=9), ctl=CONF_TO_OUT))
    c.send("s", link(0x00, MASTER, OUT))
    c.close()

    # 6. Multi-segment responses: three transport segments (150 bytes of app data), one TCP segment each,
    #    one TCP segment with all, and interleaved with a request on the other direction.
    big = rsp(obj(30, 2, 0x00, b"\x00\x4f", b"".join(bytes([1]) + struct.pack("<h", i) for i in range(80))), seq=5)
    parts = [big[i:i + 50] for i in range(0, len(big), 50)]
    c = new()
    c.send("c", ob(0, req(1, CLASS0, seq=5)))
    for i, p in enumerate(parts):
        c.send("s", seg(TO_MASTER, MASTER, OUT, p, 10 + i, fir=i == 0, fin=i == len(parts) - 1))
    c.send("c", ob(1, req(0, seq=5)))
    c.send("c", ob(2, req(1, CLASS0, seq=6)))
    c.send("s", b"".join(seg(TO_MASTER, MASTER, OUT, p, 20 + i, fir=i == 0, fin=i == len(parts) - 1) for i, p in enumerate(parts)))
    c.send("c", ob(3, req(1, CLASS0, seq=7)))
    for i, p in enumerate(parts):
        c.send("s", seg(TO_MASTER, MASTER, OUT, p, 30 + i, fir=i == 0, fin=i == len(parts) - 1))
        if i == 0:
            c.send("c", ob(4, req(0, seq=7)))
    c.close()

    # 7. Frames pipelined in one TCP segment; frames split across TCP segments in the header, in a data block.
    c = new()
    f1, f2 = ob(0, req(1, CLASS0, seq=1)), ob(1, req(13, seq=2))
    c.send("c", f1 + f2)
    c.send("c", f1[:3]); c.send("c", f1[3:11]); c.send("c", f1[11:])
    long_req = ob(2, req(2, obj(50, 1, 0x07, b"\x01", b"\x00\x10\x20\x30\x40\x50") + obj(80, 1, 0x00, b"\x07\x07", b"\x00"), seq=3))
    c.send("c", long_req[:17]); c.send("c", long_req[17:25]); c.send("c", long_req[25:])
    c.close()

    # 8. Retransmission, out-of-order segments, a lost segment at the end of the capture.
    c = new()
    a, b2, d = ob(0, req(1, CLASS0, seq=1)), ob(1, req(13, seq=2)), ob(2, req(14, seq=3))
    s0 = c.cseq
    c.send("c", a)
    c.raw("c", s0, a)                                  # retransmission
    c.raw("c", s0 + len(a) + len(b2), d)               # early
    c.raw("c", s0 + len(a), b2)                        # fills the gap
    c.close()

    # 9. Addresses: broadcast (0xffff), reserved, max, address 0.
    c = new()
    for dst, src in ((0xffff, 3), (0xfffd, 3), (0xfffc, 3), (0, 0), (0xfff0, 0xfff0), (65519, 1)):
        c.send("c", seg(TO_OUT, dst, src, req(1, CLASS0, seq=1), 0))
    c.close()

    # 10. Objects: every size class we know, as a response to a read (so data follows the headers).
    c = new()
    def resp(*objs): return rsp(b"".join(objs), seq=2)
    odd = [
        obj(1, 1, 0x00, b"\x00\x09", b"\xff\x01"),                  # packed 10 bits
        obj(2, 1, 0x00, b"\x00\x01", b"\x01\x81"),
        obj(2, 3, 0x00, b"\x00\x00", b"\x01\x10\x00"),
        obj(3, 2, 0x00, b"\x00\x00", b"\x41"),
        obj(4, 3, 0x17, b"\x01", b"\x02\x41\x01\x00"),
        obj(10, 2, 0x00, b"\x00\x01", b"\x01\x81"),
        obj(11, 1, 0x00, b"\x00\x00", b"\x01"),
        obj(20, 1, 0x00, b"\x00\x00", b"\x01\x02\x00\x00\x00"),
        obj(20, 6, 0x00, b"\x00\x01", b"\x01\x00\x02\x00"),
        obj(21, 1, 0x00, b"\x00\x00", b"\x01\x02\x00\x00\x00"),
        obj(21, 9, 0x00, b"\x00\x00", b"\x01\x00\x00\x00"),
        obj(22, 1, 0x17, b"\x01", b"\x05\x01\x02\x00\x00\x00"),
        obj(30, 1, 0x00, b"\x00\x00", b"\x01\x02\x00\x00\x00"),
        obj(30, 3, 0x00, b"\x00\x00", b"\x02\x00\x00\x00"),
        obj(30, 5, 0x00, b"\x00\x00", b"\x01\x00\x00\x80\x3f"),
        obj(30, 6, 0x00, b"\x00\x00", b"\x01" + struct.pack("<d", 1.5)),
        obj(32, 3, 0x17, b"\x01", b"\x03\x01\x02\x00\x00\x00\x01\x02\x03\x04\x05\x06"),
        obj(34, 1, 0x00, b"\x00\x00", b"\x10\x00"),
        obj(40, 1, 0x00, b"\x00\x00", b"\x01\x02\x00\x00\x00"),
        obj(50, 1, 0x07, b"\x01", b"\x00\x10\x20\x30\x40\x50"),
        obj(51, 1, 0x07, b"\x01", b"\x00\x10\x20\x30\x40\x50"),
        obj(110, 4, 0x07, b"\x01", b"abcd"),
        obj(80, 1, 0x00, b"\x00\x07", b"\x01"),
    ]
    for i, o in enumerate(odd):
        c.send("s", om(i, resp(o)))
    # an object we do not know the size of, then more objects behind it
    c.send("s", om(31, resp(obj(99, 1, 0x07, b"\x01", b"\xaa\xbb"), obj(1, 2, 0x00, b"\x00\x00", b"\x01"))))
    c.close()

    # 11. Qualifier forms: 2-byte and 4-byte ranges, 2-byte counts, no range in a request.
    c = new()
    c.send("c", ob(0, req(1, obj(1, 2, 0x01, b"\x00\x00\x0f\x00") + obj(30, 1, 0x02, struct.pack("<II", 0, 3)) +
                         obj(20, 1, 0x08, b"\x04\x00") + obj(1, 0, 0x06) + obj(30, 0, 0x07, b"\x05"), seq=3)))
    c.send("c", ob(1, req(1, obj(60, 1, 0x06) + obj(60, 2, 0x07, b"\x01"), seq=4)))
    c.close()

    # 12. Malformed: wrong CRCs, short length, truncated object list, bad transport sequence, noise in a good stream.
    c = new()
    good = ob(0, req(1, CLASS0, seq=1))
    bad_hdr = bytearray(good); bad_hdr[8] ^= 0xff
    c.send("c", bytes(bad_hdr))
    bad_blk = bytearray(ob(1, req(1, CLASS0 + CLASS123, seq=2))); bad_blk[-1] ^= 0xff
    c.send("c", bytes(bad_blk))
    c.send("c", ob(2, rsp(obj(30, 1, 0x00, b"\x00\x04", b"\x01\x02\x00\x00\x00"), seq=3)))   # 5 points, 1 present
    c.send("c", seg(TO_OUT, OUT, MASTER, req(1, CLASS0, seq=4), 5, fir=False, fin=True))     # a segment without a start
    c.send("c", ob(3, req(1, CLASS0, seq=5)))
    c.close()
    c = new()
    c.send("c", ob(0, req(1, CLASS0, seq=1)))
    c.send("c", bytes([5, 0x64, 4, 0xc4, 10, 0, 3, 0, 0, 0]))        # length 4: too small
    c.send("c", b"\x00\x01\x02 noise")
    c.send("c", ob(1, req(1, CLASS0, seq=6)))
    c.close()

    # 13. Not DNP3 on the port, and DNP3 on another port is not looked at by tshark's port heuristics but by ours.
    c = new()
    c.send("c", b"GET / HTTP/1.1\r\nHost: plc\r\n\r\n"); c.send("s", b"HTTP/1.1 200 OK\r\n\r\n"); c.close()

    # 14. UDP: a request, a response in two frames in one datagram, a bad one.
    udp = [(MASTER, 40001, 20000, ob(0, req(1, CLASS0, seq=1))),
           (OUT, 20000, 40001, om(0, rsp(obj(1, 2, 0x00, b"\x00\x00", b"\x81"), seq=1))),
           (MASTER, 40001, 20000, ob(1, req(13, seq=2)) + ob(2, req(14, seq=3)))]
    for who, sp, dp, p in udp:
        src, dst = (C, S) if who == MASTER else (S, C)
        frames.append(udp_frame(src, dst, sp, dp, p))

    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for ts, fr in frames:
            f.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(fr), len(fr)) + fr)


if __name__ == "__main__":
    main(sys.argv[1])
