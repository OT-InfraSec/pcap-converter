#!/usr/bin/env python3
"""Write a classic pcap with a mix of S7comm traffic, to test the S7 decoder
against tshark:

  scripts/s7_demo_pcap.py demo.pcap && scripts/compare_s7.py demo.pcap

Every connection is its own TCP session from a different client port to port
102. Frames are built by hand, so tshark is an independent check of both the
frames and our decoder.
"""
import struct, sys

C, S = bytes([10, 20, 0, 10]), bytes([10, 20, 0, 20])
frames, now = [], [1767225600.0]


def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b)); s = (s >> 16) + (s & 0xffff); s += s >> 16
    return ~s & 0xffff


def frame(src, dst, sp, dp, seq, ack, flags, payload=b""):
    tcp = struct.pack("!HHIIBBHHH", sp, dp, seq & 0xffffffff, ack & 0xffffffff, 5 << 4, flags, 65535, 0, 0)
    ph = src + dst + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
    tcp = tcp[:16] + struct.pack("!H", csum(ph + tcp + payload)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(tcp) + len(payload), 1, 0, 64, 6, 0) + src + dst
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    a, b = bytes.fromhex("020000000001"), bytes.fromhex("020000000002")
    eth = (b + a if dst == S else a + b) + b"\x08\x00"
    now[0] += 0.005
    return (now[0], eth + ip + tcp + payload)


class Conn:
    """One TCP session. send() puts one segment on the wire and advances the
    sequence number; raw() sends at an explicit sequence number."""
    def __init__(self, port, cseq=1000, sseq=5000, handshake=True):
        self.port, self.cseq, self.sseq = port, cseq, sseq
        if handshake:
            frames.append(frame(C, S, port, 102, cseq, 0, 0x02))
            frames.append(frame(S, C, 102, port, sseq, cseq + 1, 0x12))
            frames.append(frame(C, S, port, 102, cseq + 1, sseq + 1, 0x10))
            self.cseq += 1; self.sseq += 1

    def send(self, who, payload, flags=0x18):
        if who == "c":
            frames.append(frame(C, S, self.port, 102, self.cseq, self.sseq, flags, payload)); self.cseq += len(payload)
        else:
            frames.append(frame(S, C, 102, self.port, self.sseq, self.cseq, flags, payload)); self.sseq += len(payload)

    def raw(self, who, seq, payload):
        if who == "c":
            frames.append(frame(C, S, self.port, 102, seq, self.sseq, 0x18, payload))
        else:
            frames.append(frame(S, C, 102, self.port, seq, self.cseq, 0x18, payload))

    def close(self):
        frames.append(frame(C, S, self.port, 102, self.cseq, self.sseq, 0x11)); self.cseq += 1
        frames.append(frame(S, C, 102, self.port, self.sseq, self.cseq, 0x11)); self.sseq += 1


def tpkt(b): return struct.pack("!BBH", 3, 0, 4 + len(b)) + b
def dt(s7, eot=True): return tpkt(bytes([2, 0xf0, 0x80 if eot else 0x00]) + s7)


def s7(rosctr, ref, param, data=b"", err=(0, 0)):
    h = struct.pack("!BBHHHH", 0x32, rosctr, 0, ref, len(param), len(data))
    if rosctr in (2, 3):
        h += bytes(err)
    return h + param + data


def item(area, db, byte, length, size=2, bit=0):
    return bytes([0x12, 0x0a, 0x10, size]) + struct.pack("!HH", length, db) + bytes([area]) + (byte * 8 + bit).to_bytes(3, "big")


def cr(cc, dst, src):
    typ = 0xd0 if cc else 0xe0
    params = bytes([0xc0, 1, 0x0a, 0xc1, len(src)]) + src + bytes([0xc2, len(dst)]) + dst
    return tpkt(bytes([6 + len(params), typ, 0, 1 if cc else 0, 0, 1, 0]) + params)


def pad(s, n): return s.encode().ljust(n, b"\0")
def ud(typ, group, sub, seq, data, long=False):
    p = bytes([0, 1, 0x12, 8 if long else 4, 0x12 if typ == 8 else 0x11, typ << 4 | group, sub, seq])
    if long:
        p += bytes([0, 0, 0, 0])
    return p, data


SETUP = bytes([0xf0, 0, 0, 1, 0, 1, 0x01, 0xe0])


def handshake_s7(c, ref=1, dst=b"\x01\x02"):
    c.send("c", cr(False, dst, b"\x01\x00")); c.send("s", cr(True, dst, b"\x01\x00"))
    c.send("c", dt(s7(1, ref, SETUP))); c.send("s", dt(s7(3, ref, SETUP)))


def main(path):
    port = [50000]

    def new(**kw):
        port[0] += 1
        return Conn(port[0], **kw)

    # 1. Reads and writes, rack 0 slot 2, 480-byte PDUs.
    c = new(); handshake_s7(c)
    c.send("c", dt(s7(1, 2, bytes([4, 1]) + item(0x84, 1, 0, 2))))
    c.send("s", dt(s7(3, 2, bytes([4, 1]), bytes([0xff, 4, 0, 16, 0x12, 0x34]))))
    c.send("c", dt(s7(1, 3, bytes([4, 3]) + item(0x84, 5, 10, 4) + item(0x83, 0, 4, 1, 1, 2) + item(0x81, 0, 0, 8))))
    c.send("s", dt(s7(3, 3, bytes([4, 3]), bytes([0xff, 4, 0, 32, 1, 2, 3, 4, 0xff, 3, 0, 1, 1, 0, 0xff, 4, 0, 64, 1, 2, 3, 4, 5, 6, 7, 8]))))
    c.send("c", dt(s7(1, 4, bytes([5, 1]) + item(0x82, 0, 4, 1, 1, 2), bytes([0, 3, 0, 1, 1]))))
    c.send("s", dt(s7(3, 4, bytes([5, 1]), bytes([0xff]))))
    c.send("c", dt(s7(1, 5, bytes([4, 1]) + item(0x84, 99, 0, 2))))                                  # DB does not exist
    c.send("s", dt(s7(3, 5, bytes([4, 1]), bytes([0x0a, 0, 0, 0]))))
    c.send("c", dt(s7(1, 6, bytes([5, 1]) + item(0x84, 1, 0, 2), bytes([0, 4, 0, 16, 0xab, 0xcd]))))  # write a word
    c.send("s", dt(s7(3, 6, bytes([5, 1]), bytes([0x03]))))                                            # access denied
    c.send("c", dt(s7(1, 7, bytes([4, 1]) + item(0x1c, 0, 3, 1, 0x1c))))                               # counter
    c.send("s", dt(s7(2, 7, b"", b"", (0x81, 0x04))))                                                  # Ack with an error
    c.close()

    # 2. Identity: SZL 0x1C and 0x11 replies.
    c = new(); handshake_s7(c, dst=b"\x03\x23")
    for sid in (0x1c, 0x11):
        c.send("c", dt(s7(7, 10, *ud(4, 4, 1, 0, bytes([0xff, 9, 0, 4]) + struct.pack("!HH", sid, 0)))))
    recs = b"".join(struct.pack("!H", i) + pad(t, 32) for i, t in ((1, "S7-1200 station_1"), (2, "CPU 1214C DC/DC/DC"), (3, "Plant A"),
                                                             (4, "Original Siemens Equipment"), (5, "S C-ABC123456"), (7, "CPU 1214C"), (8, "")))
    body = struct.pack("!HHHH", 0x1c, 0, 34, 7) + recs
    c.send("c", dt(s7(7, 10, *ud(4, 4, 1, 0, bytes([0xff, 9]) + struct.pack("!H", 4) + struct.pack("!HH", 0x1c, 0)))))
    c.send("s", dt(s7(7, 10, *ud(8, 4, 1, 0, bytes([0xff, 9]) + struct.pack("!H", len(body)) + body, long=True))))
    recs = b"".join(struct.pack("!H", i) + pad(m, 20) + struct.pack("!HHH", t, 2, v) for i, m, t, v in
                    ((1, "6ES7 214-1AG40-0XB0", 0x0101, 0x0301), (6, "6ES7 214-1AG40-0XB0", 0x0102, 0x0302), (7, "6ES7 214-1AG40-0XB0", 0x0103, 0x0402)))
    body = struct.pack("!HHHH", 0x11, 0, 28, 3) + recs
    c.send("c", dt(s7(7, 11, *ud(4, 4, 1, 1, bytes([0xff, 9]) + struct.pack("!H", 4) + struct.pack("!HH", 0x11, 0)))))
    c.send("s", dt(s7(7, 11, *ud(8, 4, 1, 1, bytes([0xff, 9]) + struct.pack("!H", len(body)) + body, long=True))))
    c.close()

    # 3. PLC control and other userdata.
    c = new(); handshake_s7(c)
    c.send("c", dt(s7(1, 20, bytes([0x29, 0, 0, 0, 0, 0, 9]) + b"P_PROGRAM")))
    c.send("s", dt(s7(3, 20, bytes([0x29, 0]))))
    c.send("c", dt(s7(1, 21, bytes([0x28, 0, 0, 0, 0, 0, 0, 0xfd, 0, 0, 9]) + b"P_PROGRAM")))
    c.send("s", dt(s7(3, 21, bytes([0x28, 0]))))
    c.send("c", dt(s7(7, 22, *ud(4, 3, 1, 0, bytes([0x0a, 0, 0, 0])))))                      # list blocks
    c.send("c", dt(s7(7, 23, *ud(4, 7, 1, 0, bytes([0x0a, 0, 0, 0])))))                      # read clock
    c.send("c", dt(s7(7, 24, *ud(4, 1, 1, 0, bytes([0x0a, 0, 0, 0])))))                      # programmer commands
    c.send("c", dt(s7(1, 25, bytes([0x1a, 0, 0, 0, 0, 0, 0, 0, 9]) + b"_0A00001P")))        # request download
    c.send("c", dt(s7(1, 26, bytes([0x1d, 0, 0, 0, 0, 0, 0, 0, 9]) + b"_0A00001P")))        # start upload
    c.close()

    # 4. Stream shape: pipelined, split, long, COTP fragments, retransmission, out of order.
    c = new(); handshake_s7(c)
    rd = lambda ref: dt(s7(1, ref, bytes([4, 1]) + item(0x84, 1, 0, 2)))
    c.send("c", rd(30) + rd(31) + rd(32))                                    # pipelined
    f = rd(33); c.send("c", f[:5]); c.send("c", f[5:])                       # split in the headers
    f = rd(34); c.send("c", f[:20]); c.send("c", f[20:])                     # split in the S7 PDU
    big = bytes(range(240)) * 2
    resp = dt(s7(3, 35, bytes([4, 1]), bytes([0xff, 4]) + struct.pack("!H", len(big) * 8) + big))
    for i in range(0, len(resp), 100):
        c.send("s", resp[i:i + 100])                                         # long reply in 5 segments
    f = rd(36)
    c.send("c", f); c.raw("c", c.cseq - len(f), f)                           # retransmission
    f1, f2 = rd(37), rd(38)
    seq = c.cseq
    c.raw("c", seq + len(f1), f2); c.raw("c", seq, f1); c.cseq += len(f1) + len(f2)   # swapped
    pdu = s7(1, 39, bytes([4, 1]) + item(0x84, 1, 0, 2))
    c.send("c", dt(pdu[:9], eot=False)); c.send("c", dt(pdu[9:]))           # COTP segmentation
    c.send("c", b"".join(rd(40 + i) for i in range(5)))                      # 5 in one segment
    c.close()

    # 5. Connection requests with different TSAPs and TPDU size; a bare close.
    for dst in (b"\x01\x00", b"\x01\x02", b"\x03\x22", b"\x03\x43"):
        c = new(); c.send("c", cr(False, dst, b"\x01\x00")); c.send("s", cr(True, dst, b"\x01\x00"))
        c.send("c", dt(s7(1, 1, SETUP))); c.send("s", dt(s7(3, 1, SETUP)))
        c.close()

    # 6. Not S7 on port 102 (MMS-like data), and a malformed S7 PDU in a good connection.
    c = new()
    c.send("c", cr(False, b"\x00\x01", b"\x00\x01")); c.send("s", cr(True, b"\x00\x01", b"\x00\x01"))
    c.send("c", dt(bytes([0x0d, 0x0a, 0x05, 0x06, 0x13, 0x01, 0x00, 0x16, 0x01, 0x02]))); c.close()
    c = new(); handshake_s7(c)
    c.send("c", dt(bytes([0x32, 1, 0, 0, 0, 77, 0, 50, 0, 0])))             # parameter length 50, no parameter
    c.send("c", dt(s7(1, 78, bytes([4, 2]) + item(0x84, 1, 0, 2))))          # two items counted, one present
    c.send("c", dt(s7(1, 79, SETUP)))                                       # the stream goes on
    c.close()

    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for ts, fr in frames:
            f.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(fr), len(fr)) + fr)


if __name__ == "__main__":
    main(sys.argv[1])
