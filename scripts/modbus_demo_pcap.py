#!/usr/bin/env python3
"""Write a tiny Modbus pcap with known events, to self-test compare_modbus.py.

  scripts/modbus_demo_pcap.py demo.pcap && scripts/compare_modbus.py demo.pcap

Connection 50000: exception codes 0x42 (both tools flag it) and 0x08 on FC3
(only Suricata flags it), then 0x02 (neither). Connection 50001: unassigned
function 0x09 (only we flag it). Expected result: one event difference on
10.20.0.10:50000, exit code 1.
"""
import struct, sys
C, S = bytes([10,20,0,10]), bytes([10,20,0,20])
frames=[]; t=[1767225600.0]
def csum(b):
    if len(b)%2: b+=b'\0'
    s=sum(struct.unpack('!%dH'%(len(b)//2),b)); s=(s>>16)+(s&0xffff); s+=s>>16; return ~s&0xffff
def pkt(src,dst,sp,dp,seq,ack,flags,payload=b''):
    tcp=struct.pack('!HHIIBBHHH',sp,dp,seq,ack,5<<4,flags,65535,0,0)
    ph=src+dst+struct.pack('!BBH',0,6,len(tcp)+len(payload))
    tcp=tcp[:16]+struct.pack('!H',csum(ph+tcp+payload))+tcp[18:]
    ip=struct.pack('!BBHHHBBH',0x45,0,20+len(tcp)+len(payload),1,0,64,6,0)+src+dst
    ip=ip[:10]+struct.pack('!H',csum(ip))+ip[12:]
    eth=bytes.fromhex('020000000002' if dst==S else '020000000001')+bytes.fromhex('020000000001' if dst==S else '020000000002')+b'\x08\x00'
    t[0]+=0.005; frames.append((t[0],eth+ip+tcp+payload))
def adu(txn,unit,fc,data,length=None):
    return struct.pack('!HHHBB',txn,0,length if length is not None else 2+len(data),unit,fc)+data
def conn(sport,exchanges):
    cs,ss=1000,5000
    pkt(C,S,sport,502,cs,0,0x02); pkt(S,C,502,sport,ss,cs+1,0x12); pkt(C,S,sport,502,cs+1,ss+1,0x10)
    cs+=1; ss+=1
    for rq,rs in exchanges:
        pkt(C,S,sport,502,cs,ss,0x18,rq); cs+=len(rq)
        if rs: pkt(S,C,502,sport,ss,cs,0x18,rs); ss+=len(rs)
    pkt(C,S,sport,502,cs,ss,0x11); pkt(S,C,502,sport,ss,cs+1,0x11)
rd=lambda n: adu(n,1,3,struct.pack('!HH',0,4)); ok=lambda n: adu(n,1,3,bytes([8])+bytes(8))
warm=[(rd(1),ok(1)),(rd(2),ok(2))]
conn(50000, warm+[(rd(3),adu(3,1,0x83,b'\x42')),(rd(4),adu(4,1,0x83,b'\x08')),(rd(5),adu(5,1,0x83,b'\x02'))])
conn(50001, warm+[(adu(3,1,0x09,b'\0\1'),adu(3,1,0x89,b'\x01'))])
with open(sys.argv[1],'wb') as f:
    f.write(struct.pack('<IHHiIII',0xa1b2c3d4,2,4,0,0,65535,1))
    for ts,fr in frames: f.write(struct.pack('<IIII',int(ts),int((ts%1)*1e6),len(fr),len(fr))+fr)
