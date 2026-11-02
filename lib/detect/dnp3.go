package detect

// DNP3 (IEEE 1815) runs over TCP and UDP, port 20000 by default. Every link
// frame starts with 0x05 0x64, a length byte (counting control, destination,
// source and user data, so at least 5) and a control byte; the header and every
// 16-byte block of user data are followed by a CRC.
const (
	// DNP3Port is the registered port.
	DNP3Port uint16 = 20000

	dnp3Start0    byte = 0x05
	dnp3Start1    byte = 0x64
	dnp3HeaderLen      = 10 // start, length, control, destination, source, CRC
	dnp3MinLen         = 5
	dnp3BlockSize      = 16
	dnp3MaxFrame       = dnp3HeaderLen + 250 + 2*16 // largest user data is 250 bytes
)

// ProbeDNP3 checks a payload for the start of a DNP3 link frame: the start
// bytes and a length field that can hold the link header, as Suricata does. The
// CRC is not part of the probe: a corrupted header on a DNP3 connection should
// raise an event, not hide the connection.
func ProbeDNP3(b []byte) Result {
	if len(b) == 0 {
		return Incomplete
	}
	if b[0] != dnp3Start0 {
		return Unrecognized
	}
	if len(b) < 2 {
		return Incomplete
	}
	if b[1] != dnp3Start1 {
		return Unrecognized
	}
	if len(b) < 3 {
		return Incomplete
	}
	if b[2] < dnp3MinLen {
		return Unrecognized
	}
	if len(b) < dnp3HeaderLen {
		return Incomplete
	}
	return Recognized
}

var dnp3CRCTable = func() (t [256]uint16) {
	for i := range t {
		c := uint16(i)
		for j := 0; j < 8; j++ {
			if c&1 != 0 {
				c = c>>1 ^ 0xa6bc
			} else {
				c >>= 1
			}
		}
		t[i] = c
	}
	return
}()

// dnp3CRC is the DNP3 CRC-16 (polynomial 0x3D65, reflected, complemented).
func dnp3CRC(b []byte) uint16 {
	var c uint16
	for _, x := range b {
		c = c>>8 ^ dnp3CRCTable[byte(c)^x]
	}
	return ^c
}
