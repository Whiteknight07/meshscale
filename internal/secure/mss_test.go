package secure

import (
	"encoding/binary"
	"testing"
)

func tcpSYN() []byte {
	packet := make([]byte, 64)
	packet[0] = 0x60
	packet[6] = 6
	packet[52] = 6 << 4
	packet[53] = 2
	copy(packet[60:], []byte{2, 4, 4, 196})
	binary.BigEndian.PutUint16(packet[56:58], 0x1234)
	return packet
}
func checksumSum(data []byte) uint32 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return sum
}
func TestClampTCPMSS(t *testing.T) {
	packet := tcpSYN()
	before := checksumSum(packet[40:])
	clampTCPMSS(packet, 1172)
	if binary.BigEndian.Uint16(packet[62:64]) != 1172 || checksumSum(packet[40:]) != before {
		t.Fatal("incorrect MSS/checksum update")
	}
	checksum := binary.BigEndian.Uint16(packet[56:58])
	clampTCPMSS(packet, 1172)
	if binary.BigEndian.Uint16(packet[56:58]) != checksum {
		t.Fatal("non-idempotent checksum")
	}
	for n := 0; n < 64; n++ {
		clampTCPMSS(packet[:n], 1000)
	}
	packet = tcpSYN()
	packet[53] = 16
	clampTCPMSS(packet, 1172)
	if binary.BigEndian.Uint16(packet[62:64]) != 1220 {
		t.Fatal("modified non-SYN")
	}
}
func BenchmarkClampTCPMSSData(b *testing.B) {
	packet := tcpSYN()
	packet[53] = 16
	b.ReportAllocs()
	for b.Loop() {
		clampTCPMSS(packet, 1172)
	}
}

func TestClampTCPMSSOddOption(t *testing.T) {
	packet := make([]byte, 68)
	copy(packet, tcpSYN()[:60])
	packet[52] = 7 << 4
	copy(packet[60:], []byte{1, 2, 4, 4, 196, 0, 0, 0})
	before := checksumSum(packet[40:])
	clampTCPMSS(packet, 1172)
	if binary.BigEndian.Uint16(packet[63:65]) != 1172 || checksumSum(packet[40:]) != before {
		t.Fatal("unaligned MSS checksum update")
	}
}
