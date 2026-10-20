package obfs

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"
)

// testClientHelloRecord builds a minimal but well-formed TLS ClientHello
// record with the given SNI. When trailing is true, a supported_versions
// extension is appended after server_name to exercise length splicing.
// (Ported from sora's obfs_test.go.)
func testClientHelloRecord(t *testing.T, sni string, trailing bool) []byte {
	t.Helper()
	name := []byte(sni)
	snEntry := []byte{0, byte(len(name) >> 8), byte(len(name))}
	snEntry = append(snEntry, name...)
	snListLen := len(snEntry)
	snData := []byte{byte(snListLen >> 8), byte(snListLen)}
	snData = append(snData, snEntry...)
	snExt := []byte{0, 0, byte(len(snData) >> 8), byte(len(snData))}
	snExt = append(snExt, snData...)

	exts := snExt
	if trailing {
		// supported_versions with TLS 1.3 + 1.2.
		exts = append(exts, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04)
	}

	body := []byte{0x03, 0x03}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	body = append(body, random...)
	body = append(body, 0x00)                   // session id length
	body = append(body, 0x00, 0x02, 0x13, 0x01) // cipher suites
	body = append(body, 0x01, 0x00)             // compression
	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)

	hs := []byte{handshakeClientHello, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := []byte{recordTypeHandshake, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	rec = append(rec, hs...)
	return rec
}

// testClientHelloRecordNoSNI builds a ClientHello record without a
// server_name extension.
func testClientHelloRecordNoSNI(t *testing.T) []byte {
	t.Helper()
	exts := []byte{0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04}
	body := []byte{0x03, 0x03}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	body = append(body, random...)
	body = append(body, 0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00)
	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)
	hs := []byte{handshakeClientHello, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := []byte{recordTypeHandshake, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	return append(rec, hs...)
}

// testRecordSNI extracts the SNI hostname from a ClientHello record.
func testRecordSNI(t *testing.T, record []byte) string {
	t.Helper()
	body := record[recordHeaderLen+4:]
	_, extOff, extLen, err := findServerNameExt(body)
	if err != nil {
		t.Fatalf("findServerNameExt: %v", err)
	}
	data := body[extOff+4 : extOff+4+extLen]
	listLen := int(binary.BigEndian.Uint16(data))
	if 2+listLen != len(data) {
		t.Fatalf("server_name list length mismatch")
	}
	nameLen := int(binary.BigEndian.Uint16(data[3:5]))
	name := data[5 : 5+nameLen]
	if !bytes.Equal(data[2:3], []byte{0}) {
		t.Fatalf("unexpected name type")
	}
	return string(name)
}
