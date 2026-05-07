package collector

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// ClientHelloFingerprints parses a TLS ClientHello record (starting at the TLS
// record layer) and returns JA3 (MD5 hex) and a compact JA4-style string.
func ClientHelloFingerprints(record []byte) (ja3 string, ja4 string) {
	ch := extractClientHello(record)
	if len(ch) < 42 {
		return "", ""
	}
	// After handshake header: version(2) random(32) session(1+len) ...
	off := 0
	if len(ch) < off+34 {
		return "", ""
	}
	vers := binary.BigEndian.Uint16(ch[off : off+2])
	off += 2 + 32
	if off >= len(ch) {
		return "", ""
	}
	sessLen := int(ch[off])
	off++
	if off+sessLen > len(ch) {
		return "", ""
	}
	off += sessLen
	if off+2 > len(ch) {
		return "", ""
	}
	cipherLen := int(binary.BigEndian.Uint16(ch[off : off+2]))
	off += 2
	if cipherLen%2 != 0 || off+cipherLen > len(ch) {
		return "", ""
	}
	ciphers := make([]uint16, 0, cipherLen/2)
	for i := 0; i < cipherLen; i += 2 {
		ciphers = append(ciphers, binary.BigEndian.Uint16(ch[off+i:off+i+2]))
	}
	off += cipherLen
	if off >= len(ch) {
		return "", ""
	}
	compLen := int(ch[off])
	off++
	if off+compLen > len(ch) {
		return "", ""
	}
	off += compLen
	if off+2 > len(ch) {
		return "", ""
	}
	extLen := int(binary.BigEndian.Uint16(ch[off : off+2]))
	off += 2
	extEnd := off + extLen
	if extEnd > len(ch) {
		return "", ""
	}
	var extTypes []uint16
	var sni string
	var alpn string
	for off < extEnd {
		if off+4 > len(ch) {
			break
		}
		typ := binary.BigEndian.Uint16(ch[off : off+2])
		elen := int(binary.BigEndian.Uint16(ch[off+2 : off+4]))
		off += 4
		if off+elen > len(ch) {
			break
		}
		edata := ch[off : off+elen]
		off += elen
		extTypes = append(extTypes, typ)
		switch typ {
		case 0x0000: // server_name
			if len(edata) < 2 {
				continue
			}
			listLen := int(binary.BigEndian.Uint16(edata[0:2]))
			if 2+listLen > len(edata) {
				continue
			}
			p := 2
			for p < 2+listLen && p < len(edata) {
				if p+3 > len(edata) {
					break
				}
				nl := int(binary.BigEndian.Uint16(edata[p+1 : p+3]))
				p += 3
				if p+nl > len(edata) {
					break
				}
				sni = string(edata[p : p+nl])
				break
			}
		case 0x0010: // ALPN
			if len(edata) < 2 {
				continue
			}
			alpnList := int(binary.BigEndian.Uint16(edata[0:2]))
			q := 2
			for q < 2+alpnList && q < len(edata) {
				l := int(edata[q])
				q++
				if q+l > len(edata) {
					break
				}
				if alpn == "" {
					alpn = string(edata[q : q+l])
				}
				q += l
			}
		}
	}

	ja3 = buildJA3(vers, ciphers, extTypes)
	ja4 = buildJA4(vers, ciphers, extTypes, sni, alpn)
	return ja3, ja4
}

func extractClientHello(record []byte) []byte {
	if len(record) < 5 {
		return nil
	}
	if record[0] != 0x16 { // handshake
		return nil
	}
	recLen := int(binary.BigEndian.Uint16(record[3:5]))
	if 5+recLen > len(record) {
		return nil
	}
	body := record[5 : 5+recLen]
	if len(body) < 4 || body[0] != 0x01 { // client_hello
		return nil
	}
	hslen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	if 4+hslen > len(body) {
		return nil
	}
	return body[4 : 4+hslen]
}

func buildJA3(tlsVers uint16, ciphers []uint16, exts []uint16) string {
	var ciphStr []string
	for _, c := range ciphers {
		if isGREASE16(c) {
			continue
		}
		ciphStr = append(ciphStr, strconv.Itoa(int(c)))
	}
	var extStr []string
	for _, e := range exts {
		if isGREASE16(e) {
			continue
		}
		extStr = append(extStr, strconv.Itoa(int(e)))
	}
	// JA3: TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
	// Minimal parsers often leave the last two fields empty.
	s := fmt.Sprintf("%d,%s,%s,,",
		tlsVers,
		strings.Join(ciphStr, "-"),
		strings.Join(extStr, "-"),
	)
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func buildJA4(tlsVers uint16, ciphers []uint16, exts []uint16, sni, alpn string) string {
	cn := 0
	for _, c := range ciphers {
		if !isGREASE16(c) {
			cn++
		}
	}
	en := 0
	for _, e := range exts {
		if !isGREASE16(e) {
			en++
		}
	}
	sniL := "i"
	if sni != "" {
		sniL = "d"
	}
	alpnL := "_"
	if alpn != "" {
		alpnL = strings.Split(alpn, ",")[0]
		if len(alpnL) > 8 {
			alpnL = alpnL[:8]
		}
	}
	return fmt.Sprintf("t%04x_%02d_%02d_%s_%s", int(tlsVers), cn, en, sniL, alpnL)
}

func isGREASE16(v uint16) bool {
	b := byte(v >> 8)
	return b == byte(v) && (b == 0x0a || b == 0x1a || b == 0x2a || b == 0x3a || b == 0x4a || b == 0x5a || b == 0x6a || b == 0x7a || b == 0x8a || b == 0x9a || b == 0xaa || b == 0xba || b == 0xca || b == 0xda || b == 0xea || b == 0xfa)
}

// DecodeTLSClientHelloPayload decodes hex or standard base64 payloads commonly used in JSON.
func DecodeTLSClientHelloPayload(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty")
	}
	if b, err := hex.DecodeString(s); err == nil && len(b) > 0 {
		return b, nil
	}
	return base64.StdEncoding.DecodeString(s)
}
