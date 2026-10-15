// Package quicinitial extracts the SNI (server name) and ALPN from a QUIC v1
// or v2 Initial packet.
package quicinitial

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
)

// QUIC version numbers.
const (
	VersionV1 uint32 = 0x00000001 // RFC 9000
	VersionV2 uint32 = 0x6b3343cf // RFC 9369
)

// quicV1InitialSalt is the fixed salt for QUIC v1 initial-secret derivation
// (RFC 9001 §5.2).
var quicV1InitialSalt = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
}

// quicV2InitialSalt is the fixed salt for QUIC v2 initial-secret derivation
// (RFC 9369 §3.3.1).
var quicV2InitialSalt = []byte{
	0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
	0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
}

// hkdfExtract = HMAC-SHA256(salt, ikm) (RFC 5869).
func hkdfExtract(salt, ikm []byte) []byte {
	h := hmac.New(sha256.New, salt)
	h.Write(ikm)
	return h.Sum(nil)
}

// hkdfExpand derives length bytes from prk+info (RFC 5869).
func hkdfExpand(prk, info []byte, length int) []byte {
	out := make([]byte, 0, length)
	var t []byte
	for i := byte(1); len(out) < length; i++ {
		h := hmac.New(sha256.New, prk)
		h.Write(t)
		h.Write(info)
		h.Write([]byte{i})
		t = h.Sum(nil)
		out = append(out, t...)
	}
	return out[:length]
}

// hkdfExpandLabel implements the TLS 1.3 / QUIC labeled HKDF-Expand
// (RFC 8446 §7.1): the info is a structured HkdfLabel with the "tls13 " prefix.
func hkdfExpandLabel(secret []byte, label string, length int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 2+1+len(full)+1)
	info = append(info, byte((length>>8)&0xff), byte(length&0xff))
	info = append(info, byte(len(full)&0xff))
	info = append(info, full...)
	info = append(info, 0) // empty context
	return hkdfExpand(secret, info, length)
}

// InitialKeys holds the client-side Initial protection keys.
type InitialKeys struct {
	Key []byte
	IV  []byte
	HP  []byte
}

// DeriveClientInitialKeys derives the client Initial keys from the Destination
// Connection ID (RFC 9001 §5.2).
func DeriveClientInitialKeys(dcid []byte) InitialKeys {
	return deriveClientInitialKeys(dcid, VersionV1)
}

// deriveClientInitialKeys derives the client Initial keys for a QUIC version;
// v2 uses its own salt and HKDF labels (RFC 9369 §3.3).
func deriveClientInitialKeys(dcid []byte, version uint32) InitialKeys {
	salt := quicV1InitialSalt
	keyLabel, ivLabel, hpLabel := "quic key", "quic iv", "quic hp"
	if version == VersionV2 {
		salt = quicV2InitialSalt
		keyLabel, ivLabel, hpLabel = "quicv2 key", "quicv2 iv", "quicv2 hp"
	}
	initialSecret := hkdfExtract(salt, dcid)
	clientSecret := hkdfExpandLabel(initialSecret, "client in", 32)
	return InitialKeys{
		Key: hkdfExpandLabel(clientSecret, keyLabel, 16),
		IV:  hkdfExpandLabel(clientSecret, ivLabel, 12),
		HP:  hkdfExpandLabel(clientSecret, hpLabel, 16),
	}
}

// readVarint reads a QUIC variable-length integer (RFC 9000 §16) at off,
// returning the value and the number of bytes consumed.
func readVarint(b []byte, off int) (uint64, int, bool) {
	if off >= len(b) {
		return 0, 0, false
	}
	prefix := b[off] >> 6
	n := 1 << prefix
	if off+n > len(b) {
		return 0, 0, false
	}
	v := uint64(b[off] & 0x3f)
	for i := 1; i < n; i++ {
		v = (v << 8) | uint64(b[off+i])
	}
	return v, n, true
}

func asLen(v uint64) (int, bool) {
	if v > 1<<20 {
		return 0, false
	}
	return int(v), true
}

// Info is what a decodable client Initial packet reveals.
type Info struct {
	SNI     string
	ALPN    []string
	Version uint32
}

// ExtractSNI parses a QUIC v1/v2 long-header Initial packet and returns the
// SNI (server_name) from the client's ClientHello, or ("", false) if the
// packet is not a decodable client Initial or carries no SNI.
func ExtractSNI(b []byte) (string, bool) {
	info, err := extract(b)
	if err != nil || info.SNI == "" {
		return "", false
	}
	return info.SNI, true
}

func ExtractSNIErr(b []byte) (string, error) {
	info, err := extract(b)
	if err != nil {
		return "", err
	}
	if info.SNI == "" {
		return "", fmt.Errorf("no SNI in ClientHello")
	}
	return info.SNI, nil
}

// Extract parses a QUIC v1/v2 long-header Initial packet and returns the
// ClientHello's SNI and ALPN list.
func Extract(b []byte) (Info, error) { return extract(b) }

// ExtractPackets decrypts several Initial packets of one flow and parses the
// ClientHello from their combined CRYPTO frames.
func ExtractPackets(pkts [][]byte) (Info, error) {
	var version uint32
	var plains [][]byte
	var lastErr error
	var connection []byte
	for _, b := range pkts {
		dcid, ok := initialDCID(b)
		if ok && connection != nil && !bytes.Equal(dcid, connection) {
			continue
		}
		plain, v, err := decryptInitial(b)
		if err != nil {
			lastErr = err
			continue
		}
		if connection == nil {
			connection = dcid
		}
		version = v
		plains = append(plains, plain)
	}
	if len(plains) == 0 {
		if lastErr == nil {
			lastErr = fmt.Errorf("no packets")
		}
		return Info{}, lastErr
	}
	hs := reassembleCrypto(plains...)
	if hs == nil {
		return Info{}, fmt.Errorf("no contiguous CRYPTO data")
	}
	info := Info{Version: version}
	var ok bool
	info.SNI, info.ALPN, ok = parseClientHello(hs)
	if !ok {
		return Info{}, fmt.Errorf("not a parseable ClientHello (hslen %d)", len(hs))
	}
	if info.SNI == "" {
		return info, fmt.Errorf("no SNI (ClientHello may continue in a later packet)")
	}
	return info, nil
}

func extract(b []byte) (Info, error) {
	plain, version, err := decryptInitial(b)
	if err != nil {
		return Info{}, err
	}
	hs := reassembleCrypto(plain)
	if hs == nil {
		return Info{}, fmt.Errorf("no contiguous CRYPTO data")
	}
	info := Info{Version: version}
	var ok bool
	info.SNI, info.ALPN, ok = parseClientHello(hs)
	if !ok {
		return Info{}, fmt.Errorf("not a parseable ClientHello (hslen %d)", len(hs))
	}
	return info, nil
}

// initialDCID returns a long-header packet's Destination Connection ID.
func initialDCID(b []byte) ([]byte, bool) {
	if len(b) < 6 {
		return nil, false
	}
	dcidLen := int(b[5])
	if 6+dcidLen > len(b) {
		return nil, false
	}
	return b[6 : 6+dcidLen], true
}

// decryptInitial validates and decrypts one QUIC v1/v2 Initial packet,
// returning the plaintext payload (frames) and the QUIC version.
func decryptInitial(b []byte) ([]byte, uint32, error) {
	if len(b) < 7 {
		return nil, 0, fmt.Errorf("too short (%d)", len(b))
	}
	first := b[0]
	if first&0xC0 != 0xC0 {
		return nil, 0, fmt.Errorf("not a long header (0x%02x)", first)
	}
	version := binary.BigEndian.Uint32(b[1:5])
	switch {
	case version == VersionV1 && first&0x30 == 0x00:
	case version == VersionV2 && first&0x30 == 0x10:
	default:
		return nil, 0, fmt.Errorf("not a QUIC v1/v2 Initial (version 0x%08x, first 0x%02x)",
			version, first)
	}
	p := 5
	dcidLen := int(b[p])
	p++
	if p+dcidLen > len(b) {
		return nil, 0, fmt.Errorf("dcid out of range")
	}
	dcid := b[p : p+dcidLen]
	p += dcidLen
	if p >= len(b) {
		return nil, 0, fmt.Errorf("scid len out of range")
	}
	scidLen := int(b[p])
	p++
	if p+scidLen > len(b) {
		return nil, 0, fmt.Errorf("scid out of range")
	}
	p += scidLen
	tokenLen, n, ok := readVarint(b, p)
	if !ok {
		return nil, 0, fmt.Errorf("token len varint")
	}
	tl, ok := asLen(tokenLen)
	if !ok {
		return nil, 0, fmt.Errorf("token len too large")
	}
	p += n + tl
	lengthVarint, n, ok := readVarint(b, p)
	if !ok {
		return nil, 0, fmt.Errorf("length varint")
	}
	length, ok := asLen(lengthVarint)
	if !ok {
		return nil, 0, fmt.Errorf("length too large")
	}
	p += n
	pnOffset := p
	if pnOffset+length > len(b) || length < 20 {
		return nil, 0, fmt.Errorf("length %d vs buf %d (pnOffset %d)", length, len(b), pnOffset)
	}

	keys := deriveClientInitialKeys(dcid, version)

	sampleOff := pnOffset + 4
	if sampleOff+16 > len(b) {
		return nil, 0, fmt.Errorf("sample out of range")
	}
	block, err := aes.NewCipher(keys.HP)
	if err != nil {
		return nil, 0, err
	}
	mask := make([]byte, 16)
	block.Encrypt(mask, b[sampleOff:sampleOff+16])

	hdr := make([]byte, pnOffset+4)
	copy(hdr, b[:pnOffset+4])
	hdr[0] = first ^ (mask[0] & 0x0f)
	pnLen := int(hdr[0]&0x03) + 1
	var pn uint64
	for i := 0; i < pnLen; i++ {
		hdr[pnOffset+i] = b[pnOffset+i] ^ mask[(1+i)&0x0f]
		pn = (pn << 8) | uint64(hdr[pnOffset+i])
	}
	hdr = hdr[:pnOffset+pnLen]

	nonce := make([]byte, 12)
	copy(nonce, keys.IV)
	var pnbuf [8]byte
	binary.BigEndian.PutUint64(pnbuf[:], pn)
	for i := 0; i < 8; i++ {
		nonce[4+i] ^= pnbuf[i]
	}
	block, err = block2(keys.Key)
	if err != nil {
		return nil, 0, fmt.Errorf("payload cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, 0, err
	}
	ctStart := pnOffset + pnLen
	ctEnd := pnOffset + length
	if ctStart > ctEnd || ctEnd > len(b) {
		return nil, 0, fmt.Errorf("ciphertext range")
	}
	plain, err := gcm.Open(nil, nonce, b[ctStart:ctEnd], hdr)
	if err != nil {
		return nil, 0, fmt.Errorf("aead open: %w", err)
	}
	return plain, version, nil
}

// block2 builds an AES cipher for the GCM key.
func block2(key []byte) (cipher.Block, error) {
	return aes.NewCipher(key)
}

// reassembleCrypto merges the CRYPTO frames (type 0x06) of one or more
// decrypted Initial payloads in offset order and returns the contiguous
// handshake prefix starting at offset 0.
func reassembleCrypto(plains ...[]byte) []byte {
	type chunk struct {
		off  int
		data []byte
	}
	var chunks []chunk
	for _, plain := range plains {
		i := 0
		for i < len(plain) {
			ft := plain[i]
			if ft == 0x00 || ft == 0x01 {
				i++
				continue
			}
			if ft != 0x06 {
				break
			}
			i++
			offv, n, ok := readVarint(plain, i)
			if !ok {
				break
			}
			i += n
			lv, n, ok := readVarint(plain, i)
			if !ok {
				break
			}
			i += n
			off, ok := asLen(offv)
			if !ok {
				break
			}
			l, ok := asLen(lv)
			if !ok || i+l > len(plain) {
				break
			}
			chunks = append(chunks, chunk{off: off, data: plain[i : i+l]})
			i += l
		}
	}
	if len(chunks) == 0 {
		return nil
	}
	sort.Slice(chunks, func(i, j int) bool { return chunks[i].off < chunks[j].off })

	end := 0
	for _, c := range chunks {
		if c.off > end {
			break
		}
		if e := c.off + len(c.data); e > end {
			end = e
		}
	}
	if end == 0 || end > 1<<20 {
		return nil
	}
	out := make([]byte, end)
	for _, c := range chunks {
		if c.off >= end {
			break
		}
		copy(out[c.off:], c.data)
	}
	return out
}

// parseClientHelloSNI parses a TLS ClientHello handshake message and returns the
// server_name from the SNI extension.
func parseClientHelloSNI(hs []byte) (string, bool) {
	sni, _, ok := parseClientHello(hs)
	if !ok || sni == "" {
		return "", false
	}
	return sni, true
}

// parseClientHello parses a TLS ClientHello handshake message and returns the
// server_name from the SNI extension and the ALPN protocol list.
func parseClientHello(hs []byte) (string, []string, bool) {
	if len(hs) < 4 || hs[0] != 0x01 {
		return "", nil, false
	}
	body := hs[4:]
	p := 2 + 32
	if p+1 > len(body) {
		return "", nil, false
	}
	sidLen := int(body[p])
	p += 1 + sidLen
	if p+2 > len(body) {
		return "", nil, false
	}
	csLen := int(binary.BigEndian.Uint16(body[p:]))
	p += 2 + csLen
	if p+1 > len(body) {
		return "", nil, false
	}
	compLen := int(body[p])
	p += 1 + compLen
	if p+2 > len(body) {
		return "", nil, false
	}
	extTotal := int(binary.BigEndian.Uint16(body[p:]))
	p += 2
	if p+extTotal > len(body) {
		extTotal = len(body) - p
	}
	ext := body[p : p+extTotal]
	var sni string
	var alpn []string
	for q := 0; q+4 <= len(ext); {
		etype := binary.BigEndian.Uint16(ext[q:])
		elen := int(binary.BigEndian.Uint16(ext[q+2:]))
		q += 4
		if q+elen > len(ext) {
			break
		}
		switch etype {
		case 0x0000: // server_name
			if s, ok := parseSNIExtension(ext[q : q+elen]); ok {
				sni = s
			}
		case 0x0010: // application_layer_protocol_negotiation (RFC 7301)
			alpn = parseALPNExtension(ext[q : q+elen])
		}
		q += elen
	}
	return sni, alpn, true
}

// parseALPNExtension reads the protocol names from an ALPN extension body.
func parseALPNExtension(d []byte) []string {
	if len(d) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(d))
	p := 2
	end := p + listLen
	if end > len(d) {
		end = len(d)
	}
	var out []string
	for p+1 <= end {
		n := int(d[p])
		p++
		if n == 0 || p+n > end {
			break
		}
		out = append(out, string(d[p:p+n]))
		p += n
	}
	return out
}

// parseSNIExtension reads the first host_name from a server_name extension body.
func parseSNIExtension(d []byte) (string, bool) {
	if len(d) < 2 {
		return "", false
	}
	listLen := int(binary.BigEndian.Uint16(d))
	p := 2
	end := p + listLen
	if end > len(d) {
		end = len(d)
	}
	for p+3 <= end {
		nameType := d[p]
		nameLen := int(binary.BigEndian.Uint16(d[p+1:]))
		p += 3
		if p+nameLen > end {
			break
		}
		if nameType == 0x00 { // host_name
			return string(d[p : p+nameLen]), true
		}
		p += nameLen
	}
	return "", false
}
