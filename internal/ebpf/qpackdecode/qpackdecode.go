// Package qpackdecode implements a passive QPACK decoder (RFC 9204) for
// observed HTTP/3 traffic.
package qpackdecode

import (
	"errors"
	"fmt"
	"math"

	"golang.org/x/net/http2/hpack"

	"github.com/gma1k/podtrace/internal/safeconv"
)

func postBaseOverflows(base, index uint64) bool {
	return base > math.MaxUint64-index
}

// HeaderField is one decoded name/value pair.
type HeaderField struct {
	Name  string
	Value string
}

const (
	entryOverhead          = 32
	maxFieldLength         = 8192
	maxTableCapacity       = 1 << 16
	maxEncoderRemainder    = 64 * 1024
	maxPrefixedIntegerBits = 62
)

var errIncomplete = errors.New("qpackdecode: truncated input")

// BlockedError reports a field section that references dynamic table state
// beyond what the encoder stream has delivered so far (RFC 9204 §2.1.2).
type BlockedError struct {
	RequiredInsertCount uint64
	InsertCount         uint64
}

func (e *BlockedError) Error() string {
	return fmt.Sprintf("qpackdecode: blocked field section: requires insert count %d, have %d",
		e.RequiredInsertCount, e.InsertCount)
}

type tableEntry struct {
	name  string
	value string
	size  uint64
}

// Decoder tracks one direction of one HTTP/3 connection: the peer encoder's
// dynamic table plus buffered partial encoder-stream bytes.
type Decoder struct {
	settingsCapacity uint64
	largestCapacity  uint64
	capacity         uint64
	entries          []tableEntry
	evicted          uint64
	size             uint64
	remainder        []byte
}

// NewDecoder returns a decoder for a direction whose decoder side advertised
// maxTableCapacity, or 0 when that value is unknown.
func NewDecoder(maxTableCapacity uint64) *Decoder {
	return &Decoder{settingsCapacity: maxTableCapacity}
}

func (d *Decoder) InsertCount() uint64 {
	return d.evicted + uint64(len(d.entries))
}

// ParseEncoderStream consumes the next chunk of the peer's encoder stream.
func (d *Decoder) ParseEncoderStream(p []byte) error {
	if len(d.remainder)+len(p) > maxEncoderRemainder {
		return fmt.Errorf("qpackdecode: encoder instruction exceeds %d bytes", maxEncoderRemainder)
	}
	d.remainder = append(d.remainder, p...)
	for len(d.remainder) > 0 {
		consumed, err := d.parseEncoderInstruction(d.remainder)
		if errors.Is(err, errIncomplete) {
			return nil
		}
		if err != nil {
			return err
		}
		d.remainder = d.remainder[consumed:]
	}
	d.remainder = nil
	return nil
}

// parseEncoderInstruction decodes one instruction (RFC 9204 §4.3) and
// returns the bytes consumed, or errIncomplete if p ends mid-instruction.
func (d *Decoder) parseEncoderInstruction(p []byte) (int, error) {
	switch b := p[0]; {
	case b&0x80 != 0:
		isStatic := b&0x40 != 0
		index, n, err := readPrefixedInteger(p, 6)
		if err != nil {
			return 0, err
		}
		value, m, err := readString(p[n:], 7, 0x80)
		if err != nil {
			return 0, err
		}
		name, err := d.referencedName(isStatic, index)
		if err != nil {
			return 0, err
		}
		if err := d.insert(name, value); err != nil {
			return 0, err
		}
		return n + m, nil

	case b&0x40 != 0:
		name, n, err := readString(p, 5, 0x20)
		if err != nil {
			return 0, err
		}
		value, m, err := readString(p[n:], 7, 0x80)
		if err != nil {
			return 0, err
		}
		if err := d.insert(name, value); err != nil {
			return 0, err
		}
		return n + m, nil

	case b&0x20 != 0:
		capacity, n, err := readPrefixedInteger(p, 5)
		if err != nil {
			return 0, err
		}
		if err := d.setCapacity(capacity); err != nil {
			return 0, err
		}
		return n, nil

	default:
		index, n, err := readPrefixedInteger(p, 5)
		if err != nil {
			return 0, err
		}
		entry, err := d.relativeEntry(index)
		if err != nil {
			return 0, err
		}
		if err := d.insert(entry.name, entry.value); err != nil {
			return 0, err
		}
		return n, nil
	}
}

// referencedName resolves the name reference of an Insert With Name
// Reference instruction.
func (d *Decoder) referencedName(isStatic bool, index uint64) (string, error) {
	if isStatic {
		if index >= uint64(len(staticTable)) {
			return "", fmt.Errorf("qpackdecode: static table index %d out of range", index)
		}
		return staticTable[index].Name, nil
	}
	entry, err := d.relativeEntry(index)
	if err != nil {
		return "", err
	}
	return entry.name, nil
}

// relativeEntry resolves an encoder-stream relative index against the
// dynamic table: relative 0 is the most recent insertion.
func (d *Decoder) relativeEntry(relative uint64) (tableEntry, error) {
	count := d.InsertCount()
	if relative >= count {
		return tableEntry{}, fmt.Errorf("qpackdecode: dynamic relative index %d exceeds insert count %d", relative, count)
	}
	return d.absoluteEntry(count - 1 - relative)
}

func (d *Decoder) absoluteEntry(absolute uint64) (tableEntry, error) {
	if absolute < d.evicted {
		return tableEntry{}, fmt.Errorf("qpackdecode: reference to evicted dynamic entry %d", absolute)
	}
	if absolute >= d.InsertCount() {
		return tableEntry{}, fmt.Errorf("qpackdecode: reference to dynamic entry %d beyond insert count %d", absolute, d.InsertCount())
	}
	return d.entries[absolute-d.evicted], nil
}

func (d *Decoder) setCapacity(capacity uint64) error {
	if capacity > maxTableCapacity {
		return fmt.Errorf("qpackdecode: dynamic table capacity %d exceeds limit %d", capacity, maxTableCapacity)
	}
	if d.settingsCapacity > 0 && capacity > d.settingsCapacity {
		return fmt.Errorf("qpackdecode: capacity %d exceeds SETTINGS maximum %d", capacity, d.settingsCapacity)
	}
	if capacity > d.largestCapacity {
		d.largestCapacity = capacity
	}
	d.capacity = capacity
	d.evictTo(capacity)
	return nil
}

func (d *Decoder) insert(name, value string) error {
	entrySize := uint64(len(name)) + uint64(len(value)) + entryOverhead
	if entrySize > d.capacity {
		return fmt.Errorf("qpackdecode: entry of size %d exceeds table capacity %d", entrySize, d.capacity)
	}
	d.evictTo(d.capacity - entrySize)
	d.entries = append(d.entries, tableEntry{name: name, value: value, size: entrySize})
	d.size += entrySize
	return nil
}

func (d *Decoder) evictTo(target uint64) {
	for d.size > target && len(d.entries) > 0 {
		d.size -= d.entries[0].size
		d.entries = d.entries[1:]
		d.evicted++
	}
}

// DecodeFieldSection decodes one complete field section (the payload of one
// HEADERS frame).
func (d *Decoder) DecodeFieldSection(p []byte) ([]HeaderField, error) {
	fields, _, err := d.decodeFieldSection(p, false)
	return fields, err
}

// DecodeFieldSectionBestEffort decodes what it can of a field section even
// when dynamic table state is missing.
func (d *Decoder) DecodeFieldSectionBestEffort(p []byte) ([]HeaderField, int, error) {
	return d.decodeFieldSection(p, true)
}

func (d *Decoder) decodeFieldSection(p []byte, bestEffort bool) ([]HeaderField, int, error) {
	encodedInsertCount, n, err := readPrefixedInteger(p, 8)
	if err != nil {
		return nil, 0, sectionError(err)
	}
	requiredInsertCount, ricKnown, err := d.reconstructRequiredInsertCount(encodedInsertCount, bestEffort)
	if err != nil {
		return nil, 0, err
	}
	if ricKnown && requiredInsertCount > d.InsertCount() && !bestEffort {
		return nil, 0, &BlockedError{RequiredInsertCount: requiredInsertCount, InsertCount: d.InsertCount()}
	}
	p = p[n:]
	if len(p) == 0 {
		return nil, 0, sectionError(errIncomplete)
	}
	signNegative := p[0]&0x80 != 0
	deltaBase, n, err := readPrefixedInteger(p, 7)
	if err != nil {
		return nil, 0, sectionError(err)
	}
	p = p[n:]

	var base uint64
	baseKnown := ricKnown
	if ricKnown {
		if signNegative {
			if deltaBase+1 > requiredInsertCount {
				return nil, 0, fmt.Errorf("qpackdecode: negative base: delta %d with required insert count %d", deltaBase, requiredInsertCount)
			}
			base = requiredInsertCount - deltaBase - 1
		} else {
			base = requiredInsertCount + deltaBase
		}
	}

	var fields []HeaderField
	unresolved := 0
	appendEntry := func(entry tableEntry, err error) error {
		if err != nil {
			if bestEffort {
				unresolved++
				return nil
			}
			return err
		}
		fields = append(fields, HeaderField{Name: entry.name, Value: entry.value})
		return nil
	}
	dynamicEntry := func(absolute uint64, known bool) (tableEntry, error) {
		if !known {
			return tableEntry{}, errors.New("qpackdecode: dynamic reference without reconstructable base")
		}
		return d.absoluteEntry(absolute)
	}
	postBaseEntry := func(index uint64) (tableEntry, error) {
		if postBaseOverflows(base, index) {
			return tableEntry{}, fmt.Errorf("qpackdecode: post-base index overflow (base %d, index %d)", base, index)
		}
		return dynamicEntry(base+index, baseKnown)
	}

	for len(p) > 0 {
		switch b := p[0]; {
		case b&0x80 != 0: // Indexed Field Line: 1 T(1) Index(6+)
			index, n, err := readPrefixedInteger(p, 6)
			if err != nil {
				return nil, 0, sectionError(err)
			}
			if b&0x40 != 0 {
				if index >= uint64(len(staticTable)) {
					return nil, 0, fmt.Errorf("qpackdecode: static table index %d out of range", index)
				}
				fields = append(fields, staticTable[index])
			} else {
				baseOK := baseKnown && base >= index+1
				var entry tableEntry
				var lookupErr error
				if baseOK {
					entry, lookupErr = dynamicEntry(base-index-1, true)
				} else {
					entry, lookupErr = dynamicEntry(0, false)
				}
				if err := appendEntry(entry, lookupErr); err != nil {
					return nil, 0, err
				}
			}
			p = p[n:]

		case b&0x40 != 0:
			isStatic := b&0x10 != 0
			index, n, err := readPrefixedInteger(p, 4)
			if err != nil {
				return nil, 0, sectionError(err)
			}
			value, m, err := readString(p[n:], 7, 0x80)
			if err != nil {
				return nil, 0, sectionError(err)
			}
			if isStatic {
				if index >= uint64(len(staticTable)) {
					return nil, 0, fmt.Errorf("qpackdecode: static table index %d out of range", index)
				}
				fields = append(fields, HeaderField{Name: staticTable[index].Name, Value: value})
			} else {
				baseOK := baseKnown && base >= index+1
				var entry tableEntry
				var lookupErr error
				if baseOK {
					entry, lookupErr = dynamicEntry(base-index-1, true)
				} else {
					entry, lookupErr = dynamicEntry(0, false)
				}
				if lookupErr == nil {
					fields = append(fields, HeaderField{Name: entry.name, Value: value})
				} else if bestEffort {
					unresolved++
				} else {
					return nil, 0, lookupErr
				}
			}
			p = p[n+m:]

		case b&0x20 != 0:
			name, n, err := readString(p, 3, 0x08)
			if err != nil {
				return nil, 0, sectionError(err)
			}
			value, m, err := readString(p[n:], 7, 0x80)
			if err != nil {
				return nil, 0, sectionError(err)
			}
			fields = append(fields, HeaderField{Name: name, Value: value})
			p = p[n+m:]

		case b&0x10 != 0:
			index, n, err := readPrefixedInteger(p, 4)
			if err != nil {
				return nil, 0, sectionError(err)
			}
			entry, lookupErr := postBaseEntry(index)
			if err := appendEntry(entry, lookupErr); err != nil {
				return nil, 0, err
			}
			p = p[n:]

		default:
			index, n, err := readPrefixedInteger(p, 3)
			if err != nil {
				return nil, 0, sectionError(err)
			}
			value, m, err := readString(p[n:], 7, 0x80)
			if err != nil {
				return nil, 0, sectionError(err)
			}
			entry, lookupErr := postBaseEntry(index)
			if lookupErr == nil {
				fields = append(fields, HeaderField{Name: entry.name, Value: value})
			} else if bestEffort {
				unresolved++
			} else {
				return nil, 0, lookupErr
			}
			p = p[n+m:]
		}
	}
	return fields, unresolved, nil
}

// reconstructRequiredInsertCount implements RFC 9204 §4.5.1.1.
func (d *Decoder) reconstructRequiredInsertCount(encoded uint64, bestEffort bool) (uint64, bool, error) {
	if encoded == 0 {
		return 0, true, nil
	}
	anchor := d.settingsCapacity
	if anchor == 0 {
		anchor = d.largestCapacity
	}
	maxEntries := anchor / entryOverhead
	if maxEntries == 0 {
		if bestEffort {
			return 0, false, nil
		}
		return 0, false, &BlockedError{InsertCount: d.InsertCount()}
	}
	fullRange := 2 * maxEntries
	if encoded > fullRange {
		if d.settingsCapacity > 0 {
			return 0, false, fmt.Errorf("qpackdecode: encoded insert count %d exceeds full range %d", encoded, fullRange)
		}
		encoded = (encoded-1)%fullRange + 1
	}
	maxValue := d.InsertCount() + maxEntries
	maxWrapped := maxValue / fullRange * fullRange
	requiredInsertCount := maxWrapped + encoded - 1
	if requiredInsertCount > maxValue {
		if requiredInsertCount <= fullRange {
			return 0, false, fmt.Errorf("qpackdecode: invalid required insert count %d", requiredInsertCount)
		}
		requiredInsertCount -= fullRange
	}
	if requiredInsertCount == 0 {
		return 0, false, errors.New("qpackdecode: invalid required insert count 0")
	}
	return requiredInsertCount, true, nil
}

func sectionError(err error) error {
	if errors.Is(err, errIncomplete) {
		return errors.New("qpackdecode: truncated field section")
	}
	return err
}

// readPrefixedInteger decodes an N-bit-prefix integer (RFC 9204 §4.1.1 /
// RFC 7541 §5.1) and returns the value and bytes consumed.
func readPrefixedInteger(p []byte, prefixBits uint) (uint64, int, error) {
	if len(p) == 0 {
		return 0, 0, errIncomplete
	}
	mask := uint64(1)<<prefixBits - 1
	value := uint64(p[0]) & mask
	if value < mask {
		return value, 1, nil
	}
	var shift uint
	for i := 1; ; i++ {
		if i >= len(p) {
			return 0, 0, errIncomplete
		}
		if shift >= maxPrefixedIntegerBits {
			return 0, 0, errors.New("qpackdecode: prefixed integer overflow")
		}
		b := p[i]
		value += uint64(b&0x7f) << shift
		shift += 7
		if b&0x80 == 0 {
			return value, i + 1, nil
		}
	}
}

// readString decodes a length-prefixed string literal whose length uses a
// prefixBits-bit prefix and whose Huffman flag is huffmanMask in the first
// byte. It returns the decoded string and total bytes consumed.
func readString(p []byte, prefixBits uint, huffmanMask byte) (string, int, error) {
	if len(p) == 0 {
		return "", 0, errIncomplete
	}
	huffman := p[0]&huffmanMask != 0
	length, n, err := readPrefixedInteger(p, prefixBits)
	if err != nil {
		return "", 0, err
	}
	if length > maxFieldLength {
		return "", 0, fmt.Errorf("qpackdecode: field of %d bytes exceeds limit %d", length, maxFieldLength)
	}
	byteLen := int(safeconv.Uint64ToInt32(length))
	rest := p[n:]
	if len(rest) < byteLen {
		return "", 0, errIncomplete
	}
	raw := rest[:byteLen]
	if !huffman {
		return string(raw), n + byteLen, nil
	}
	decoded, err := hpack.HuffmanDecodeToString(raw)
	if err != nil {
		return "", 0, fmt.Errorf("qpackdecode: %w", err)
	}
	if len(decoded) > maxFieldLength {
		return "", 0, fmt.Errorf("qpackdecode: field of %d bytes exceeds limit %d", len(decoded), maxFieldLength)
	}
	return decoded, n + byteLen, nil
}
