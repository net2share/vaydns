// Package dns deals with encoding and decoding DNS wire format.
package dns

import (
	"bytes"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

// The maximum number of DNS name compression pointers we are willing to follow.
// Without something like this, infinite loops are possible.
const compressionPointerLimit = 10

var (
	// ErrZeroLengthLabel is the error returned for names that contain a
	// zero-length label, like "example..com".
	ErrZeroLengthLabel = errors.New("name contains a zero-length label")

	// ErrLabelTooLong is the error returned for labels that are longer than
	// 63 octets.
	ErrLabelTooLong = errors.New("name contains a label longer than 63 octets")

	// ErrNameTooLong is the error returned for names whose encoded
	// representation is longer than 255 octets.
	ErrNameTooLong = errors.New("name is longer than 255 octets")

	// ErrReservedLabelType is the error returned when reading a label type
	// prefix whose two most significant bits are not 00 or 11.
	ErrReservedLabelType = errors.New("reserved label type")

	// ErrTooManyPointers is the error returned when reading a compressed
	// name that has too many compression pointers.
	ErrTooManyPointers = errors.New("too many compression pointers")

	// ErrTrailingBytes is the error returned when bytes remain in the parse
	// buffer after parsing a message.
	ErrTrailingBytes = errors.New("trailing bytes after message")

	// ErrIntegerOverflow is the error returned when trying to encode an
	// integer greater than 65535 into a 16-bit field.
	ErrIntegerOverflow = errors.New("integer overflow")
)

const (
	// https://tools.ietf.org/html/rfc1035#section-3.2.2
	RRTypeA     = 1
	RRTypeNS    = 2
	RRTypeCNAME = 5
	RRTypeNULL  = 10
	RRTypeMX    = 15
	RRTypeTXT   = 16
	RRTypeAAAA  = 28
	RRTypeSRV   = 33
	RRTypeCAA   = 257
	// https://tools.ietf.org/html/rfc6891#section-6.1.1
	RRTypeOPT = 41

	// https://tools.ietf.org/html/rfc1035#section-3.2.4
	ClassIN = 1

	// https://tools.ietf.org/html/rfc1035#section-4.1.1
	RcodeNoError        = 0 // a.k.a. NOERROR
	RcodeFormatError    = 1 // a.k.a. FORMERR
	RcodeServerFailure  = 2 // a.k.a. SERVFAIL
	RcodeNameError      = 3 // a.k.a. NXDOMAIN
	RcodeNotImplemented = 4 // a.k.a. NOTIMPL
	// https://tools.ietf.org/html/rfc6891#section-9
	ExtendedRcodeBadVers = 16 // a.k.a. BADVERS
)

// ParseRecordType converts a record type string ("txt", "cname", "a", etc.)
// to the corresponding RR type constant. Returns an error for unknown types.
func ParseRecordType(s string) (uint16, error) {
	switch strings.ToLower(s) {
	case "txt":
		return RRTypeTXT, nil
	case "cname":
		return RRTypeCNAME, nil
	case "null":
		return RRTypeNULL, nil
	case "a":
		return RRTypeA, nil
	case "aaaa":
		return RRTypeAAAA, nil
	case "mx":
		return RRTypeMX, nil
	case "ns":
		return RRTypeNS, nil
	case "srv":
		return RRTypeSRV, nil
	case "caa":
		return RRTypeCAA, nil
	default:
		return 0, fmt.Errorf("unknown record type %q: must be one of: txt, cname, null, a, aaaa, mx, ns, srv, caa", s)
	}
}

// Name represents a domain name, a sequence of labels each of which is 63
// octets or less in length.
//
// https://tools.ietf.org/html/rfc1035#section-3.1
type Name [][]byte

// NewName returns a Name from a slice of labels, after checking the labels for
// validity. Does not include a zero-length label at the end of the slice.
func NewName(labels [][]byte) (Name, error) {
	name := Name(labels)
	// https://tools.ietf.org/html/rfc1035#section-2.3.4
	// Various objects and parameters in the DNS have size limits.
	//   labels          63 octets or less
	//   names           255 octets or less
	for _, label := range labels {
		if len(label) == 0 {
			return nil, ErrZeroLengthLabel
		}
		if len(label) > 63 {
			return nil, ErrLabelTooLong
		}
	}
	// Check the total length.
	builder := newMessageBuilder()
	builder.WriteName(name)
	if len(builder.Bytes()) > 255 {
		return nil, ErrNameTooLong
	}
	return name, nil
}

// ParseName returns a new Name from a string of labels separated by dots, after
// checking the name for validity. A single dot at the end of the string is
// ignored.
func ParseName(s string) (Name, error) {
	b := bytes.TrimSuffix([]byte(s), []byte("."))
	if len(b) == 0 {
		// bytes.Split(b, ".") would return [""] in this case
		return NewName([][]byte{})
	} else {
		return NewName(bytes.Split(b, []byte(".")))
	}
}

// String returns a reversible string representation of name. Labels are
// separated by dots, and any bytes in a label that are outside the set
// [0-9A-Za-z-] are replaced with a \xXX hex escape sequence.
func (name Name) String() string {
	if len(name) == 0 {
		return "."
	}

	var buf strings.Builder
	for i, label := range name {
		if i > 0 {
			buf.WriteByte('.')
		}
		for _, b := range label {
			if b == '-' ||
				('0' <= b && b <= '9') ||
				('A' <= b && b <= 'Z') ||
				('a' <= b && b <= 'z') {
				buf.WriteByte(b)
			} else {
				fmt.Fprintf(&buf, "\\x%02x", b)
			}
		}
	}
	return buf.String()
}

// TrimSuffix returns a Name with the given suffix removed, if it was present.
// The second return value indicates whether the suffix was present. If the
// suffix was not present, the first return value is nil.
func (name Name) TrimSuffix(suffix Name) (Name, bool) {
	if len(name) < len(suffix) {
		return nil, false
	}
	split := len(name) - len(suffix)
	fore, aft := name[:split], name[split:]
	for i := 0; i < len(aft); i++ {
		if !bytes.Equal(bytes.ToLower(aft[i]), bytes.ToLower(suffix[i])) {
			return nil, false
		}
	}
	return fore, true
}

// WireFormat serializes a Name to uncompressed DNS wire format: a sequence of
// length-prefixed labels followed by a zero-length root label.
func (name Name) WireFormat() []byte {
	var buf bytes.Buffer
	for _, label := range name {
		buf.WriteByte(byte(len(label)))
		buf.Write(label)
	}
	buf.WriteByte(0)
	return buf.Bytes()
}

// NameFromWireFormat parses an uncompressed DNS name from raw bytes. It does not
// handle compression pointers.
func NameFromWireFormat(data []byte) (Name, error) {
	var labels [][]byte
	i := 0
	for {
		if i >= len(data) {
			return nil, io.ErrUnexpectedEOF
		}
		length := int(data[i])
		i++
		if length == 0 {
			break
		}
		if length > 63 {
			return nil, ErrLabelTooLong
		}
		if i+length > len(data) {
			return nil, io.ErrUnexpectedEOF
		}
		labels = append(labels, data[i:i+length])
		i += length
	}
	return Name(labels), nil
}

// Message represents a DNS message.
//
// https://tools.ietf.org/html/rfc1035#section-4.1
type Message struct {
	ID    uint16
	Flags uint16

	Question   []Question
	Answer     []RR
	Authority  []RR
	Additional []RR
}

// Opcode extracts the OPCODE part of the Flags field.
//
// https://tools.ietf.org/html/rfc1035#section-4.1.1
func (message *Message) Opcode() uint16 {
	return (message.Flags >> 11) & 0xf
}

// Rcode extracts the RCODE part of the Flags field.
//
// https://tools.ietf.org/html/rfc1035#section-4.1.1
func (message *Message) Rcode() uint16 {
	return message.Flags & 0x000f
}

// Question represents an entry in the question section of a message.
//
// https://tools.ietf.org/html/rfc1035#section-4.1.2
type Question struct {
	Name  Name
	Type  uint16
	Class uint16
}

// RR represents a resource record.
//
// https://tools.ietf.org/html/rfc1035#section-4.1.3
type RR struct {
	Name  Name
	Type  uint16
	Class uint16
	TTL   uint32
	Data  []byte
}

// readName parses a DNS name from r. It leaves r positioned just after the
// parsed name.
func readName(r io.ReadSeeker) (Name, error) {
	var labels [][]byte
	// We limit the number of compression pointers we are willing to follow.
	numPointers := 0
	// If we followed any compression pointers, we must finally seek to just
	// past the first pointer.
	var seekTo int64
loop:
	for {
		var labelType byte
		err := binary.Read(r, binary.BigEndian, &labelType)
		if err != nil {
			return nil, err
		}

		switch labelType & 0xc0 {
		case 0x00:
			// This is an ordinary label.
			// https://tools.ietf.org/html/rfc1035#section-3.1
			length := int(labelType & 0x3f)
			if length == 0 {
				break loop
			}
			label := make([]byte, length)
			_, err := io.ReadFull(r, label)
			if err != nil {
				return nil, err
			}
			labels = append(labels, label)
		case 0xc0:
			// This is a compression pointer.
			// https://tools.ietf.org/html/rfc1035#section-4.1.4
			upper := labelType & 0x3f
			var lower byte
			err := binary.Read(r, binary.BigEndian, &lower)
			if err != nil {
				return nil, err
			}
			offset := (uint16(upper) << 8) | uint16(lower)

			if numPointers == 0 {
				// The first time we encounter a pointer,
				// remember our position so we can seek back to
				// it when done.
				seekTo, err = r.Seek(0, io.SeekCurrent)
				if err != nil {
					return nil, err
				}
			}
			numPointers++
			if numPointers > compressionPointerLimit {
				return nil, ErrTooManyPointers
			}

			// Follow the pointer and continue.
			_, err = r.Seek(int64(offset), io.SeekStart)
			if err != nil {
				return nil, err
			}
		default:
			// "The 10 and 01 combinations are reserved for future
			// use."
			return nil, ErrReservedLabelType
		}
	}
	// If we followed any pointers, then seek back to just after the first
	// one.
	if numPointers > 0 {
		_, err := r.Seek(seekTo, io.SeekStart)
		if err != nil {
			return nil, err
		}
	}
	return NewName(labels)
}

// readQuestion parses one entry from the Question section. It leaves r
// positioned just after the parsed entry.
//
// https://tools.ietf.org/html/rfc1035#section-4.1.2
func readQuestion(r io.ReadSeeker) (Question, error) {
	var question Question
	var err error
	question.Name, err = readName(r)
	if err != nil {
		return question, err
	}
	for _, ptr := range []*uint16{&question.Type, &question.Class} {
		err := binary.Read(r, binary.BigEndian, ptr)
		if err != nil {
			return question, err
		}
	}

	return question, nil
}

// readRR parses one resource record. It leaves r positioned just after the
// parsed resource record.
//
// https://tools.ietf.org/html/rfc1035#section-4.1.3
func readRR(r io.ReadSeeker) (RR, error) {
	var rr RR
	var err error
	rr.Name, err = readName(r)
	if err != nil {
		return rr, err
	}
	for _, ptr := range []*uint16{&rr.Type, &rr.Class} {
		err := binary.Read(r, binary.BigEndian, ptr)
		if err != nil {
			return rr, err
		}
	}
	err = binary.Read(r, binary.BigEndian, &rr.TTL)
	if err != nil {
		return rr, err
	}
	var rdLength uint16
	err = binary.Read(r, binary.BigEndian, &rdLength)
	if err != nil {
		return rr, err
	}
	// readRRName is a helper that attempts to parse a compressed name from
	// RDATA. On failure, it falls back to reading raw bytes.
	readRRName := func(headerLen int) error {
		startPos, err := r.Seek(0, io.SeekCurrent)
		if err != nil {
			return err
		}
		// Read any fixed-size header before the name.
		var header []byte
		if headerLen > 0 {
			header = make([]byte, headerLen)
			if _, err := io.ReadFull(r, header); err != nil {
				return err
			}
		}
		name, err := readName(r)
		if err != nil {
			// Fallback: read raw bytes instead.
			if _, seekErr := r.Seek(startPos, io.SeekStart); seekErr != nil {
				return seekErr
			}
			rr.Data = make([]byte, rdLength)
			_, err = io.ReadFull(r, rr.Data)
			return err
		}
		nameWire := name.WireFormat()
		rr.Data = make([]byte, headerLen+len(nameWire))
		copy(rr.Data, header)
		copy(rr.Data[headerLen:], nameWire)
		// Ensure reader is positioned past the RDATA.
		_, err = r.Seek(startPos+int64(rdLength), io.SeekStart)
		return err
	}

	switch {
	case rdLength > 0 && (rr.Type == RRTypeCNAME || rr.Type == RRTypeNS):
		if err := readRRName(0); err != nil {
			return rr, err
		}
	case rdLength > 2 && rr.Type == RRTypeMX:
		if err := readRRName(2); err != nil {
			return rr, err
		}
	case rdLength > 6 && rr.Type == RRTypeSRV:
		if err := readRRName(6); err != nil {
			return rr, err
		}
	default:
		rr.Data = make([]byte, rdLength)
		_, err = io.ReadFull(r, rr.Data)
		if err != nil {
			return rr, err
		}
	}

	return rr, nil
}

// readMessage parses a complete DNS message. It leaves r positioned just after
// the parsed message.
func readMessage(r io.ReadSeeker) (Message, error) {
	var message Message

	// Header section
	// https://tools.ietf.org/html/rfc1035#section-4.1.1
	var qdCount, anCount, nsCount, arCount uint16
	for _, ptr := range []*uint16{
		&message.ID, &message.Flags,
		&qdCount, &anCount, &nsCount, &arCount,
	} {
		err := binary.Read(r, binary.BigEndian, ptr)
		if err != nil {
			return message, err
		}
	}

	// Question section
	// https://tools.ietf.org/html/rfc1035#section-4.1.2
	for i := 0; i < int(qdCount); i++ {
		question, err := readQuestion(r)
		if err != nil {
			return message, err
		}
		message.Question = append(message.Question, question)
	}

	// Answer, Authority, and Additional sections
	// https://tools.ietf.org/html/rfc1035#section-4.1.3
	for _, rec := range []struct {
		ptr   *[]RR
		count uint16
	}{
		{&message.Answer, anCount},
		{&message.Authority, nsCount},
		{&message.Additional, arCount},
	} {
		for i := 0; i < int(rec.count); i++ {
			rr, err := readRR(r)
			if err != nil {
				return message, err
			}
			*rec.ptr = append(*rec.ptr, rr)
		}
	}

	return message, nil
}

// MessageFromWireFormat parses a message from buf and returns a Message object.
// It returns ErrTrailingBytes if there are bytes remaining in buf after parsing
// is done.
func MessageFromWireFormat(buf []byte) (Message, error) {
	r := bytes.NewReader(buf)
	message, err := readMessage(r)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	} else if err == nil {
		// Check for trailing bytes.
		_, err = r.ReadByte()
		if err == io.EOF {
			err = nil
		} else if err == nil {
			err = ErrTrailingBytes
		}
	}
	return message, err
}

// messageBuilder manages the state of serializing a DNS message. Its main
// function is to keep track of names already written for the purpose of name
// compression.
type messageBuilder struct {
	w         bytes.Buffer
	nameCache map[string]int
}

// newMessageBuilder creates a new messageBuilder with an empty name cache.
func newMessageBuilder() *messageBuilder {
	return &messageBuilder{
		nameCache: make(map[string]int),
	}
}

// Bytes returns the serialized DNS message as a slice of bytes.
func (builder *messageBuilder) Bytes() []byte {
	return builder.w.Bytes()
}

// WriteName appends name to the in-progress messageBuilder, employing
// compression pointers to previously written names if possible.
func (builder *messageBuilder) WriteName(name Name) {
	// https://tools.ietf.org/html/rfc1035#section-3.1
	for i := range name {
		// Has this suffix already been encoded in the message?
		if ptr, ok := builder.nameCache[name[i:].String()]; ok && ptr&0x3fff == ptr {
			// If so, we can write a compression pointer.
			binary.Write(&builder.w, binary.BigEndian, uint16(0xc000|ptr))
			return
		}
		// Not cached; we must encode this label verbatim. Store a cache
		// entry pointing to the beginning of it.
		builder.nameCache[name[i:].String()] = builder.w.Len()
		length := len(name[i])
		if length == 0 || length > 63 {
			panic(length)
		}
		builder.w.WriteByte(byte(length))
		builder.w.Write(name[i])
	}
	builder.w.WriteByte(0)
}

// WriteQuestion appends a Question section entry to the in-progress
// messageBuilder.
func (builder *messageBuilder) WriteQuestion(question *Question) {
	// https://tools.ietf.org/html/rfc1035#section-4.1.2
	builder.WriteName(question.Name)
	binary.Write(&builder.w, binary.BigEndian, question.Type)
	binary.Write(&builder.w, binary.BigEndian, question.Class)
}

// WriteRR appends a resource record to the in-progress messageBuilder. It
// returns ErrIntegerOverflow if the length of rr.Data does not fit in 16 bits.
func (builder *messageBuilder) WriteRR(rr *RR) error {
	// https://tools.ietf.org/html/rfc1035#section-4.1.3
	builder.WriteName(rr.Name)
	binary.Write(&builder.w, binary.BigEndian, rr.Type)
	binary.Write(&builder.w, binary.BigEndian, rr.Class)
	binary.Write(&builder.w, binary.BigEndian, rr.TTL)
	rdLength := uint16(len(rr.Data))
	if int(rdLength) != len(rr.Data) {
		return ErrIntegerOverflow
	}
	binary.Write(&builder.w, binary.BigEndian, rdLength)
	builder.w.Write(rr.Data)
	return nil
}

// WriteMessage appends a complete DNS message to the in-progress
// messageBuilder. It returns ErrIntegerOverflow if the number of entries in any
// section, or the length of the data in any resource record, does not fit in 16
// bits.
func (builder *messageBuilder) WriteMessage(message *Message) error {
	// Header section
	// https://tools.ietf.org/html/rfc1035#section-4.1.1
	binary.Write(&builder.w, binary.BigEndian, message.ID)
	binary.Write(&builder.w, binary.BigEndian, message.Flags)
	for _, count := range []int{
		len(message.Question),
		len(message.Answer),
		len(message.Authority),
		len(message.Additional),
	} {
		count16 := uint16(count)
		if int(count16) != count {
			return ErrIntegerOverflow
		}
		binary.Write(&builder.w, binary.BigEndian, count16)
	}

	// Question section
	// https://tools.ietf.org/html/rfc1035#section-4.1.2
	for _, question := range message.Question {
		builder.WriteQuestion(&question)
	}

	// Answer, Authority, and Additional sections
	// https://tools.ietf.org/html/rfc1035#section-4.1.3
	for _, rrs := range [][]RR{message.Answer, message.Authority, message.Additional} {
		for _, rr := range rrs {
			err := builder.WriteRR(&rr)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// WireFormat encodes a Message as a slice of bytes in DNS wire format. It
// returns ErrIntegerOverflow if the number of entries in any section, or the
// length of the data in any resource record, does not fit in 16 bits.
func (message *Message) WireFormat() ([]byte, error) {
	builder := newMessageBuilder()
	err := builder.WriteMessage(message)
	if err != nil {
		return nil, err
	}
	return builder.Bytes(), nil
}

// DecodeRDataTXT decodes TXT-DATA (as found in the RDATA for a resource record
// with TYPE=TXT) as a raw byte slice, by concatenating all the
// <character-string>s it contains.
//
// https://tools.ietf.org/html/rfc1035#section-3.3.14
func DecodeRDataTXT(p []byte) ([]byte, error) {
	var buf bytes.Buffer
	for {
		if len(p) == 0 {
			return nil, io.ErrUnexpectedEOF
		}
		n := int(p[0])
		p = p[1:]
		if len(p) < n {
			return nil, io.ErrUnexpectedEOF
		}
		buf.Write(p[:n])
		p = p[n:]
		if len(p) == 0 {
			break
		}
	}
	return buf.Bytes(), nil
}

// EncodeRDataTXT encodes a slice of bytes as TXT-DATA, as appropriate for the
// RDATA of a resource record with TYPE=TXT. No length restriction is enforced
// here; that must be checked at a higher level.
//
// https://tools.ietf.org/html/rfc1035#section-3.3.14
func EncodeRDataTXT(p []byte) []byte {
	// https://tools.ietf.org/html/rfc1035#section-3.3
	// https://tools.ietf.org/html/rfc1035#section-3.3.14
	// TXT data is a sequence of one or more <character-string>s, where
	// <character-string> is a length octet followed by that number of
	// octets.
	var buf bytes.Buffer
	for len(p) > 255 {
		buf.WriteByte(255)
		buf.Write(p[:255])
		p = p[255:]
	}
	// Must write here, even if len(p) == 0, because it's "*one or more*
	// <character-string>s".
	buf.WriteByte(byte(len(p)))
	buf.Write(p)
	return buf.Bytes()
}

// DecodeRDataNULL decodes NULL RDATA as a raw byte slice.
// https://tools.ietf.org/html/rfc1035#section-3.3.10
func DecodeRDataNULL(p []byte) ([]byte, error) { return p, nil }

// EncodeRDataNULL encodes a slice of bytes as NULL RDATA.
// https://tools.ietf.org/html/rfc1035#section-3.3.10
func EncodeRDataNULL(p []byte) []byte { return p }

// DecodeRDataCAA decodes CAA RDATA and returns the value portion.
// https://datatracker.ietf.org/doc/html/rfc8659
func DecodeRDataCAA(p []byte) ([]byte, error) {
	if len(p) < 2 {
		return nil, io.ErrUnexpectedEOF
	}
	tagLen := int(p[1])
	p = p[2:]
	if len(p) < tagLen {
		return nil, io.ErrUnexpectedEOF
	}
	return p[tagLen:], nil
}

// EncodeRDataCAA encodes a slice of bytes as CAA RDATA using a fixed
// "issue" tag so the payload lives entirely in the value portion.
// https://datatracker.ietf.org/doc/html/rfc8659
func EncodeRDataCAA(p []byte) []byte {
	const tag = "issue"
	rdata := make([]byte, 2+len(tag)+len(p))
	// rdata[0] = 0 (flags; bit 7 is the "critical" flag per RFC 8659 §4.1)
	rdata[1] = byte(len(tag))
	copy(rdata[2:], tag)
	copy(rdata[2+len(tag):], p)
	return rdata
}

// base32Encoding is a base32 encoding without padding, used for CNAME RDATA.
var base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// encodePayloadAsName base32-encodes a payload into DNS name labels and appends
// the tunnel domain. Returns the uncompressed wire-format domain name.
func encodePayloadAsName(p []byte, domain Name) ([]byte, error) {
	const labelLen = 63

	encoded := make([]byte, base32Encoding.EncodedLen(len(p)))
	base32Encoding.Encode(encoded, p)
	encoded = bytes.ToLower(encoded)

	var labels [][]byte
	for len(encoded) > labelLen {
		labels = append(labels, encoded[:labelLen])
		encoded = encoded[labelLen:]
	}
	if len(encoded) > 0 {
		labels = append(labels, encoded)
	}
	labels = append(labels, domain...)

	name, err := NewName(labels)
	if err != nil {
		return nil, err
	}
	return name.WireFormat(), nil
}

// decodePayloadFromName parses an uncompressed wire-format domain name, strips
// the tunnel domain suffix, joins the remaining labels, and base32-decodes them.
func decodePayloadFromName(data []byte, domain Name) ([]byte, error) {
	name, err := NameFromWireFormat(data)
	if err != nil {
		return nil, err
	}
	prefix, ok := name.TrimSuffix(domain)
	if !ok {
		return nil, fmt.Errorf("name does not end with domain %s", domain)
	}
	joined := bytes.ToUpper(bytes.Join(prefix, nil))
	payload := make([]byte, base32Encoding.DecodedLen(len(joined)))
	n, err := base32Encoding.Decode(payload, joined)
	if err != nil {
		return nil, err
	}
	return payload[:n], nil
}

// EncodeRDataCNAME encodes a payload as CNAME RDATA.
// https://tools.ietf.org/html/rfc1035#section-3.3.1
func EncodeRDataCNAME(p []byte, domain Name) ([]byte, error) {
	return encodePayloadAsName(p, domain)
}

// DecodeRDataCNAME decodes CNAME RDATA back to the original payload.
func DecodeRDataCNAME(data []byte, domain Name) ([]byte, error) {
	return decodePayloadFromName(data, domain)
}

// EncodeRDataNS encodes a payload as NS RDATA (identical format to CNAME).
// https://tools.ietf.org/html/rfc1035#section-3.3.11
func EncodeRDataNS(p []byte, domain Name) ([]byte, error) {
	return encodePayloadAsName(p, domain)
}

// DecodeRDataNS decodes NS RDATA back to the original payload.
func DecodeRDataNS(data []byte, domain Name) ([]byte, error) {
	return decodePayloadFromName(data, domain)
}

// EncodeRDataMX encodes a payload as MX RDATA: [preference:2][exchange:name].
// https://tools.ietf.org/html/rfc1035#section-3.3.9
func EncodeRDataMX(p []byte, domain Name) ([]byte, error) {
	nameWire, err := encodePayloadAsName(p, domain)
	if err != nil {
		return nil, err
	}
	// Prepend 2-byte preference field (set to 0).
	rdata := make([]byte, 2+len(nameWire))
	copy(rdata[2:], nameWire)
	return rdata, nil
}

// DecodeRDataMX decodes MX RDATA back to the original payload.
func DecodeRDataMX(data []byte, domain Name) ([]byte, error) {
	if len(data) < 2 {
		return nil, io.ErrUnexpectedEOF
	}
	// Skip 2-byte preference field.
	return decodePayloadFromName(data[2:], domain)
}

// EncodeRDataSRV encodes a payload as SRV RDATA:
// [priority:2][weight:2][port:2][target:name].
// https://tools.ietf.org/html/rfc2782
func EncodeRDataSRV(p []byte, domain Name) ([]byte, error) {
	nameWire, err := encodePayloadAsName(p, domain)
	if err != nil {
		return nil, err
	}
	// Prepend 6-byte header (priority, weight, port — all set to 0).
	rdata := make([]byte, 6+len(nameWire))
	copy(rdata[6:], nameWire)
	return rdata, nil
}

// DecodeRDataSRV decodes SRV RDATA back to the original payload.
func DecodeRDataSRV(data []byte, domain Name) ([]byte, error) {
	if len(data) < 6 {
		return nil, io.ErrUnexpectedEOF
	}
	// Skip 6-byte header.
	return decodePayloadFromName(data[6:], domain)
}

// encodeRDataMultiRR encodes a payload as multiple fixed-size RDATA chunks.
// The payload is prefixed with a 2-byte big-endian length, then split into
// chunkSize-byte chunks (last chunk zero-padded).
func encodeRDataMultiRR(p []byte, chunkSize int) [][]byte {
	buf := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(buf, uint16(len(p)))
	copy(buf[2:], p)
	var chunks [][]byte
	for len(buf) > 0 {
		chunk := make([]byte, chunkSize)
		copy(chunk, buf)
		buf = buf[min(chunkSize, len(buf)):]
		chunks = append(chunks, chunk)
	}
	return chunks
}

// decodeRDataMultiRR decodes multiple fixed-size RDATA chunks back to the
// original payload by concatenating them and reading the 2-byte length prefix.
func decodeRDataMultiRR(chunks [][]byte) ([]byte, error) {
	var buf bytes.Buffer
	for _, chunk := range chunks {
		buf.Write(chunk)
	}
	data := buf.Bytes()
	if len(data) < 2 {
		return nil, io.ErrUnexpectedEOF
	}
	n := int(binary.BigEndian.Uint16(data))
	data = data[2:]
	if len(data) < n {
		return nil, io.ErrUnexpectedEOF
	}
	return data[:n], nil
}

// EncodeRDataA encodes a payload as multiple A record RDATA chunks (4 bytes each).
func EncodeRDataA(p []byte) [][]byte { return encodeRDataMultiRR(p, 4) }

// DecodeRDataA decodes multiple A record RDATA chunks back to the original payload.
func DecodeRDataA(chunks [][]byte) ([]byte, error) { return decodeRDataMultiRR(chunks) }

// EncodeRDataAAAA encodes a payload as multiple AAAA record RDATA chunks (16 bytes each).
func EncodeRDataAAAA(p []byte) [][]byte { return encodeRDataMultiRR(p, 16) }

// DecodeRDataAAAA decodes multiple AAAA record RDATA chunks back to the original payload.
func DecodeRDataAAAA(chunks [][]byte) ([]byte, error) { return decodeRDataMultiRR(chunks) }
