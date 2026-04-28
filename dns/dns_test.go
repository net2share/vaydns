package dns

import (
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"
)

func namesEqual(a, b Name) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

func TestName(t *testing.T) {
	for _, test := range []struct {
		labels [][]byte
		err    error
		s      string
	}{
		{[][]byte{}, nil, "."},
		{[][]byte{[]byte("test")}, nil, "test"},
		{[][]byte{[]byte("a"), []byte("b"), []byte("c")}, nil, "a.b.c"},

		{[][]byte{{}}, ErrZeroLengthLabel, ""},
		{[][]byte{[]byte("a"), {}, []byte("c")}, ErrZeroLengthLabel, ""},

		// 63 octets.
		{[][]byte{[]byte("0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDE")}, nil,
			"0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDE"},
		// 64 octets.
		{[][]byte{[]byte("0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDEF")}, ErrLabelTooLong, ""},

		// 64+64+64+62 octets.
		{[][]byte{
			[]byte("0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDE"),
			[]byte("0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDE"),
			[]byte("0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDE"),
			[]byte("0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABC"),
		}, nil,
			"0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDE.0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDE.0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDE.0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABC"},
		// 64+64+64+63 octets.
		{[][]byte{
			[]byte("0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDE"),
			[]byte("0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDE"),
			[]byte("0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDE"),
			[]byte("0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCD"),
		}, ErrNameTooLong, ""},
		// 127 one-octet labels.
		{[][]byte{
			{'0'}, {'1'}, {'2'}, {'3'}, {'4'}, {'5'}, {'6'}, {'7'}, {'8'}, {'9'}, {'a'}, {'b'}, {'c'}, {'d'}, {'e'}, {'f'},
			{'0'}, {'1'}, {'2'}, {'3'}, {'4'}, {'5'}, {'6'}, {'7'}, {'8'}, {'9'}, {'A'}, {'B'}, {'C'}, {'D'}, {'E'}, {'F'},
			{'0'}, {'1'}, {'2'}, {'3'}, {'4'}, {'5'}, {'6'}, {'7'}, {'8'}, {'9'}, {'a'}, {'b'}, {'c'}, {'d'}, {'e'}, {'f'},
			{'0'}, {'1'}, {'2'}, {'3'}, {'4'}, {'5'}, {'6'}, {'7'}, {'8'}, {'9'}, {'A'}, {'B'}, {'C'}, {'D'}, {'E'}, {'F'},
			{'0'}, {'1'}, {'2'}, {'3'}, {'4'}, {'5'}, {'6'}, {'7'}, {'8'}, {'9'}, {'a'}, {'b'}, {'c'}, {'d'}, {'e'}, {'f'},
			{'0'}, {'1'}, {'2'}, {'3'}, {'4'}, {'5'}, {'6'}, {'7'}, {'8'}, {'9'}, {'A'}, {'B'}, {'C'}, {'D'}, {'E'}, {'F'},
			{'0'}, {'1'}, {'2'}, {'3'}, {'4'}, {'5'}, {'6'}, {'7'}, {'8'}, {'9'}, {'a'}, {'b'}, {'c'}, {'d'}, {'e'}, {'f'},
			{'0'}, {'1'}, {'2'}, {'3'}, {'4'}, {'5'}, {'6'}, {'7'}, {'8'}, {'9'}, {'A'}, {'B'}, {'C'}, {'D'}, {'E'},
		}, nil,
			"0.1.2.3.4.5.6.7.8.9.a.b.c.d.e.f.0.1.2.3.4.5.6.7.8.9.A.B.C.D.E.F.0.1.2.3.4.5.6.7.8.9.a.b.c.d.e.f.0.1.2.3.4.5.6.7.8.9.A.B.C.D.E.F.0.1.2.3.4.5.6.7.8.9.a.b.c.d.e.f.0.1.2.3.4.5.6.7.8.9.A.B.C.D.E.F.0.1.2.3.4.5.6.7.8.9.a.b.c.d.e.f.0.1.2.3.4.5.6.7.8.9.A.B.C.D.E"},
		// 128 one-octet labels.
		{[][]byte{
			{'0'}, {'1'}, {'2'}, {'3'}, {'4'}, {'5'}, {'6'}, {'7'}, {'8'}, {'9'}, {'a'}, {'b'}, {'c'}, {'d'}, {'e'}, {'f'},
			{'0'}, {'1'}, {'2'}, {'3'}, {'4'}, {'5'}, {'6'}, {'7'}, {'8'}, {'9'}, {'A'}, {'B'}, {'C'}, {'D'}, {'E'}, {'F'},
			{'0'}, {'1'}, {'2'}, {'3'}, {'4'}, {'5'}, {'6'}, {'7'}, {'8'}, {'9'}, {'a'}, {'b'}, {'c'}, {'d'}, {'e'}, {'f'},
			{'0'}, {'1'}, {'2'}, {'3'}, {'4'}, {'5'}, {'6'}, {'7'}, {'8'}, {'9'}, {'A'}, {'B'}, {'C'}, {'D'}, {'E'}, {'F'},
			{'0'}, {'1'}, {'2'}, {'3'}, {'4'}, {'5'}, {'6'}, {'7'}, {'8'}, {'9'}, {'a'}, {'b'}, {'c'}, {'d'}, {'e'}, {'f'},
			{'0'}, {'1'}, {'2'}, {'3'}, {'4'}, {'5'}, {'6'}, {'7'}, {'8'}, {'9'}, {'A'}, {'B'}, {'C'}, {'D'}, {'E'}, {'F'},
			{'0'}, {'1'}, {'2'}, {'3'}, {'4'}, {'5'}, {'6'}, {'7'}, {'8'}, {'9'}, {'a'}, {'b'}, {'c'}, {'d'}, {'e'}, {'f'},
			{'0'}, {'1'}, {'2'}, {'3'}, {'4'}, {'5'}, {'6'}, {'7'}, {'8'}, {'9'}, {'A'}, {'B'}, {'C'}, {'D'}, {'E'}, {'F'},
		}, ErrNameTooLong, ""},
	} {
		// Test that NewName returns proper error codes, and otherwise
		// returns an equal slice of labels.
		name, err := NewName(test.labels)
		if err != test.err || (err == nil && !namesEqual(name, test.labels)) {
			t.Errorf("%+q returned (%+q, %v), expected (%+q, %v)",
				test.labels, name, err, test.labels, test.err)
			continue
		}
		if test.err != nil {
			continue
		}

		// Test that the string version of the name comes out as
		// expected.
		s := name.String()
		if s != test.s {
			t.Errorf("%+q became string %+q, expected %+q", test.labels, s, test.s)
			continue
		}

		// Test that parsing from a string back to a Name results in the
		// original slice of labels.
		name, err = ParseName(s)
		if err != nil || !namesEqual(name, test.labels) {
			t.Errorf("%+q parsing %+q returned (%+q, %v), expected (%+q, %v)",
				test.labels, s, name, err, test.labels, nil)
			continue
		}
		// A trailing dot should be ignored.
		if !strings.HasSuffix(s, ".") {
			dotName, dotErr := ParseName(s + ".")
			if dotErr != err || !namesEqual(dotName, name) {
				t.Errorf("%+q parsing %+q returned (%+q, %v), expected (%+q, %v)",
					test.labels, s+".", dotName, dotErr, name, err)
				continue
			}
		}
	}
}

func TestParseName(t *testing.T) {
	for _, test := range []struct {
		s    string
		name Name
		err  error
	}{
		// This case can't be tested by TestName above because String
		// will never produce "" (it produces "." instead).
		{"", [][]byte{}, nil},
	} {
		name, err := ParseName(test.s)
		if err != test.err || (err == nil && !namesEqual(name, test.name)) {
			t.Errorf("%+q returned (%+q, %v), expected (%+q, %v)",
				test.s, name, err, test.name, test.err)
			continue
		}
	}
}

func unescapeString(s string) ([][]byte, error) {
	if s == "." {
		return [][]byte{}, nil
	}

	var result [][]byte
	for _, label := range strings.Split(s, ".") {
		var buf bytes.Buffer
		i := 0
		for i < len(label) {
			switch label[i] {
			case '\\':
				if i+3 >= len(label) {
					return nil, fmt.Errorf("truncated escape sequence at index %v", i)
				}
				if label[i+1] != 'x' {
					return nil, fmt.Errorf("malformed escape sequence at index %v", i)
				}
				b, err := strconv.ParseUint(string(label[i+2:i+4]), 16, 8)
				if err != nil {
					return nil, fmt.Errorf("malformed hex sequence at index %v", i+2)
				}
				buf.WriteByte(byte(b))
				i += 4
			default:
				buf.WriteByte(label[i])
				i++
			}
		}
		result = append(result, buf.Bytes())
	}
	return result, nil
}

func TestNameString(t *testing.T) {
	for _, test := range []struct {
		name Name
		s    string
	}{
		{[][]byte{}, "."},
		{[][]byte{[]byte("\x00"), []byte("a.b"), []byte("c\nd\\")}, "\\x00.a\\x2eb.c\\x0ad\\x5c"},
		{[][]byte{
			[]byte("\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !\"#$%&'()*+,-./0123456789:;<=>"),
			[]byte("?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}"),
			[]byte("~\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc"),
			[]byte("\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb"),
			[]byte("\xfc\xfd\xfe\xff"),
		}, "\\x00\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08\\x09\\x0a\\x0b\\x0c\\x0d\\x0e\\x0f\\x10\\x11\\x12\\x13\\x14\\x15\\x16\\x17\\x18\\x19\\x1a\\x1b\\x1c\\x1d\\x1e\\x1f\\x20\\x21\\x22\\x23\\x24\\x25\\x26\\x27\\x28\\x29\\x2a\\x2b\\x2c-\\x2e\\x2f0123456789\\x3a\\x3b\\x3c\\x3d\\x3e.\\x3f\\x40ABCDEFGHIJKLMNOPQRSTUVWXYZ\\x5b\\x5c\\x5d\\x5e\\x5f\\x60abcdefghijklmnopqrstuvwxyz\\x7b\\x7c\\x7d.\\x7e\\x7f\\x80\\x81\\x82\\x83\\x84\\x85\\x86\\x87\\x88\\x89\\x8a\\x8b\\x8c\\x8d\\x8e\\x8f\\x90\\x91\\x92\\x93\\x94\\x95\\x96\\x97\\x98\\x99\\x9a\\x9b\\x9c\\x9d\\x9e\\x9f\\xa0\\xa1\\xa2\\xa3\\xa4\\xa5\\xa6\\xa7\\xa8\\xa9\\xaa\\xab\\xac\\xad\\xae\\xaf\\xb0\\xb1\\xb2\\xb3\\xb4\\xb5\\xb6\\xb7\\xb8\\xb9\\xba\\xbb\\xbc.\\xbd\\xbe\\xbf\\xc0\\xc1\\xc2\\xc3\\xc4\\xc5\\xc6\\xc7\\xc8\\xc9\\xca\\xcb\\xcc\\xcd\\xce\\xcf\\xd0\\xd1\\xd2\\xd3\\xd4\\xd5\\xd6\\xd7\\xd8\\xd9\\xda\\xdb\\xdc\\xdd\\xde\\xdf\\xe0\\xe1\\xe2\\xe3\\xe4\\xe5\\xe6\\xe7\\xe8\\xe9\\xea\\xeb\\xec\\xed\\xee\\xef\\xf0\\xf1\\xf2\\xf3\\xf4\\xf5\\xf6\\xf7\\xf8\\xf9\\xfa\\xfb.\\xfc\\xfd\\xfe\\xff"},
	} {
		s := test.name.String()
		if s != test.s {
			t.Errorf("%+q escaped to %+q, expected %+q", test.name, s, test.s)
			continue
		}
		unescaped, err := unescapeString(s)
		if err != nil {
			t.Errorf("%+q unescaping %+q resulted in error %v", test.name, s, err)
			continue
		}
		if !namesEqual(Name(unescaped), test.name) {
			t.Errorf("%+q roundtripped through %+q to %+q", test.name, s, unescaped)
			continue
		}
	}
}

func TestNameTrimSuffix(t *testing.T) {
	for _, test := range []struct {
		name, suffix string
		trimmed      string
		ok           bool
	}{
		{"", "", ".", true},
		{".", ".", ".", true},
		{"abc", "", "abc", true},
		{"abc", ".", "abc", true},
		{"", "abc", ".", false},
		{".", "abc", ".", false},
		{"example.com", "com", "example", true},
		{"example.com", "net", ".", false},
		{"example.com", "example.com", ".", true},
		{"example.com", "test.com", ".", false},
		{"example.com", "xample.com", ".", false},
		{"example.com", "example", ".", false},
		{"example.com", "COM", "example", true},
		{"EXAMPLE.COM", "com", "EXAMPLE", true},
	} {
		tmp, ok := mustParseName(test.name).TrimSuffix(mustParseName(test.suffix))
		trimmed := tmp.String()
		if ok != test.ok || trimmed != test.trimmed {
			t.Errorf("TrimSuffix %+q %+q returned (%+q, %v), expected (%+q, %v)",
				test.name, test.suffix, trimmed, ok, test.trimmed, test.ok)
			continue
		}
	}
}

func TestReadName(t *testing.T) {
	// Good tests.
	for _, test := range []struct {
		start int64
		end   int64
		input string
		s     string
	}{
		// Empty name.
		{0, 1, "\x00abcd", "."},
		// No pointers.
		{12, 25, "AAAABBBBCCCC\x07example\x03com\x00", "example.com"},
		// Backward pointer.
		{25, 31, "AAAABBBBCCCC\x07example\x03com\x00\x03sub\xc0\x0c", "sub.example.com"},
		// Forward pointer.
		{0, 4, "\x01a\xc0\x04\x03bcd\x00", "a.bcd"},
		// Two backwards pointers.
		{31, 38, "AAAABBBBCCCC\x07example\x03com\x00\x03sub\xc0\x0c\x04sub2\xc0\x19", "sub2.sub.example.com"},
		// Forward then backward pointer.
		{25, 31, "AAAABBBBCCCC\x07example\x03com\x00\x03sub\xc0\x1f\x04sub2\xc0\x0c", "sub.sub2.example.com"},
		// Overlapping codons.
		{0, 4, "\x01a\xc0\x03bcd\x00", "a.bcd"},
		// Pointer to empty label.
		{0, 10, "\x07example\xc0\x0a\x00", "example"},
		{1, 11, "\x00\x07example\xc0\x00", "example"},
		// Pointer to pointer to empty label.
		{0, 10, "\x07example\xc0\x0a\xc0\x0c\x00", "example"},
		{1, 11, "\x00\x07example\xc0\x0c\xc0\x00", "example"},
	} {
		r := bytes.NewReader([]byte(test.input))
		_, err := r.Seek(test.start, io.SeekStart)
		if err != nil {
			panic(err)
		}
		name, err := readName(r)
		if err != nil {
			t.Errorf("%+q returned error %s", test.input, err)
			continue
		}
		s := name.String()
		if s != test.s {
			t.Errorf("%+q returned %+q, expected %+q", test.input, s, test.s)
			continue
		}
		cur, _ := r.Seek(0, io.SeekCurrent)
		if cur != test.end {
			t.Errorf("%+q left offset %d, expected %d", test.input, cur, test.end)
			continue
		}
	}

	// Bad tests.
	for _, test := range []struct {
		start int64
		input string
		err   error
	}{
		{0, "", io.ErrUnexpectedEOF},
		// Reserved label type.
		{0, "\x80example", ErrReservedLabelType},
		// Reserved label type.
		{0, "\x40example", ErrReservedLabelType},
		// No Terminating empty label.
		{0, "\x07example\x03com", io.ErrUnexpectedEOF},
		// Pointer past end of buffer.
		{0, "\x07example\xc0\xff", io.ErrUnexpectedEOF},
		// Pointer to self.
		{0, "\x07example\x03com\xc0\x0c", ErrTooManyPointers},
		// Pointer to self with intermediate label.
		{0, "\x07example\x03com\xc0\x08", ErrTooManyPointers},
		// Two pointers that point to each other.
		{0, "\xc0\x02\xc0\x00", ErrTooManyPointers},
		// Two pointers that point to each other, with intermediate labels.
		{0, "\x01a\xc0\x04\x01b\xc0\x00", ErrTooManyPointers},
		// EOF while reading label.
		{0, "\x0aexample", io.ErrUnexpectedEOF},
		// EOF before second byte of pointer.
		{0, "\xc0", io.ErrUnexpectedEOF},
		{0, "\x07example\xc0", io.ErrUnexpectedEOF},
	} {
		r := bytes.NewReader([]byte(test.input))
		_, err := r.Seek(test.start, io.SeekStart)
		if err != nil {
			panic(err)
		}
		name, err := readName(r)
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		if err != test.err {
			t.Errorf("%+q returned (%+q, %v), expected %v", test.input, name, err, test.err)
			continue
		}
	}
}

func mustParseName(s string) Name {
	name, err := ParseName(s)
	if err != nil {
		panic(err)
	}
	return name
}

func questionsEqual(a, b *Question) bool {
	if !namesEqual(a.Name, b.Name) {
		return false
	}
	if a.Type != b.Type || a.Class != b.Class {
		return false
	}
	return true
}

func rrsEqual(a, b *RR) bool {
	if !namesEqual(a.Name, b.Name) {
		return false
	}
	if a.Type != b.Type || a.Class != b.Class || a.TTL != b.TTL {
		return false
	}
	if !bytes.Equal(a.Data, b.Data) {
		return false
	}
	return true
}

func messagesEqual(a, b *Message) bool {
	if a.ID != b.ID || a.Flags != b.Flags {
		return false
	}
	if len(a.Question) != len(b.Question) {
		return false
	}
	for i := 0; i < len(a.Question); i++ {
		if !questionsEqual(&a.Question[i], &b.Question[i]) {
			return false
		}
	}
	for _, rec := range []struct{ rrA, rrB []RR }{
		{a.Answer, b.Answer},
		{a.Authority, b.Authority},
		{a.Additional, b.Additional},
	} {
		if len(rec.rrA) != len(rec.rrB) {
			return false
		}
		for i := 0; i < len(rec.rrA); i++ {
			if !rrsEqual(&rec.rrA[i], &rec.rrB[i]) {
				return false
			}
		}
	}
	return true
}

func TestMessageFromWireFormat(t *testing.T) {
	for _, test := range []struct {
		buf      string
		expected Message
		err      error
	}{
		{
			"\x12\x34",
			Message{},
			io.ErrUnexpectedEOF,
		},
		{
			"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01",
			Message{
				ID:    0x1234,
				Flags: 0x0100,
				Question: []Question{
					{
						Name:  mustParseName("www.example.com"),
						Type:  1,
						Class: 1,
					},
				},
				Answer:     []RR{},
				Authority:  []RR{},
				Additional: []RR{},
			},
			nil,
		},
		{
			"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01X",
			Message{},
			ErrTrailingBytes,
		},
		{
			"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01\x03www\x07example\x03com\x00\x00\x01\x00\x01\x00\x00\x00\x80\x00\x04\xc0\x00\x02\x01",
			Message{
				ID:    0x1234,
				Flags: 0x8180,
				Question: []Question{
					{
						Name:  mustParseName("www.example.com"),
						Type:  1,
						Class: 1,
					},
				},
				Answer: []RR{
					{
						Name:  mustParseName("www.example.com"),
						Type:  1,
						Class: 1,
						TTL:   128,
						Data:  []byte{192, 0, 2, 1},
					},
				},
				Authority:  []RR{},
				Additional: []RR{},
			},
			nil,
		},
	} {
		message, err := MessageFromWireFormat([]byte(test.buf))
		if err != test.err || (err == nil && !messagesEqual(&message, &test.expected)) {
			t.Errorf("%+q\nreturned (%+v, %v)\nexpected (%+v, %v)",
				test.buf, message, err, test.expected, test.err)
			continue
		}
	}
}

func TestMessageWireFormatRoundTrip(t *testing.T) {
	for _, message := range []Message{
		{
			ID:    0x1234,
			Flags: 0x0100,
			Question: []Question{
				{
					Name:  mustParseName("www.example.com"),
					Type:  1,
					Class: 1,
				},
				{
					Name:  mustParseName("www2.example.com"),
					Type:  2,
					Class: 2,
				},
			},
			Answer: []RR{
				{
					Name:  mustParseName("abc"),
					Type:  2,
					Class: 3,
					TTL:   0xffffffff,
					Data:  []byte{1},
				},
				{
					Name:  mustParseName("xyz"),
					Type:  2,
					Class: 3,
					TTL:   255,
					Data:  []byte{},
				},
			},
			Authority: []RR{
				{
					Name:  mustParseName("."),
					Type:  65535,
					Class: 65535,
					TTL:   0,
					Data:  []byte("XXXXXXXXXXXXXXXXXXX"),
				},
			},
			Additional: []RR{},
		},
	} {
		buf, err := message.WireFormat()
		if err != nil {
			t.Errorf("%+v cannot make wire format: %v", message, err)
			continue
		}
		message2, err := MessageFromWireFormat(buf)
		if err != nil {
			t.Errorf("%+q cannot parse wire format: %v", buf, err)
			continue
		}
		if !messagesEqual(&message, &message2) {
			t.Errorf("messages unequal\nbefore: %+v\n after: %+v", message, message2)
			continue
		}
	}
}

func TestDecodeRDataTXT(t *testing.T) {
	for _, test := range []struct {
		p       []byte
		decoded []byte
		err     error
	}{
		{[]byte{}, nil, io.ErrUnexpectedEOF},
		{[]byte("\x00"), []byte{}, nil},
		{[]byte("\x01"), nil, io.ErrUnexpectedEOF},
	} {
		decoded, err := DecodeRDataTXT(test.p)
		if err != test.err || (err == nil && !bytes.Equal(decoded, test.decoded)) {
			t.Errorf("%+q\nreturned (%+q, %v)\nexpected (%+q, %v)",
				test.p, decoded, err, test.decoded, test.err)
			continue
		}
	}
}

func TestEncodeRDataTXT(t *testing.T) {
	// Encoding 0 bytes needs to return at least a single length octet of
	// zero, not an empty slice.
	p := make([]byte, 0)
	encoded := EncodeRDataTXT(p)
	if len(encoded) < 0 {
		t.Errorf("EncodeRDataTXT(%v) returned %v", p, encoded)
	}

	// 255 bytes should be able to be encoded into 256 bytes.
	p = make([]byte, 255)
	encoded = EncodeRDataTXT(p)
	if len(encoded) > 256 {
		t.Errorf("EncodeRDataTXT(%d bytes) returned %d bytes", len(p), len(encoded))
	}
}

func TestRDataTXTRoundTrip(t *testing.T) {
	for _, p := range [][]byte{
		{},
		[]byte("\x00"),
		{
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
			0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
			0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
			0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
			0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
			0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
			0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
			0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
			0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
			0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
			0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
			0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
			0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
			0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
			0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
		},
	} {
		rdata := EncodeRDataTXT(p)
		decoded, err := DecodeRDataTXT(rdata)
		if err != nil || !bytes.Equal(decoded, p) {
			t.Errorf("%+q returned (%+q, %v)", p, decoded, err)
			continue
		}
	}
}

func TestNameWireFormatRoundTrip(t *testing.T) {
	for _, test := range []struct {
		labels [][]byte
	}{
		{[][]byte{}},
		{[][]byte{[]byte("example"), []byte("com")}},
		{[][]byte{[]byte("a"), []byte("b"), []byte("c")}},
		{[][]byte{[]byte("0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDE")}},
	} {
		name, err := NewName(test.labels)
		if err != nil {
			t.Fatalf("NewName(%v): %v", test.labels, err)
		}
		wire := name.WireFormat()
		parsed, err := NameFromWireFormat(wire)
		if err != nil {
			t.Errorf("NameFromWireFormat(%x): %v", wire, err)
			continue
		}
		if !namesEqual(name, parsed) {
			t.Errorf("round-trip failed: %v != %v", name, parsed)
		}
	}
}

func TestEncodeDecodeRDataCNAME(t *testing.T) {
	domain, err := ParseName("t.example.com")
	if err != nil {
		t.Fatal(err)
	}

	for _, p := range [][]byte{
		{},
		{0x01},
		{0x01, 0x02, 0x03},
		[]byte("hello world, this is a test of CNAME encoding"),
		// ~100 bytes
		bytes.Repeat([]byte{0xab}, 100),
	} {
		rdata, err := EncodeRDataCNAME(p, domain)
		if err != nil {
			t.Errorf("EncodeRDataCNAME(%x): %v", p, err)
			continue
		}
		decoded, err := DecodeRDataCNAME(rdata, domain)
		if err != nil {
			t.Errorf("DecodeRDataCNAME(%x): %v", rdata, err)
			continue
		}
		if !bytes.Equal(decoded, p) {
			t.Errorf("round-trip failed for %x: got %x", p, decoded)
		}
	}
}

func TestReadRRCNAMECompression(t *testing.T) {
	// Construct a DNS message with a CNAME answer that uses a compression
	// pointer. The CNAME target is "www.example.com" where "example.com"
	// is referenced via a compression pointer to the question name.

	// Question: example.com IN CNAME
	// Answer: example.com CNAME www.example.com (with compression)
	msg := []byte{
		// Header
		0x00, 0x01, // ID
		0x81, 0x80, // Flags: QR=1, RD=1, RA=1
		0x00, 0x01, // QDCOUNT=1
		0x00, 0x01, // ANCOUNT=1
		0x00, 0x00, // NSCOUNT=0
		0x00, 0x00, // ARCOUNT=0
		// Question: example.com
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', // label "example"
		0x03, 'c', 'o', 'm', // label "com"
		0x00,       // root
		0x00, 0x05, // QTYPE=CNAME
		0x00, 0x01, // QCLASS=IN
		// Answer: example.com CNAME www.example.com
		0xc0, 0x0c, // Name: compression pointer to offset 12 (example.com)
		0x00, 0x05, // TYPE=CNAME
		0x00, 0x01, // CLASS=IN
		0x00, 0x00, 0x0e, 0x10, // TTL=3600
		0x00, 0x06, // RDLENGTH=6
		// RDATA: www.example.com with compression
		0x03, 'w', 'w', 'w', // label "www"
		0xc0, 0x0c, // compression pointer to offset 12 (example.com)
	}

	parsed, err := MessageFromWireFormat(msg)
	if err != nil {
		t.Fatalf("MessageFromWireFormat: %v", err)
	}

	if len(parsed.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(parsed.Answer))
	}

	answer := parsed.Answer[0]
	if answer.Type != RRTypeCNAME {
		t.Fatalf("expected CNAME type, got %d", answer.Type)
	}

	// The Data should be the uncompressed wire format of "www.example.com"
	expected := Name([][]byte{[]byte("www"), []byte("example"), []byte("com")})
	expectedWire := expected.WireFormat()
	if !bytes.Equal(answer.Data, expectedWire) {
		t.Errorf("CNAME RDATA: got %x, want %x", answer.Data, expectedWire)
	}
}

func TestEncodeDecodeRDataNS(t *testing.T) {
	domain, _ := ParseName("t.example.com")
	for _, p := range [][]byte{{}, {0x01}, bytes.Repeat([]byte{0xcd}, 80)} {
		rdata, err := EncodeRDataNS(p, domain)
		if err != nil {
			t.Errorf("EncodeRDataNS(%x): %v", p, err)
			continue
		}
		decoded, err := DecodeRDataNS(rdata, domain)
		if err != nil {
			t.Errorf("DecodeRDataNS: %v", err)
			continue
		}
		if !bytes.Equal(decoded, p) {
			t.Errorf("NS round-trip failed for %x: got %x", p, decoded)
		}
	}
}

func TestEncodeDecodeRDataMX(t *testing.T) {
	domain, _ := ParseName("t.example.com")
	for _, p := range [][]byte{{}, {0x01}, bytes.Repeat([]byte{0xab}, 80)} {
		rdata, err := EncodeRDataMX(p, domain)
		if err != nil {
			t.Errorf("EncodeRDataMX(%x): %v", p, err)
			continue
		}
		decoded, err := DecodeRDataMX(rdata, domain)
		if err != nil {
			t.Errorf("DecodeRDataMX: %v", err)
			continue
		}
		if !bytes.Equal(decoded, p) {
			t.Errorf("MX round-trip failed for %x: got %x", p, decoded)
		}
	}
}

func TestEncodeDecodeRDataSRV(t *testing.T) {
	domain, _ := ParseName("t.example.com")
	for _, p := range [][]byte{{}, {0x01}, bytes.Repeat([]byte{0xef}, 80)} {
		rdata, err := EncodeRDataSRV(p, domain)
		if err != nil {
			t.Errorf("EncodeRDataSRV(%x): %v", p, err)
			continue
		}
		decoded, err := DecodeRDataSRV(rdata, domain)
		if err != nil {
			t.Errorf("DecodeRDataSRV: %v", err)
			continue
		}
		if !bytes.Equal(decoded, p) {
			t.Errorf("SRV round-trip failed for %x: got %x", p, decoded)
		}
	}
}

func TestEncodeDecodeRDataA(t *testing.T) {
	for _, p := range [][]byte{
		{},
		{0x01},
		{0x01, 0x02, 0x03, 0x04, 0x05},
		bytes.Repeat([]byte{0xab}, 100),
	} {
		chunks := EncodeRDataA(p)
		for _, chunk := range chunks {
			if len(chunk) != 4 {
				t.Errorf("A chunk length %d != 4", len(chunk))
			}
		}
		decoded, err := DecodeRDataA(chunks)
		if err != nil {
			t.Errorf("DecodeRDataA: %v", err)
			continue
		}
		if !bytes.Equal(decoded, p) {
			t.Errorf("A round-trip failed for len=%d: got len=%d", len(p), len(decoded))
		}
	}
}

func TestEncodeDecodeRDataAAAA(t *testing.T) {
	for _, p := range [][]byte{
		{},
		{0x01},
		bytes.Repeat([]byte{0xab}, 50),
		bytes.Repeat([]byte{0xcd}, 200),
	} {
		chunks := EncodeRDataAAAA(p)
		for _, chunk := range chunks {
			if len(chunk) != 16 {
				t.Errorf("AAAA chunk length %d != 16", len(chunk))
			}
		}
		decoded, err := DecodeRDataAAAA(chunks)
		if err != nil {
			t.Errorf("DecodeRDataAAAA: %v", err)
			continue
		}
		if !bytes.Equal(decoded, p) {
			t.Errorf("AAAA round-trip failed for len=%d: got len=%d", len(p), len(decoded))
		}
	}
}

func TestEncodeDecodeRDataNULL(t *testing.T) {
	for _, p := range [][]byte{
		{},
		{0x00},
		{0x01, 0x02, 0x03},
		bytes.Repeat([]byte{0xab}, 100),
		bytes.Repeat([]byte{0xff}, 1000),
	} {
		rdata := EncodeRDataNULL(p)
		decoded, err := DecodeRDataNULL(rdata)
		if err != nil {
			t.Errorf("DecodeRDataNULL(%x): %v", rdata, err)
			continue
		}
		if !bytes.Equal(decoded, p) {
			t.Errorf("NULL round-trip failed for len=%d: got len=%d", len(p), len(decoded))
		}
	}
}

func TestRDataNULLIdentity(t *testing.T) {
	// NULL encode/decode should be identity — no framing overhead.
	p := []byte{0x01, 0x02, 0x03}
	if !bytes.Equal(EncodeRDataNULL(p), p) {
		t.Error("EncodeRDataNULL should return input unchanged")
	}
	decoded, _ := DecodeRDataNULL(p)
	if !bytes.Equal(decoded, p) {
		t.Error("DecodeRDataNULL should return input unchanged")
	}
}

func TestDecodeRDataCAA(t *testing.T) {
	for _, test := range []struct {
		desc    string
		p       []byte
		decoded []byte
		err     error
	}{
		{"empty input", []byte{}, nil, io.ErrUnexpectedEOF},
		{"single byte", []byte{0x00}, nil, io.ErrUnexpectedEOF},
		{"tag length exceeds data", []byte{0x00, 0x05, 'a'}, nil, io.ErrUnexpectedEOF},
		{"tag only, no value", []byte{0x00, 0x05, 'i', 's', 's', 'u', 'e'}, []byte{}, nil},
		{"tag + value", []byte{0x00, 0x05, 'i', 's', 's', 'u', 'e', 0xaa, 0xbb}, []byte{0xaa, 0xbb}, nil},
		{"zero-length tag", []byte{0x00, 0x00, 0x01, 0x02}, []byte{0x01, 0x02}, nil},
		{"flags byte ignored", []byte{0x80, 0x05, 'i', 's', 's', 'u', 'e', 0xff}, []byte{0xff}, nil},
	} {
		decoded, err := DecodeRDataCAA(test.p)
		if err != test.err {
			t.Errorf("%s: got err %v, want %v", test.desc, err, test.err)
			continue
		}
		if err == nil && !bytes.Equal(decoded, test.decoded) {
			t.Errorf("%s: got %x, want %x", test.desc, decoded, test.decoded)
		}
	}
}

func TestEncodeRDataCAA(t *testing.T) {
	p := []byte{0x01, 0x02, 0x03}
	rdata := EncodeRDataCAA(p)
	// Expected: flags(0) + tagLen(5) + "issue" + payload
	expected := append([]byte{0x00, 0x05, 'i', 's', 's', 'u', 'e'}, p...)
	if !bytes.Equal(rdata, expected) {
		t.Errorf("EncodeRDataCAA(%x) = %x, want %x", p, rdata, expected)
	}
}

func TestEncodeRDataCAAEmpty(t *testing.T) {
	rdata := EncodeRDataCAA([]byte{})
	// Even with empty payload, should have flags + tagLen + tag.
	if len(rdata) != 7 {
		t.Errorf("EncodeRDataCAA(empty) length = %d, want 7", len(rdata))
	}
}

func TestRDataCAARoundTrip(t *testing.T) {
	for _, p := range [][]byte{
		{},
		{0x00},
		{0x01, 0x02, 0x03},
		bytes.Repeat([]byte{0xab}, 100),
		bytes.Repeat([]byte{0xff}, 1000),
	} {
		rdata := EncodeRDataCAA(p)
		decoded, err := DecodeRDataCAA(rdata)
		if err != nil {
			t.Errorf("CAA round-trip decode error for len=%d: %v", len(p), err)
			continue
		}
		if !bytes.Equal(decoded, p) {
			t.Errorf("CAA round-trip failed for len=%d: got len=%d", len(p), len(decoded))
		}
	}
}

func TestReadRRMXCompression(t *testing.T) {
	// DNS message with MX answer using compression pointer in exchange name.
	msg := []byte{
		// Header
		0x00, 0x01, 0x81, 0x80,
		0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		// Question: example.com
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
		0x00, 0x0f, // QTYPE=MX
		0x00, 0x01,
		// Answer: example.com MX 10 mail.example.com
		0xc0, 0x0c, // compression pointer to example.com
		0x00, 0x0f, // TYPE=MX
		0x00, 0x01, // CLASS=IN
		0x00, 0x00, 0x0e, 0x10, // TTL
		0x00, 0x09, // RDLENGTH=9
		// RDATA: preference=10, exchange=mail.example.com (compressed)
		0x00, 0x0a, // preference
		0x04, 'm', 'a', 'i', 'l', // label "mail"
		0xc0, 0x0c, // compression pointer to example.com
	}

	parsed, err := MessageFromWireFormat(msg)
	if err != nil {
		t.Fatalf("MessageFromWireFormat: %v", err)
	}
	if len(parsed.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(parsed.Answer))
	}
	answer := parsed.Answer[0]
	if answer.Type != RRTypeMX {
		t.Fatalf("expected MX type, got %d", answer.Type)
	}
	// Data should be: preference(2) + uncompressed wire format of "mail.example.com"
	expectedName := Name([][]byte{[]byte("mail"), []byte("example"), []byte("com")})
	expectedData := append([]byte{0x00, 0x0a}, expectedName.WireFormat()...)
	if !bytes.Equal(answer.Data, expectedData) {
		t.Errorf("MX RDATA: got %x, want %x", answer.Data, expectedData)
	}
}

func TestReadRRSRVCompression(t *testing.T) {
	// DNS message with SRV answer using compression pointer in target name.
	msg := []byte{
		// Header
		0x00, 0x01, 0x81, 0x80,
		0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		// Question: example.com
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
		0x00, 0x21, // QTYPE=SRV
		0x00, 0x01,
		// Answer: example.com SRV 0 0 443 web.example.com
		0xc0, 0x0c,
		0x00, 0x21, // TYPE=SRV
		0x00, 0x01,
		0x00, 0x00, 0x0e, 0x10,
		0x00, 0x0c, // RDLENGTH=12
		// RDATA
		0x00, 0x00, // priority
		0x00, 0x00, // weight
		0x01, 0xbb, // port=443
		0x03, 'w', 'e', 'b', // label "web"
		0xc0, 0x0c, // compression pointer
	}

	parsed, err := MessageFromWireFormat(msg)
	if err != nil {
		t.Fatalf("MessageFromWireFormat: %v", err)
	}
	answer := parsed.Answer[0]
	if answer.Type != RRTypeSRV {
		t.Fatalf("expected SRV type, got %d", answer.Type)
	}
	expectedName := Name([][]byte{[]byte("web"), []byte("example"), []byte("com")})
	expectedData := append([]byte{0x00, 0x00, 0x00, 0x00, 0x01, 0xbb}, expectedName.WireFormat()...)
	if !bytes.Equal(answer.Data, expectedData) {
		t.Errorf("SRV RDATA: got %x, want %x", answer.Data, expectedData)
	}
}
