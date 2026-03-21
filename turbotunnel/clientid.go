package turbotunnel

import (
	"crypto/rand"
	"encoding/hex"
)

// ClientID is an abstract identifier that binds together all the communications
// belonging to a single client session, even though those communications may
// arrive from multiple IP addresses or over multiple lower-level connections.
// It plays the same role that an (IP address, port number) tuple plays in a
// net.UDPConn: it's the return address pertaining to a long-lived abstract
// client session. The client attaches its ClientID to each of its
// communications, enabling the server to disambiguate requests among its many
// clients. ClientID implements the net.Addr interface.
//
// ClientID is backed by a string (immutable and comparable) so it can serve as
// a map key in RemoteMap while supporting variable sizes. The default size is
// 2 bytes; dnstt compatibility mode uses 8 bytes.
type ClientID string

// NewClientID generates a random ClientID of the given byte size.
func NewClientID(size int) ClientID {
	buf := make([]byte, size)
	_, err := rand.Read(buf)
	if err != nil {
		panic(err)
	}
	return ClientID(buf)
}

func (id ClientID) Network() string { return "clientid" }
func (id ClientID) String() string  { return hex.EncodeToString([]byte(id)) }

// Bytes returns the raw bytes of the ClientID.
func (id ClientID) Bytes() []byte { return []byte(id) }

// Len returns the byte length of the ClientID.
func (id ClientID) Len() int { return len(id) }
