package client

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/net2share/vaydns/dns"
	"github.com/net2share/vaydns/turbotunnel"
)

const (
	// pollNonceLen is the number of random bytes appended to poll queries
	// for cache busting. Without this, empty polls would be identical and
	// recursive resolvers would return cached (stale) responses.
	pollNonceLen = 4

	// sendLoop has a poll timer that automatically sends an empty polling
	// query when a certain amount of time has elapsed without a send. The
	// poll timer is initially set to initPollDelay. It increases by a
	// factor of pollDelayMultiplier every time the poll timer expires, up
	// to a maximum of maxPollDelay. The poll timer is reset to
	// initPollDelay whenever an a send occurs that is not the result of the
	// poll timer expiring.
	initPollDelay       = 500 * time.Millisecond
	maxPollDelay        = 10 * time.Second
	pollDelayMultiplier = 2.0

	// A limit on the number of empty poll requests we may send in a burst
	// as a result of receiving data.
	pollLimit = 16
)

// base32Encoding is a base32 encoding without padding.
var base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// forgedInfoMilestones defines the exact totals at which an INFO log is
// emitted. After the last explicit milestone the interval logic in
// forgedInfoMilestone takes over.
var forgedInfoMilestones = [...]uint64{10, 100, 500, 1000, 2500, 5000}

// RateLimiter implements a token bucket rate limiter for DNS queries.
type RateLimiter struct {
	mu       sync.Mutex
	tokens   float64
	capacity float64
	rate     float64 // tokens per second
	lastTime time.Time
}

// NewRateLimiter creates a new token bucket rate limiter with the given
// queries-per-second rate. Returns nil for non-positive or invalid values,
// which means unlimited.
func NewRateLimiter(rps float64) *RateLimiter {
	if rps <= 0 || math.IsNaN(rps) || math.IsInf(rps, 0) {
		return nil
	}
	return &RateLimiter{
		tokens:   rps,
		capacity: rps,
		rate:     rps,
		lastTime: time.Now(),
	}
}

// Wait blocks until a token is available. It is safe to call on a nil receiver
// (no-op), which allows clean "unlimited" behavior without nil checks at call sites.
func (rl *RateLimiter) Wait() {
	if rl == nil {
		return
	}
	for {
		rl.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(rl.lastTime).Seconds()
		rl.lastTime = now
		rl.tokens += elapsed * rl.rate
		if rl.tokens > rl.capacity {
			rl.tokens = rl.capacity
		}
		if rl.tokens >= 1.0 {
			rl.tokens -= 1.0
			rl.mu.Unlock()
			return
		}
		needed := 1.0 - rl.tokens
		waitTime := time.Duration(needed / rl.rate * float64(time.Second))
		rl.mu.Unlock()
		time.Sleep(waitTime)
	}
}

// ForgedStats tracks forged DNS response counters. It is shared between
// UDPPacketConn (per-query mode) and DNSPacketConn (shared socket mode) so
// that forged response visibility is consistent regardless of transport.
type ForgedStats struct {
	Total    uint64
	SERVFAIL uint64
	NXDOMAIN uint64
	Other    uint64
}

// Record increments the appropriate counter for the given RCODE and logs
// a summary at INFO level at milestone counts. Non-milestone forged
// responses are silently counted.
func (s *ForgedStats) Record(rcode uint16) {
	switch rcode {
	case dns.RcodeServerFailure:
		atomic.AddUint64(&s.SERVFAIL, 1)
	case dns.RcodeNameError:
		atomic.AddUint64(&s.NXDOMAIN, 1)
	default:
		atomic.AddUint64(&s.Other, 1)
	}
	total := atomic.AddUint64(&s.Total, 1)
	if forgedInfoMilestone(total) {
		log.Infof("forged DNS responses: total=%d, SERVFAIL=%d, NXDOMAIN=%d, other=%d",
			total,
			atomic.LoadUint64(&s.SERVFAIL),
			atomic.LoadUint64(&s.NXDOMAIN),
			atomic.LoadUint64(&s.Other))
	}
}

func forgedInfoMilestone(total uint64) bool {
	for _, m := range forgedInfoMilestones {
		if total == m {
			return true
		}
	}
	switch {
	case total <= 100_000:
		return total%10_000 == 0
	case total <= 1_000_000:
		return total%50_000 == 0
	default:
		return total%100_000 == 0
	}
}

// DNSPacketConn provides a packet-sending and -receiving interface over various
// forms of DNS. It handles the details of how packets and padding are encoded
// as a DNS name in the Question section of an upstream query, and as a TXT RR
// in downstream responses.
//
// DNSPacketConn does not handle the mechanics of actually sending and receiving
// encoded DNS messages. That is rather the responsibility of some other
// net.PacketConn such as net.UDPConn, HTTPPacketConn, or TLSPacketConn, one of
// which must be provided to NewDNSPacketConn.
//
// We don't have a need to match up a query and a response by ID. Queries and
// responses are vehicles for carrying data and for our purposes don't need to
// be correlated. When sending a query, we generate a random ID, and when
// receiving a response, we ignore the ID.
type DNSPacketConn struct {
	clientID   turbotunnel.ClientID
	wireConfig turbotunnel.WireConfig
	domain     dns.Name
	// rrType is the DNS record type used for downstream data (TXT, CNAME, A, AAAA, MX, NS, or SRV).
	rrType uint16
	// Sending on pollChan permits sendLoop to send an empty polling query.
	// sendLoop also does its own polling according to a time schedule.
	pollChan chan struct{}
	// rateLimiter throttles outgoing DNS queries (nil = unlimited).
	rateLimiter *RateLimiter
	// maxQnameLen is the maximum total QNAME length in wire format (0 = 253 per RFC).
	maxQnameLen int
	// maxNumLabels is the maximum number of data labels (0 = unlimited).
	maxNumLabels int
	// Forged response tracking (shared with UDPPacketConn in per-query mode)
	forgedStats *ForgedStats
	// Transport error reporting for session health monitoring
	transportErr chan error
	// QueuePacketConn is the direct receiver of ReadFrom and WriteTo calls.
	// recvLoop and sendLoop take the messages out of the receive and send
	// queues and actually put them on the network.
	*turbotunnel.QueuePacketConn
}

// NewDNSPacketConn creates a new DNSPacketConn. transport, through its WriteTo
// and ReadFrom methods, handles the actual sending and receiving the DNS
// messages encoded by DNSPacketConn. addr is the address to be passed to
// transport.WriteTo whenever a message needs to be sent.
// maxQnameLen is the max total QNAME length (0 = 253 per RFC 1035).
// maxNumLabels is the max number of data labels (0 = unlimited).
// forgedStats is shared with the transport layer (e.g. UDPPacketConn) for
// consistent forged response tracking; if nil, a new instance is created.
func NewDNSPacketConn(transport net.PacketConn, addr net.Addr, domain dns.Name, rateLimiter *RateLimiter, maxQnameLen int, maxNumLabels int, wireConfig turbotunnel.WireConfig, forgedStats *ForgedStats, rrType uint16, queueSize int) *DNSPacketConn {
	if maxQnameLen <= 0 || maxQnameLen > 253 {
		maxQnameLen = 253
	}
	if forgedStats == nil {
		forgedStats = &ForgedStats{}
	}
	// Generate a new random ClientID.
	clientID := turbotunnel.NewClientID(wireConfig.ClientIDSize)
	if rrType == 0 {
		rrType = dns.RRTypeTXT
	}
	c := &DNSPacketConn{
		clientID:        clientID,
		wireConfig:      wireConfig,
		domain:          domain,
		rrType:          rrType,
		pollChan:        make(chan struct{}, pollLimit),
		rateLimiter:     rateLimiter,
		maxQnameLen:     maxQnameLen,
		maxNumLabels:    maxNumLabels,
		forgedStats:     forgedStats,
		transportErr:    make(chan error, 2),
		QueuePacketConn: turbotunnel.NewQueuePacketConn(clientID, 0, queueSize),
	}
	go func() {
		err := c.recvLoop(transport)
		select {
		case <-c.QueuePacketConn.Closed():
			return
		default:
		}
		if err != nil {
			log.Errorf("recvLoop: %v", err)
			select {
			case c.transportErr <- fmt.Errorf("recvLoop: %w", err):
			default:
			}
		}
	}()
	go func() {
		err := c.sendLoop(transport, addr)
		select {
		case <-c.QueuePacketConn.Closed():
			return
		default:
		}
		if err != nil {
			log.Errorf("sendLoop: %v", err)
			select {
			case c.transportErr <- fmt.Errorf("sendLoop: %w", err):
			default:
			}
		}
	}()
	return c
}

// TransportErrors returns a channel that receives errors from the
// underlying transport goroutines (recvLoop and sendLoop).
func (c *DNSPacketConn) TransportErrors() <-chan error {
	return c.transportErr
}

// dnsResponsePayload extracts the downstream payload of a DNS response, encoded
// into the RDATA of a TXT or CNAME RR. It returns (nil, true) when the response
// has a non-NoError RCODE, indicating a forged or hijacked response. It returns
// (payload, false) on success or (nil, false) when the response doesn't pass
// format checks.
func dnsResponsePayload(resp *dns.Message, domain dns.Name, rrType uint16) ([]byte, bool) {
	if resp.Flags&0x8000 != 0x8000 {
		// QR != 1, this is not a response.
		return nil, false
	}
	if resp.Flags&0x000f != dns.RcodeNoError {
		// Non-zero RCODE indicates a forged or hijacked response.
		return nil, true
	}

	if len(resp.Answer) < 1 {
		return nil, false
	}

	// For A/AAAA, collect RDATA from all answer RRs.
	if rrType == dns.RRTypeA || rrType == dns.RRTypeAAAA {
		var chunks [][]byte
		for _, answer := range resp.Answer {
			if answer.Type != rrType {
				return nil, false
			}
			chunks = append(chunks, answer.Data)
		}
		var payload []byte
		var err error
		if rrType == dns.RRTypeA {
			payload, err = dns.DecodeRDataA(chunks)
		} else {
			payload, err = dns.DecodeRDataAAAA(chunks)
		}
		if err != nil {
			return nil, false
		}
		return payload, false
	}

	// All other types: single answer RR.
	if len(resp.Answer) != 1 {
		return nil, false
	}
	answer := resp.Answer[0]

	_, ok := answer.Name.TrimSuffix(domain)
	if !ok {
		return nil, false
	}

	if answer.Type != rrType {
		return nil, false
	}

	var payload []byte
	var err error
	switch rrType {
	case dns.RRTypeCNAME:
		payload, err = dns.DecodeRDataCNAME(answer.Data, domain)
	case dns.RRTypeNS:
		payload, err = dns.DecodeRDataNS(answer.Data, domain)
	case dns.RRTypeMX:
		payload, err = dns.DecodeRDataMX(answer.Data, domain)
	case dns.RRTypeSRV:
		payload, err = dns.DecodeRDataSRV(answer.Data, domain)
	default:
		payload, err = dns.DecodeRDataTXT(answer.Data)
	}
	if err != nil {
		return nil, false
	}

	return payload, false
}

// nextPacket reads the next length-prefixed packet from r. It returns a nil
// error only when a complete packet was read. It returns io.EOF only when there
// were 0 bytes remaining to read from r. It returns io.ErrUnexpectedEOF when
// EOF occurs in the middle of an encoded packet.
func nextPacket(r *bytes.Reader) ([]byte, error) {
	var n uint16
	err := binary.Read(r, binary.BigEndian, &n)
	if err != nil {
		// We may return a real io.EOF only here.
		return nil, err
	}
	p := make([]byte, n)
	_, err = io.ReadFull(r, p)
	// Here we must change io.EOF to io.ErrUnexpectedEOF.
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return p, err
}

// recvLoop repeatedly calls transport.ReadFrom to receive a DNS message,
// extracts its payload and breaks it into packets, and stores the packets in a
// queue to be returned from a future call to c.ReadFrom.
//
// Whenever we receive a DNS response containing at least one data packet, we
// send on c.pollChan to permit sendLoop to send an immediate polling queries.
func (c *DNSPacketConn) recvLoop(transport net.PacketConn) error {
	for {
		var buf [4096]byte
		n, addr, err := transport.ReadFrom(buf[:])
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				log.Warnf("ReadFrom temporary error: %v", err)
				continue
			}
			return err
		}

		// Got a response. Try to parse it as a DNS message.
		resp, err := dns.MessageFromWireFormat(buf[:n])
		if err != nil {
			log.Warnf("MessageFromWireFormat: %v", err)
			continue
		}

		payload, isForged := dnsResponsePayload(&resp, c.domain, c.rrType)
		if isForged {
			c.forgedStats.Record(resp.Flags & 0x000f)
			continue
		}

		// Pull out the packets contained in the payload.
		r := bytes.NewReader(payload)
		any := false
		for {
			p, err := nextPacket(r)
			if err != nil {
				break
			}
			any = true
			c.QueuePacketConn.QueueIncoming(p, addr)
		}

		// If the payload contained one or more packets, permit sendLoop
		// to poll immediately.
		if any {
			select {
			case c.pollChan <- struct{}{}:
			default:
			}
		}
	}
}

// chunks breaks p into non-empty subslices of at most n bytes, greedily so that
// only final subslice has length < n.
func chunks(p []byte, n int) [][]byte {
	var result [][]byte
	for len(p) > 0 {
		sz := len(p)
		if sz > n {
			sz = n
		}
		result = append(result, p[:sz])
		p = p[sz:]
	}
	return result
}

// send sends p as a single packet encoded into a DNS query, using
// transport.WriteTo(query, addr).
//
// VayDNS encoding format:
//   - Data query:  [ClientID:N][DataLen:1][Data]
//   - Poll query:  [ClientID:N][Nonce:4]  (4 random bytes for cache busting)
//
// dnstt compatibility encoding format (when -compat dnstt):
//   - Data query:  [ClientID:8][PaddingPrefix:224+3][Padding:3][DataLen:1][Data]
//   - Poll query:  [ClientID:8][PaddingPrefix:224+8][Padding:8]
//
// The encoded bytes are base32-encoded, split into 63-byte labels, and
// appended with the tunnel domain to form the DNS query name. Label count
// and total QNAME length are constrained by maxQnameLen and maxNumLabels.
// The query QTYPE is set to rrType (e.g. TXT, CNAME, A) to match the
// server's configured response encoding.
func (c *DNSPacketConn) send(transport net.PacketConn, p []byte, addr net.Addr) error {
	const labelLen = 63 // DNS maximum label size

	domain := c.domain

	// Calculate domain wire length (each label: 1 length byte + content).
	domainWireLen := 0
	for _, label := range domain {
		domainWireLen += 1 + len(label)
	}

	// Calculate available wire bytes for data labels.
	maxQnameLen := c.maxQnameLen
	if maxQnameLen <= 0 || maxQnameLen > 253 {
		maxQnameLen = 253
	}
	availableWireBytes := maxQnameLen - domainWireLen
	if availableWireBytes <= 0 {
		return fmt.Errorf("domain %s is too long for max-qname-len %d", domain.String(), c.maxQnameLen)
	}

	// Calculate encoded capacity from wire bytes.
	encodedCapacity := availableWireBytes * labelLen / (labelLen + 1)

	// If maxNumLabels is limited, also cap the encoded capacity.
	if c.maxNumLabels > 0 {
		maxEncoded := c.maxNumLabels * labelLen
		if encodedCapacity > maxEncoded {
			encodedCapacity = maxEncoded
		}
	}

	var decoded []byte
	{
		var buf bytes.Buffer
		buf.Write(c.clientID.Bytes())
		if len(p) > 0 {
			if c.wireConfig.IsDnstt() {
				// dnstt data: [ClientID][PaddingPrefix:224+3][Padding:3][DataLen:1][Data]
				if len(p) > c.wireConfig.MaxDataLen() {
					return fmt.Errorf("too long")
				}
				buf.WriteByte(224 + 3)
				io.CopyN(&buf, rand.Reader, 3)
			} else {
				if len(p) > c.wireConfig.MaxDataLen() {
					return fmt.Errorf("too long")
				}
			}
			buf.WriteByte(byte(len(p)))
			buf.Write(p)
		} else {
			if c.wireConfig.IsDnstt() {
				// dnstt poll: [ClientID][PaddingPrefix:224+8][Padding:8]
				buf.WriteByte(224 + 8)
				io.CopyN(&buf, rand.Reader, 8)
			} else {
				// vaydns poll: [ClientID][Nonce:4]
				io.CopyN(&buf, rand.Reader, pollNonceLen)
			}
		}
		decoded = buf.Bytes()
	}

	encoded := make([]byte, base32Encoding.EncodedLen(len(decoded)))
	base32Encoding.Encode(encoded, decoded)
	encoded = bytes.ToLower(encoded)
	// Truncate encoded data to fit within constraints.
	if len(encoded) > encodedCapacity {
		encoded = encoded[:encodedCapacity]
	}
	labels := chunks(encoded, labelLen)
	labels = append(labels, domain...)
	name, err := dns.NewName(labels)
	if err != nil {
		return err
	}

	var id uint16
	binary.Read(rand.Reader, binary.BigEndian, &id)
	query := &dns.Message{
		ID:    id,
		Flags: 0x0100, // QR = 0, RD = 1
		Question: []dns.Question{
			{
				Name:  name,
				Type:  c.rrType,
				Class: dns.ClassIN,
			},
		},
		// EDNS(0)
		Additional: []dns.RR{
			{
				Name:  dns.Name{},
				Type:  dns.RRTypeOPT,
				Class: 4096, // requester's UDP payload size
				TTL:   0,    // extended RCODE and flags
				Data:  []byte{},
			},
		},
	}
	buf, err := query.WireFormat()
	if err != nil {
		return err
	}

	_, err = transport.WriteTo(buf, addr)
	return err
}

// sendLoop takes packets that have been written using c.WriteTo, and sends them
// on the network using send. It also does polling with empty packets when
// requested by pollChan or after a timeout.
func (c *DNSPacketConn) sendLoop(transport net.PacketConn, addr net.Addr) error {
	pollDelay := initPollDelay
	pollTimer := time.NewTimer(pollDelay)
	defer pollTimer.Stop()
	outgoing := c.QueuePacketConn.OutgoingQueue(addr)
	closed := c.QueuePacketConn.Closed()
	for {
		var p []byte
		pollTimerExpired := false
		// Prioritize sending an actual data packet from outgoing. Only
		// consider a poll when outgoing is empty.
		select {
		case <-closed:
			return nil
		case p = <-outgoing:
		default:
			select {
			case <-closed:
				return nil
			case p = <-outgoing:
			case <-c.pollChan:
			case <-pollTimer.C:
				pollTimerExpired = true
			}
		}

		if len(p) > 0 {
			// A data-carrying packet displaces one pending poll
			// opportunity, if any.
			select {
			case <-c.pollChan:
			default:
			}
		}

		if pollTimerExpired {
			// We're polling because it's been a while since we last
			// polled. Increase the poll delay.
			pollDelay = time.Duration(float64(pollDelay) * pollDelayMultiplier)
			if pollDelay > maxPollDelay {
				pollDelay = maxPollDelay
			}
		} else {
			// We're sending an actual data packet, or we're polling
			// in response to a received packet. Reset the poll
			// delay to initial.
			if !pollTimer.Stop() {
				<-pollTimer.C
			}
			pollDelay = initPollDelay
		}
		pollTimer.Reset(pollDelay)

		// Unlike in the server, in the client we assume that because
		// the data capacity of queries is so limited, it's not worth
		// trying to send more than one packet per query.
		c.rateLimiter.Wait()
		select {
		case <-closed:
			return nil
		default:
		}
		err := c.send(transport, p, addr)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				log.Warnf("send timeout: %v", err)
				continue
			}
			return err
		}
	}
}
