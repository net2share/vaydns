package client

import (
	"context"
	"net"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/net2share/vaydns/dns"
	"github.com/net2share/vaydns/turbotunnel"
)

// UDPPacketConn implements net.PacketConn using per-query UDP sockets. Each
// outgoing DNS query is sent from a fresh socket with a random source port,
// making the tunnel harder to fingerprint and more resilient to censorship
// injection attacks that target a single source port.
//
// A pool of worker goroutines dequeues packets from the embedded
// QueuePacketConn, sends each as a DNS query on a new socket, and reads the
// response back into the incoming queue. When ignoreErrors is true (default),
// workers skip non-NOERROR responses and keep reading until a valid response
// arrives or the per-query timeout expires — this defeats forged error
// injection by censors.
type UDPPacketConn struct {
	remoteAddr      net.Addr
	dialerControl   func(network, address string, c syscall.RawConn) error
	responseTimeout time.Duration
	ignoreErrors    bool
	forgedStats     *ForgedStats
	*turbotunnel.QueuePacketConn
}

// NewUDPPacketConn creates a UDPPacketConn with numWorkers goroutines that
// each send one query at a time on a fresh UDP socket. The returned
// ForgedStats pointer is shared with the caller so DNSPacketConn can
// include per-query forged counts in its reporting.
func NewUDPPacketConn(remoteAddr net.Addr, dialerControl func(network, address string, c syscall.RawConn) error, numWorkers int, responseTimeout time.Duration, ignoreErrors bool, queueSize int) (*UDPPacketConn, *ForgedStats, error) {
	stats := &ForgedStats{}
	pconn := &UDPPacketConn{
		remoteAddr:      remoteAddr,
		dialerControl:   dialerControl,
		responseTimeout: responseTimeout,
		ignoreErrors:    ignoreErrors,
		forgedStats:     stats,
		QueuePacketConn: turbotunnel.NewQueuePacketConn(remoteAddr, 0, queueSize),
	}
	for i := 0; i < numWorkers; i++ {
		go pconn.sendLoop()
	}
	return pconn, stats, nil
}

// sendLoop is the per-worker loop. It dequeues one packet at a time from the
// outgoing queue, sends it on a fresh UDP socket, reads the response, and
// queues valid responses for the upper layer. On consecutive send/recv
// failures, it backs off exponentially to avoid CPU spinning when the
// resolver is unreachable.
func (c *UDPPacketConn) sendLoop() {
	const (
		initBackoff = 100 * time.Millisecond
		maxBackoff  = 5 * time.Second
	)
	backoff := initBackoff
	outgoing := c.OutgoingQueue(c.remoteAddr)
	closed := c.Closed()

	for {
		var p []byte
		select {
		case <-closed:
			return
		case p = <-outgoing:
		}
		if err := c.sendRecv(p); err != nil {
			timer := time.NewTimer(backoff)
			select {
			case <-closed:
				timer.Stop()
				return
			case <-timer.C:
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		} else {
			backoff = initBackoff
		}
	}
}

// sendRecv sends a single DNS query on a fresh UDP socket and reads the
// response. If ignoreErrors is set, it keeps reading past non-NOERROR
// responses until a valid one arrives or the timeout expires. Returns nil
// on success, or an error if the query could not be sent or no valid
// response arrived within the timeout.
func (c *UDPPacketConn) sendRecv(p []byte) error {
	lc := net.ListenConfig{
		Control: c.dialerControl,
	}
	conn, err := lc.ListenPacket(context.Background(), "udp", "")
	if err != nil {
		log.Warnf("udp worker: ListenPacket: %v", err)
		return err
	}
	defer conn.Close()

	_, err = conn.WriteTo(p, c.remoteAddr)
	if err != nil {
		log.Warnf("udp worker: WriteTo: %v", err)
		return err
	}

	conn.SetReadDeadline(time.Now().Add(c.responseTimeout))

	var buf [4096]byte
	for {
		n, _, err := conn.ReadFrom(buf[:])
		if err != nil {
			// Timeout or other read error — give up on this query.
			return err
		}

		resp, err := dns.MessageFromWireFormat(buf[:n])
		if err != nil {
			log.Debugf("udp worker: MessageFromWireFormat: %v", err)
			continue
		}

		// Check RCODE. Non-NOERROR usually means a forged/injected response.
		if resp.Flags&0x000f != dns.RcodeNoError {
			rcode := resp.Flags & 0x000f
			if c.ignoreErrors {
				c.forgedStats.Record(rcode)
				continue
			}
			// Pass it through — dns.go recvLoop will drop it as a safety net.
			log.Debugf("udp worker: passing through error response (rcode=%d)", rcode)
		}

		// Queue the raw wire-format response for the upper layer (dns.go recvLoop).
		c.QueueIncoming(buf[:n], c.remoteAddr)
		return nil
	}
}
