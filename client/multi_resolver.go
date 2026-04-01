package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/net2share/vaydns/dns"
	"github.com/net2share/vaydns/turbotunnel"
	log "github.com/sirupsen/logrus"
)

// SelectionMode controls which resolver MultiResolver picks for outgoing packets.
type SelectionMode string

const (
	// SelectionRoundRobin rotates through preferred resolvers in order.
	SelectionRoundRobin SelectionMode = "roundrobin"
	// SelectionBest picks the resolver with the best observed score.
	SelectionBest SelectionMode = "best"
	// SelectionSmart currently aliases best-score selection.
	SelectionSmart SelectionMode = "smart"
)

// ResolverState is the current health state of one resolver.
type ResolverState string

const (
	ResolverStateUnknown     ResolverState = "unknown"
	ResolverStateHealthy     ResolverState = "healthy"
	ResolverStateRateLimited ResolverState = "rate_limited"
	ResolverStateDown        ResolverState = "down"
)

const (
	pendingResponseTimeout = 5 * time.Second
	healthTickInterval     = 1 * time.Second
	downTimeoutThreshold   = int64(8)
	rateLimitThreshold     = int64(5)
	probeInterval          = 1 * time.Second
)

// ResolverStat is a snapshot of one resolver's counters and health state.
type ResolverStat struct {
	Address      string
	State        ResolverState
	ValidCount   int64
	InvalidCount int64
	TimeoutCount int64
	LastWrite    time.Time
	LastValid    time.Time
}

type resolverEntry struct {
	name string
	addr net.Addr
	conn net.PacketConn

	validCount   atomic.Int64
	invalidCount atomic.Int64
	timeoutCount atomic.Int64

	mu        sync.Mutex
	pending   map[uint16]time.Time
	lastWrite time.Time
	lastValid time.Time
	lastProbe time.Time
	state     ResolverState
}

func (e *resolverEntry) writePacket(b []byte) (int, error) {
	now := time.Now()
	e.trackOutgoingID(b, now)
	n, err := e.conn.WriteTo(b, e.addr)
	if err != nil {
		e.invalidCount.Add(1)
	}
	e.mu.Lock()
	e.lastWrite = now
	e.mu.Unlock()
	return n, err
}

func (e *resolverEntry) trackOutgoingID(b []byte, now time.Time) {
	msg, err := dns.MessageFromWireFormat(b)
	if err != nil {
		return
	}
	e.mu.Lock()
	e.pending[msg.ID] = now
	e.mu.Unlock()
}

func (e *resolverEntry) readPacket() multiReadResult {
	var result multiReadResult
	result.entry = e
	result.n, result.addr, result.err = e.conn.ReadFrom(result.buf[:])
	if result.err == nil {
		e.evaluateIncoming(result.buf[:result.n])
	}
	return result
}

func (e *resolverEntry) evaluateIncoming(packet []byte) {
	resp, err := dns.MessageFromWireFormat(packet)
	if err != nil {
		e.invalidCount.Add(1)
		e.recomputeState(time.Now())
		return
	}

	e.mu.Lock()
	delete(e.pending, resp.ID)
	e.mu.Unlock()

	if isValidDNSResponse(resp) {
		e.validCount.Add(1)
		e.timeoutCount.Store(0)
		e.mu.Lock()
		e.lastValid = time.Now()
		e.state = ResolverStateHealthy
		e.mu.Unlock()
		return
	}

	e.invalidCount.Add(1)
	if isRateLimitedResponse(resp) {
		e.mu.Lock()
		e.state = ResolverStateRateLimited
		e.mu.Unlock()
	}
	e.recomputeState(time.Now())
}

func (e *resolverEntry) expirePending(now time.Time) {
	expired := int64(0)
	e.mu.Lock()
	for id, t := range e.pending {
		if now.Sub(t) >= pendingResponseTimeout {
			delete(e.pending, id)
			expired++
		}
	}
	e.mu.Unlock()
	if expired > 0 {
		e.timeoutCount.Add(expired)
		e.invalidCount.Add(expired)
	}
	e.recomputeState(now)
}

func (e *resolverEntry) recomputeState(now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()

	timeouts := e.timeoutCount.Load()
	invalid := e.invalidCount.Load()
	valid := e.validCount.Load()

	switch {
	case timeouts >= downTimeoutThreshold:
		e.state = ResolverStateDown
	case invalid >= rateLimitThreshold && valid == 0:
		e.state = ResolverStateRateLimited
	case valid > 0 && now.Sub(e.lastValid) <= 30*time.Second:
		e.state = ResolverStateHealthy
	case valid == 0:
		e.state = ResolverStateUnknown
	default:
		e.state = ResolverStateUnknown
	}

	// Slow decay to avoid sticky penalties.
	if invalid > 0 {
		e.invalidCount.Store(invalid - 1)
	}
	if timeouts > 0 {
		e.timeoutCount.Store(timeouts - 1)
	}
}

func (e *resolverEntry) stateSnapshot() ResolverState {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.state
}

func (e *resolverEntry) markProbe(now time.Time) {
	e.mu.Lock()
	e.lastProbe = now
	e.mu.Unlock()
}

func (e *resolverEntry) canProbe(now time.Time) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return now.Sub(e.lastProbe) >= probeInterval
}

func (e *resolverEntry) snapshot() ResolverStat {
	e.mu.Lock()
	defer e.mu.Unlock()
	return ResolverStat{
		Address:      e.name,
		State:        e.state,
		ValidCount:   e.validCount.Load(),
		InvalidCount: e.invalidCount.Load(),
		TimeoutCount: e.timeoutCount.Load(),
		LastWrite:    e.lastWrite,
		LastValid:    e.lastValid,
	}
}

type multiReadResult struct {
	buf   [4096]byte
	n     int
	addr  net.Addr
	err   error
	entry *resolverEntry
}

// MultiResolver is a net.PacketConn that multiplexes across multiple DNS
// resolver transport connections. It tracks per-resolver health from valid and
// invalid responses, avoids down resolvers for primary traffic, and probes
// unhealthy resolvers by duplicating selected packets.
type MultiResolver struct {
	entries   []*resolverEntry
	mode      SelectionMode
	mu        sync.Mutex
	rrIndex   int
	probeRR   int
	recvChan  chan multiReadResult
	closed    chan struct{}
	closeOnce sync.Once
}

// NewMultiResolver creates a MultiResolver from a slice of Resolver configs.
func NewMultiResolver(resolvers []Resolver, mode SelectionMode, queueSize int, overflowMode turbotunnel.QueueOverflowMode) (*MultiResolver, error) {
	if len(resolvers) == 0 {
		return nil, fmt.Errorf("at least one resolver is required")
	}

	entries := make([]*resolverEntry, 0, len(resolvers))
	for _, r := range resolvers {
		conn, addr, err := getResolverConnection(r, queueSize, overflowMode)
		if err != nil {
			for _, e := range entries {
				e.conn.Close()
			}
			return nil, fmt.Errorf("resolver %s %s: %w", r.ResolverType, r.ResolverAddr, err)
		}
		entries = append(entries, &resolverEntry{
			name:    r.ResolverAddr,
			addr:    addr,
			conn:    conn,
			pending: make(map[uint16]time.Time),
			state:   ResolverStateUnknown,
		})
	}

	mr := &MultiResolver{
		entries:  entries,
		mode:     mode,
		recvChan: make(chan multiReadResult, len(entries)*4),
		closed:   make(chan struct{}),
	}
	for _, e := range entries {
		entry := e
		go func() {
			for {
				res := entry.readPacket()
				select {
				case mr.recvChan <- res:
				case <-mr.closed:
					return
				}
				if res.err != nil {
					return
				}
			}
		}()
	}
	go mr.healthWorker()
	return mr, nil
}

func (mr *MultiResolver) healthWorker() {
	ticker := time.NewTicker(healthTickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			stats := make([]ResolverStat, 0, len(mr.entries))
			for _, e := range mr.entries {
				e.expirePending(now)
				stats = append(stats, e.snapshot())
			}
			log.Trace("\n" + renderResolverStatsTable(stats, now))
		case <-mr.closed:
			return
		}
	}
}

func renderResolverStatsTable(stats []ResolverStat, now time.Time) string {
	var b strings.Builder
	b.WriteString("+-------------------------+--------------+--------+---------+---------+-------------+-------------+\n")
	b.WriteString("| resolver                | state        | valid  | invalid | timeout | last_write  | last_valid  |\n")
	b.WriteString("+-------------------------+--------------+--------+---------+---------+-------------+-------------+\n")
	for _, s := range stats {
		lastWriteAgo := "-"
		if !s.LastWrite.IsZero() {
			lastWriteAgo = now.Sub(s.LastWrite).Truncate(time.Second).String()
		}
		lastValidAgo := "-"
		if !s.LastValid.IsZero() {
			lastValidAgo = now.Sub(s.LastValid).Truncate(time.Second).String()
		}
		b.WriteString(fmt.Sprintf("| %-23.23s | %-12s | %6d | %7d | %7d | %11s | %11s |\n",
			s.Address,
			s.State,
			s.ValidCount,
			s.InvalidCount,
			s.TimeoutCount,
			lastWriteAgo,
			lastValidAgo,
		))
	}
	b.WriteString("+-------------------------+--------------+--------+---------+---------+-------------+-------------+")
	return b.String()
}

func isValidDNSResponse(resp dns.Message) bool {
	if resp.Flags&0x8000 == 0 {
		return false
	}
	return (resp.Flags & 0x000f) == dns.RcodeNoError
}

func isRateLimitedResponse(resp dns.Message) bool {
	rcode := resp.Flags & 0x000f
	return rcode == dns.RcodeRefused || rcode == dns.RcodeServerFailure
}

// ReadFrom receives a packet from whichever resolver responds first.
func (mr *MultiResolver) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	select {
	case <-mr.closed:
		return 0, nil, net.ErrClosed
	case res := <-mr.recvChan:
		if res.err != nil {
			return 0, res.addr, res.err
		}
		n = copy(b, res.buf[:res.n])
		return n, turbotunnel.DummyAddr{}, nil
	}
}

// WriteTo sends b to the selected primary resolver and may duplicate b to one
// unhealthy resolver as a probe to detect recovery.
func (mr *MultiResolver) WriteTo(b []byte, _ net.Addr) (n int, err error) {
	select {
	case <-mr.closed:
		return 0, net.ErrClosed
	default:
	}

	primary := mr.selectPrimary()
	n, err = primary.writePacket(b)
	if err != nil {
		return n, err
	}

	if probe := mr.selectProbeTarget(primary); probe != nil {
		probe.markProbe(time.Now())
		_, _ = probe.writePacket(b)
	}
	return n, nil
}

func (mr *MultiResolver) selectPrimary() *resolverEntry {
	if mr.mode == SelectionRoundRobin {
		if e := mr.selectRoundRobinHealthy(); e != nil {
			return e
		}
		return mr.entries[0]
	}
	if e := mr.selectBestScore(); e != nil {
		return e
	}
	return mr.entries[0]
}

func (mr *MultiResolver) selectRoundRobinHealthy() *resolverEntry {
	mr.mu.Lock()
	defer mr.mu.Unlock()

	if len(mr.entries) == 0 {
		return nil
	}

	start := mr.rrIndex
	for i := 0; i < len(mr.entries); i++ {
		idx := (start + i) % len(mr.entries)
		state := mr.entries[idx].stateSnapshot()
		if state == ResolverStateHealthy || state == ResolverStateUnknown {
			mr.rrIndex = (idx + 1) % len(mr.entries)
			return mr.entries[idx]
		}
	}
	idx := start % len(mr.entries)
	mr.rrIndex = (idx + 1) % len(mr.entries)
	return mr.entries[idx]
}

func (mr *MultiResolver) selectBestScore() *resolverEntry {
	if len(mr.entries) == 0 {
		return nil
	}
	best := mr.entries[0]
	bestScore := resolverScore(best)
	for _, e := range mr.entries[1:] {
		s := resolverScore(e)
		if s > bestScore {
			best = e
			bestScore = s
		}
	}
	return best
}

func resolverScore(e *resolverEntry) int64 {
	statePenalty := int64(0)
	switch e.stateSnapshot() {
	case ResolverStateHealthy:
		statePenalty = 0
	case ResolverStateUnknown:
		statePenalty = 5
	case ResolverStateRateLimited:
		statePenalty = 15
	case ResolverStateDown:
		statePenalty = 30
	}
	return e.validCount.Load()*4 - e.invalidCount.Load()*2 - e.timeoutCount.Load()*3 - statePenalty
}

func (mr *MultiResolver) selectProbeTarget(primary *resolverEntry) *resolverEntry {
	mr.mu.Lock()
	defer mr.mu.Unlock()

	now := time.Now()
	for i := 0; i < len(mr.entries); i++ {
		idx := (mr.probeRR + i) % len(mr.entries)
		e := mr.entries[idx]
		if e == primary {
			continue
		}
		state := e.stateSnapshot()
		if state == ResolverStateHealthy {
			continue
		}
		if e.canProbe(now) {
			mr.probeRR = (idx + 1) % len(mr.entries)
			return e
		}
	}
	return nil
}

// ResolverStats returns current resolver health counters.
func (mr *MultiResolver) ResolverStats() []ResolverStat {
	stats := make([]ResolverStat, 0, len(mr.entries))
	for _, e := range mr.entries {
		stats = append(stats, e.snapshot())
	}
	return stats
}

// ValidInvalidCounts returns valid/invalid counts by resolver address.
func (mr *MultiResolver) ValidInvalidCounts() map[string][2]int64 {
	out := make(map[string][2]int64, len(mr.entries))
	for _, e := range mr.entries {
		out[e.name] = [2]int64{e.validCount.Load(), e.invalidCount.Load()}
	}
	return out
}

// Close closes all underlying connections and stops the reader goroutines.
func (mr *MultiResolver) Close() error {
	mr.closeOnce.Do(func() {
		close(mr.closed)
		for _, e := range mr.entries {
			e.conn.Close()
		}
	})
	return nil
}

// LocalAddr returns the local address of the first underlying connection.
func (mr *MultiResolver) LocalAddr() net.Addr {
	return mr.entries[0].conn.LocalAddr()
}

// SetDeadline sets a deadline on all underlying connections.
func (mr *MultiResolver) SetDeadline(t time.Time) error {
	var last error
	for _, e := range mr.entries {
		if err := e.conn.SetDeadline(t); err != nil {
			last = err
		}
	}
	return last
}

// SetReadDeadline sets a read deadline on all underlying connections.
func (mr *MultiResolver) SetReadDeadline(t time.Time) error {
	var last error
	for _, e := range mr.entries {
		if err := e.conn.SetReadDeadline(t); err != nil {
			last = err
		}
	}
	return last
}

// SetWriteDeadline sets a write deadline on all underlying connections.
func (mr *MultiResolver) SetWriteDeadline(t time.Time) error {
	var last error
	for _, e := range mr.entries {
		if err := e.conn.SetWriteDeadline(t); err != nil {
			last = err
		}
	}
	return last
}

// getResolverConnection creates the underlying transport net.PacketConn for r.
func getResolverConnection(r Resolver, queueSize int, overflowMode turbotunnel.QueueOverflowMode) (net.PacketConn, net.Addr, error) {
	switch r.ResolverType {
	case ResolverTypeUDP:
		addr, err := net.ResolveUDPAddr("udp", r.ResolverAddr)
		if err != nil {
			return nil, nil, err
		}
		if r.UDPSharedSocket {
			lc := net.ListenConfig{Control: r.DialerControl}
			conn, err := lc.ListenPacket(context.Background(), "udp", ":0")
			if err != nil {
				return nil, nil, err
			}
			return conn, addr, nil
		}
		workers := r.UDPWorkers
		if workers <= 0 {
			workers = DefaultUDPWorkers
		}
		timeout := r.UDPTimeout
		if timeout <= 0 {
			timeout = DefaultUDPResponseTimeout
		}
		conn, _, err := NewUDPPacketConn(addr, r.DialerControl, workers, timeout, !r.UDPAcceptErrors, queueSize, overflowMode)
		if err != nil {
			return nil, nil, err
		}
		return conn, addr, nil

	case ResolverTypeDOH:
		var rt http.RoundTripper
		if r.RoundTripper != nil {
			rt = r.RoundTripper
		} else if r.UTLSClientHelloID != nil {
			rt = NewUTLSRoundTripper(nil, r.UTLSClientHelloID)
		} else {
			rt = http.DefaultTransport
		}
		conn, err := NewHTTPPacketConn(rt, r.ResolverAddr, 8, queueSize, overflowMode)
		if err != nil {
			return nil, nil, err
		}
		return conn, turbotunnel.DummyAddr{}, nil

	case ResolverTypeDOT:
		var dialTLSContext func(ctx context.Context, network, addr string) (net.Conn, error)
		if r.UTLSClientHelloID != nil {
			id := r.UTLSClientHelloID
			dialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return UTLSDialContext(ctx, network, addr, nil, id)
			}
		} else {
			dialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return tls.DialWithDialer(&net.Dialer{}, network, addr, nil)
			}
		}
		conn, err := NewTLSPacketConn(r.ResolverAddr, dialTLSContext, queueSize, overflowMode)
		if err != nil {
			return nil, nil, err
		}
		return conn, turbotunnel.DummyAddr{}, nil

	default:
		return nil, nil, fmt.Errorf("unsupported resolver type: %s", r.ResolverType)
	}
}
