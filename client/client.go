// Package client provides a reusable DNS tunnel client library.
//
// It provides configuration options for VayDNS features (DoH/DoT transports,
// per-query UDP, forged response filtering, rate limiting, dnstt wire
// compatibility, etc.).
//
// Basic usage (xray-core compatible):
//
//	r, _ := client.NewResolver(client.ResolverTypeUDP, "8.8.8.8:53")
//	ts, _ := client.NewTunnelServer("t.example.com", "pubkey-hex")
//	t, _ := client.NewTunnel(r, ts)
//	t.InitiateResolverConnection()
//	t.InitiateDNSPacketConn(ts.Addr)
//	t.InitiateKCPConn(ts.MTU)
//	t.InitiateNoiseChannel()
//	t.InitiateSmuxSession()
//	stream, _ := t.OpenStream() // returns net.Conn
//	defer t.Close()
package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	utls "github.com/refraction-networking/utls"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"github.com/net2share/vaydns/dns"
	"github.com/net2share/vaydns/noise"
	"github.com/net2share/vaydns/turbotunnel"
)

// Default timeouts for VayDNS mode.
const (
	DefaultIdleTimeout          = 60 * time.Second
	DefaultKeepAlive            = 10 * time.Second
	DefaultOpenStreamTimeout    = 10 * time.Second
	DefaultReconnectDelay       = 1 * time.Second
	DefaultReconnectMaxDelay    = 30 * time.Second
	DefaultSessionCheckInterval = 20 * time.Second
	DefaultUDPResponseTimeout   = 500 * time.Millisecond
	DefaultUDPWorkers           = 100
	DefaultMaxStreams            = 256
)

// Default timeouts for dnstt compatibility mode.
const (
	DnsttIdleTimeout = 2 * time.Minute
	DnsttKeepAlive   = 10 * time.Second
)

// ResolverType identifies the DNS transport to use.
type ResolverType string

const (
	ResolverTypeUDP ResolverType = "udp"
	ResolverTypeDOT ResolverType = "dot"
	ResolverTypeDOH ResolverType = "doh"
)

// Resolver holds DNS resolver configuration.
type Resolver struct {
	ResolverType ResolverType
	ResolverAddr string // UDP: "1.1.1.1:53", DoT: "resolver:853", DoH: "https://resolver/dns-query"

	// UTLSClientHelloID sets the uTLS fingerprint for DoH/DoT connections.
	// nil means no uTLS (plain TLS).
	UTLSClientHelloID *utls.ClientHelloID

	// RoundTripper overrides the HTTP transport for DoH. If set,
	// UTLSClientHelloID is ignored for DoH.
	RoundTripper http.RoundTripper

	// DialerControl is an optional callback for setting socket options
	// (SO_MARK, SO_BINDTODEVICE, etc.) on UDP sockets.
	DialerControl func(network, address string, c syscall.RawConn) error

	// UDP transport settings (only apply to ResolverTypeUDP).
	UDPWorkers      int           // concurrent UDP workers (0 = DefaultUDPWorkers)
	UDPSharedSocket bool          // use single shared socket instead of per-query
	UDPTimeout      time.Duration // per-query response timeout (0 = DefaultUDPResponseTimeout)
	UDPAcceptErrors bool          // pass through non-NOERROR responses (default: filter)
}

// NewResolver creates a Resolver with the given type and address.
func NewResolver(resolverType ResolverType, resolverAddr string) (Resolver, error) {
	switch resolverType {
	case ResolverTypeUDP, ResolverTypeDOT, ResolverTypeDOH:
	default:
		return Resolver{}, fmt.Errorf("unsupported resolver type: %s", resolverType)
	}
	return Resolver{
		ResolverType: resolverType,
		ResolverAddr: resolverAddr,
	}, nil
}

// TunnelServer holds tunnel server configuration (domain + public key).
type TunnelServer struct {
	Addr               dns.Name
	PubKey             string
	MTU                int // auto-computed if 0 when InitiateKCPConn is called
	decodedNoisePubKey []byte

	// DnsttCompat enables the original dnstt wire format (8-byte ClientID,
	// padding prefixes). When true, ClientIDSize is forced to 8.
	DnsttCompat bool

	// ClientIDSize is the ClientID size in bytes (default: 2).
	// Ignored when DnsttCompat is true.
	ClientIDSize int

	// MaxQnameLen is the maximum QNAME wire length (default: 101, or 253 with DnsttCompat).
	MaxQnameLen int

	// MaxNumLabels is the maximum number of data labels (default: 0 = unlimited).
	MaxNumLabels int

	// RPS limits outgoing DNS queries per second (default: 0 = unlimited).
	RPS float64
}

// NewTunnelServer creates a TunnelServer from a domain string and hex-encoded
// public key.
func NewTunnelServer(addr string, pubKeyString string) (TunnelServer, error) {
	domain, err := dns.ParseName(addr)
	if err != nil {
		return TunnelServer{}, fmt.Errorf("invalid domain %+q: %w", addr, err)
	}

	pubkey, err := noise.DecodeKey(pubKeyString)
	if err != nil {
		return TunnelServer{}, fmt.Errorf("pubkey format error: %w", err)
	}

	return TunnelServer{
		Addr:               domain,
		PubKey:             pubKeyString,
		decodedNoisePubKey: pubkey,
	}, nil
}

// wireConfig returns the WireConfig derived from the TunnelServer settings.
func (ts *TunnelServer) wireConfig() turbotunnel.WireConfig {
	if ts.DnsttCompat {
		return turbotunnel.WireConfig{ClientIDSize: 8, Compat: true}
	}
	size := ts.ClientIDSize
	if size <= 0 {
		size = 2
	}
	return turbotunnel.WireConfig{ClientIDSize: size}
}

// effectiveMaxQnameLen returns the max QNAME length, applying dnstt defaults.
func (ts *TunnelServer) effectiveMaxQnameLen() int {
	if ts.MaxQnameLen > 0 {
		return ts.MaxQnameLen
	}
	if ts.DnsttCompat {
		return 253
	}
	return 101
}

// Tunnel represents a DNS tunnel connection. Create with NewTunnel, then
// either call the step-by-step Initiate* methods (for embedding in frameworks
// like xray-core) or call ListenAndServe for a fully managed session.
type Tunnel struct {
	Resolver     Resolver
	TunnelServer TunnelServer

	// Session configuration. Zero values use defaults.
	IdleTimeout          time.Duration // default: 10s (2m with DnsttCompat)
	KeepAlive            time.Duration // default: 2s (10s with DnsttCompat)
	OpenStreamTimeout    time.Duration // default: 10s
	MaxStreams            int           // default: 256 (0 = unlimited)
	ReconnectMinDelay    time.Duration // default: 1s
	ReconnectMaxDelay    time.Duration // default: 30s
	SessionCheckInterval time.Duration // default: 500ms

	// internal state
	wireConfig    turbotunnel.WireConfig
	forgedStats   *ForgedStats
	resolverConn  net.PacketConn
	dnsPacketConn *DNSPacketConn
	kcpConn       *kcp.UDPSession
	noiseChannel  io.ReadWriteCloser
	smuxSession   *smux.Session
	remoteAddr    net.Addr
}

// NewTunnel creates a Tunnel with the given resolver and server configuration.
// Zero-value fields use sensible defaults.
func NewTunnel(resolver Resolver, tunnelServer TunnelServer) (*Tunnel, error) {
	t := &Tunnel{
		Resolver:     resolver,
		TunnelServer: tunnelServer,
	}
	t.wireConfig = tunnelServer.wireConfig()
	return t, nil
}

func (t *Tunnel) applyDefaults() {
	isDnstt := t.TunnelServer.DnsttCompat

	if t.IdleTimeout == 0 {
		if isDnstt {
			t.IdleTimeout = DnsttIdleTimeout
		} else {
			t.IdleTimeout = DefaultIdleTimeout
		}
	}
	if t.KeepAlive == 0 {
		if isDnstt {
			t.KeepAlive = DnsttKeepAlive
		} else {
			t.KeepAlive = DefaultKeepAlive
		}
	}
	if t.OpenStreamTimeout == 0 {
		t.OpenStreamTimeout = DefaultOpenStreamTimeout
	}
	if t.MaxStreams == 0 {
		t.MaxStreams = DefaultMaxStreams
	}
	if t.ReconnectMinDelay == 0 {
		t.ReconnectMinDelay = DefaultReconnectDelay
	}
	if t.ReconnectMaxDelay == 0 {
		t.ReconnectMaxDelay = DefaultReconnectMaxDelay
	}
	if t.SessionCheckInterval == 0 {
		t.SessionCheckInterval = DefaultSessionCheckInterval
	}
}

// InitiateResolverConnection creates the underlying transport connection
// based on the Resolver configuration.
func (t *Tunnel) InitiateResolverConnection() error {
	r := t.Resolver
	switch r.ResolverType {
	case ResolverTypeUDP:
		addr, err := net.ResolveUDPAddr("udp", r.ResolverAddr)
		if err != nil {
			return err
		}
		t.remoteAddr = addr
		if r.UDPSharedSocket {
			lc := net.ListenConfig{Control: r.DialerControl}
			conn, err := lc.ListenPacket(context.Background(), "udp", ":0")
			if err != nil {
				return err
			}
			t.resolverConn = conn
		} else {
			workers := r.UDPWorkers
			if workers <= 0 {
				workers = DefaultUDPWorkers
			}
			timeout := r.UDPTimeout
			if timeout <= 0 {
				timeout = DefaultUDPResponseTimeout
			}
			conn, forgedStats, err := NewUDPPacketConn(addr, r.DialerControl, workers, timeout, !r.UDPAcceptErrors)
			if err != nil {
				return err
			}
			t.forgedStats = forgedStats
			t.resolverConn = conn
		}
		return nil

	case ResolverTypeDOH:
		t.remoteAddr = turbotunnel.DummyAddr{}
		var rt http.RoundTripper
		if r.RoundTripper != nil {
			rt = r.RoundTripper
		} else if r.UTLSClientHelloID != nil {
			rt = NewUTLSRoundTripper(nil, r.UTLSClientHelloID)
		} else {
			rt = http.DefaultTransport
		}
		conn, err := NewHTTPPacketConn(rt, r.ResolverAddr, 8)
		if err != nil {
			return err
		}
		t.resolverConn = conn
		return nil

	case ResolverTypeDOT:
		t.remoteAddr = turbotunnel.DummyAddr{}
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
		conn, err := NewTLSPacketConn(r.ResolverAddr, dialTLSContext)
		if err != nil {
			return err
		}
		t.resolverConn = conn
		return nil

	default:
		return fmt.Errorf("unsupported resolver type: %s", r.ResolverType)
	}
}

// InitiateDNSPacketConn wraps the resolver connection with DNS encoding.
func (t *Tunnel) InitiateDNSPacketConn(domain dns.Name) error {
	var rateLimiter *RateLimiter
	if t.TunnelServer.RPS > 0 {
		rateLimiter = NewRateLimiter(t.TunnelServer.RPS)
	}
	maxQnameLen := t.TunnelServer.effectiveMaxQnameLen()
	t.dnsPacketConn = NewDNSPacketConn(t.resolverConn, t.remoteAddr, domain, rateLimiter, maxQnameLen, t.TunnelServer.MaxNumLabels, t.wireConfig, t.forgedStats)
	return nil
}

// InitiateKCPConn opens a KCP connection over the DNS packet connection.
// If mtu is 0, it is auto-computed from the domain and QNAME constraints.
func (t *Tunnel) InitiateKCPConn(mtu int) error {
	if mtu <= 0 {
		maxQnameLen := t.TunnelServer.effectiveMaxQnameLen()
		mtu = DNSNameCapacity(t.TunnelServer.Addr, maxQnameLen, t.TunnelServer.MaxNumLabels) - t.wireConfig.DataOverhead()
	}
	if mtu < 50 {
		return fmt.Errorf("MTU %d is too small (minimum 50); try increasing -max-qname-len (currently %d), increasing -max-num-labels (currently %d), using a shorter domain, or decreasing -clientid-size (currently %d)",
			mtu, t.TunnelServer.effectiveMaxQnameLen(), t.TunnelServer.MaxNumLabels, t.wireConfig.ClientIDSize)
	}
	t.TunnelServer.MTU = mtu
	log.Infof("effective MTU %d", mtu)

	conn, err := kcp.NewConn2(t.remoteAddr, nil, 0, 0, t.dnsPacketConn)
	if err != nil {
		return fmt.Errorf("opening KCP conn: %v", err)
	}
	log.Infof("session %08x ready", conn.GetConv())
	conn.SetStreamMode(true)
	conn.SetNoDelay(0, 0, 0, 1)
	conn.SetWindowSize(turbotunnel.QueueSize/2, turbotunnel.QueueSize/2)
	if rc := conn.SetMtu(mtu); !rc {
		conn.Close()
		return fmt.Errorf("failed to set KCP MTU to %d", mtu)
	}

	t.kcpConn = conn
	return nil
}

// InitiateNoiseChannel performs the Noise protocol handshake.
func (t *Tunnel) InitiateNoiseChannel() error {
	rw, err := noise.NewClient(t.kcpConn, t.TunnelServer.decodedNoisePubKey)
	if err != nil {
		return fmt.Errorf("noise handshake: %v", err)
	}
	t.noiseChannel = rw
	return nil
}

// InitiateSmuxSession establishes a multiplexed session over the Noise channel.
func (t *Tunnel) InitiateSmuxSession() error {
	t.applyDefaults()

	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveInterval = t.KeepAlive
	smuxConfig.KeepAliveTimeout = t.IdleTimeout
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024
	sess, err := smux.Client(t.noiseChannel, smuxConfig)
	if err != nil {
		return fmt.Errorf("opening smux session: %v", err)
	}
	t.smuxSession = sess
	return nil
}

// OpenStream opens a new multiplexed stream. Returns a net.Conn.
func (t *Tunnel) OpenStream() (net.Conn, error) {
	timeout := t.OpenStreamTimeout
	if timeout <= 0 {
		timeout = DefaultOpenStreamTimeout
	}

	type result struct {
		stream *smux.Stream
		err    error
	}
	ch := make(chan result, 1)
	go func() {
		s, err := t.smuxSession.OpenStream()
		ch <- result{s, err}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			return nil, fmt.Errorf("session %08x opening stream: %v", t.kcpConn.GetConv(), r.err)
		}
		log.Debugf("stream %08x:%d ready", t.kcpConn.GetConv(), r.stream.ID())
		return r.stream, nil
	case <-time.After(timeout):
		go func() {
			r := <-ch
			if r.stream != nil {
				r.stream.Close()
			}
		}()
		return nil, fmt.Errorf("session %08x opening stream: timed out after %v", t.kcpConn.GetConv(), timeout)
	}
}

// Handle forwards data between a local TCP connection and a tunnel stream.
func (t *Tunnel) Handle(lconn *net.TCPConn) error {
	stream, err := t.OpenStream()
	if err != nil {
		return err
	}
	defer stream.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(stream, lconn)
		if err == io.EOF {
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Warnf("copy stream←local: %v", err)
		}
		lconn.CloseRead()
		stream.Close()
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(lconn, stream)
		if err == io.EOF {
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Warnf("copy local←stream: %v", err)
		}
		lconn.CloseWrite()
	}()
	wg.Wait()

	return nil
}

// Close tears down the tunnel and all its layers.
func (t *Tunnel) Close() error {
	if t.smuxSession != nil {
		t.smuxSession.Close()
	}
	if t.noiseChannel != nil {
		t.noiseChannel.Close()
	}
	if t.kcpConn != nil {
		log.Debugf("session %08x closed", t.kcpConn.GetConv())
		t.kcpConn.Close()
	}
	if t.dnsPacketConn != nil {
		t.dnsPacketConn.Close()
	}
	if t.resolverConn != nil {
		t.resolverConn.Close()
	}
	return nil
}

// ListenAndServe starts a TCP listener and forwards connections through the
// tunnel with automatic session reconnection. This is the main entry point
// for the CLI.
func (t *Tunnel) ListenAndServe(listenAddr string) error {
	t.applyDefaults()

	localAddr, err := net.ResolveTCPAddr("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("invalid listen address: %v", err)
	}

	maxQnameLen := t.TunnelServer.effectiveMaxQnameLen()
	mtu := DNSNameCapacity(t.TunnelServer.Addr, maxQnameLen, t.TunnelServer.MaxNumLabels) - t.wireConfig.DataOverhead()
	if mtu < 50 {
		return fmt.Errorf("MTU %d is too small (minimum 50); try increasing -max-qname-len (currently %d), increasing -max-num-labels (currently %d), using a shorter domain, or decreasing -clientid-size (currently %d)",
			mtu, maxQnameLen, t.TunnelServer.MaxNumLabels, t.wireConfig.ClientIDSize)
	}
	log.Infof("effective MTU %d", mtu)

	// Create the transport and DNS layer.
	if err := t.InitiateResolverConnection(); err != nil {
		return err
	}
	defer t.resolverConn.Close()

	if err := t.InitiateDNSPacketConn(t.TunnelServer.Addr); err != nil {
		return err
	}
	transportErrCh := t.dnsPacketConn.TransportErrors()

	ln, err := net.ListenTCP("tcp", localAddr)
	if err != nil {
		return fmt.Errorf("opening local listener: %v", err)
	}
	defer ln.Close()

	var sem chan struct{}
	if t.MaxStreams > 0 {
		sem = make(chan struct{}, t.MaxStreams)
	}

	for {
		// Create a new tunnel session with exponential backoff.
		var conn *kcp.UDPSession
		var sess *smux.Session
		delay := t.ReconnectMinDelay
		for {
			conn, sess, err = t.createSession(mtu)
			if err == nil {
				break
			}
			log.Warnf("session creation failed: %v; retrying in %v", err, delay)
			time.Sleep(delay)
			delay *= 2
			if delay > t.ReconnectMaxDelay {
				delay = t.ReconnectMaxDelay
			}
		}

		sessDone := sess.CloseChan()
		conv := conn.GetConv()

		sessionAlive := true
		for sessionAlive {
			ln.SetDeadline(time.Now().Add(t.SessionCheckInterval))
			local, err := ln.Accept()
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					select {
					case <-sessDone:
						sessionAlive = false
					case <-transportErrCh:
						sessionAlive = false
					default:
					}
					continue
				}
				sess.Close()
				conn.Close()
				return err
			}

			select {
			case <-sessDone:
				local.Close()
				sessionAlive = false
				continue
			case <-transportErrCh:
				local.Close()
				sessionAlive = false
				continue
			default:
			}

			go func() {
				if sem != nil {
					sem <- struct{}{}
					defer func() { <-sem }()
				}
				defer local.Close()
				err := t.handleConn(local.(*net.TCPConn), sess, conv)
				if err != nil {
					log.Warnf("handle: %v", err)
				}
			}()
		}

		log.Warnf("session %08x closed, reconnecting", conv)
		sess.Close()
		conn.Close()
	}
}

// createSession creates a KCP+Noise+smux session (used by ListenAndServe).
func (t *Tunnel) createSession(mtu int) (*kcp.UDPSession, *smux.Session, error) {
	conn, err := kcp.NewConn2(t.remoteAddr, nil, 0, 0, t.dnsPacketConn)
	if err != nil {
		return nil, nil, fmt.Errorf("opening KCP conn: %v", err)
	}
	log.Infof("session %08x ready", conn.GetConv())
	conn.SetStreamMode(true)
	conn.SetNoDelay(0, 0, 0, 1)
	conn.SetWindowSize(turbotunnel.QueueSize/2, turbotunnel.QueueSize/2)
	if rc := conn.SetMtu(mtu); !rc {
		conn.Close()
		return nil, nil, fmt.Errorf("failed to set KCP MTU to %d", mtu)
	}

	rw, err := noise.NewClient(conn, t.TunnelServer.decodedNoisePubKey)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("noise handshake: %v", err)
	}

	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveInterval = t.KeepAlive
	smuxConfig.KeepAliveTimeout = t.IdleTimeout
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024
	sess, err := smux.Client(rw, smuxConfig)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("opening smux session: %v", err)
	}

	return conn, sess, nil
}

// handleConn forwards a single TCP connection through the tunnel session.
func (t *Tunnel) handleConn(local *net.TCPConn, sess *smux.Session, conv uint32) error {
	type streamResult struct {
		stream *smux.Stream
		err    error
	}
	ch := make(chan streamResult, 1)
	go func() {
		s, err := sess.OpenStream()
		ch <- streamResult{s, err}
	}()

	var stream *smux.Stream
	select {
	case r := <-ch:
		if r.err != nil {
			return fmt.Errorf("session %08x opening stream: %v", conv, r.err)
		}
		stream = r.stream
	case <-time.After(t.OpenStreamTimeout):
		go func() {
			r := <-ch
			if r.stream != nil {
				r.stream.Close()
			}
		}()
		return fmt.Errorf("session %08x opening stream: timed out after %v", conv, t.OpenStreamTimeout)
	}

	defer func() {
		log.Debugf("stream %08x:%d closed", conv, stream.ID())
		stream.Close()
	}()
	log.Infof("stream %08x:%d ready", conv, stream.ID())

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(stream, local)
		if err == io.EOF {
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Warnf("stream %08x:%d copy stream←local: %v", conv, stream.ID(), err)
		}
		local.CloseRead()
		stream.Close()
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(local, stream)
		if err == io.EOF {
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Warnf("stream %08x:%d copy local←stream: %v", conv, stream.ID(), err)
		}
		local.CloseWrite()
	}()
	wg.Wait()

	return nil
}

// DNSNameCapacity returns the number of raw bytes that can be encoded in a DNS
// query name, given the domain suffix and encoding constraints.
func DNSNameCapacity(domain dns.Name, maxQnameLen int, maxNumLabels int) int {
	const labelLen = 63

	if maxQnameLen <= 0 || maxQnameLen > 253 {
		maxQnameLen = 253
	}

	domainWireLen := 0
	for _, label := range domain {
		domainWireLen += 1 + len(label)
	}

	availableWireBytes := maxQnameLen - domainWireLen
	if availableWireBytes <= 0 {
		return 0
	}

	encodedCapacity := availableWireBytes * labelLen / (labelLen + 1)

	if maxNumLabels > 0 {
		maxEncoded := maxNumLabels * labelLen
		if encodedCapacity > maxEncoded {
			encodedCapacity = maxEncoded
		}
	}

	rawCapacity := encodedCapacity * 5 / 8
	return rawCapacity
}

// SampleUTLSDistribution parses a weighted distribution string (e.g.,
// "3*Firefox,2*Chrome,1*iOS") and randomly selects a ClientHelloID.
func SampleUTLSDistribution(spec string) (*utls.ClientHelloID, error) {
	weights, labels, err := parseWeightedList(spec)
	if err != nil {
		return nil, err
	}
	ids := make([]*utls.ClientHelloID, 0, len(labels))
	for _, label := range labels {
		var id *utls.ClientHelloID
		if label == "none" {
			id = nil
		} else {
			id = UTLSLookup(label)
			if id == nil {
				return nil, fmt.Errorf("unknown TLS fingerprint %q", label)
			}
		}
		ids = append(ids, id)
	}
	return ids[sampleWeighted(weights)], nil
}

// UTLSClientHelloIDMap returns the list of supported uTLS fingerprint labels.
func UTLSClientHelloIDMap() []struct {
	Label string
	ID    *utls.ClientHelloID
} {
	return utlsClientHelloIDMap
}

// Outbound provides a high-level API for creating tunnels from multiple
// resolvers and tunnel servers.
type Outbound struct {
	Resolvers     []Resolver
	TunnelServers []TunnelServer
	tunnels       []*Tunnel
}

// NewOutbound creates an Outbound with the given resolvers and tunnel servers.
func NewOutbound(resolvers []Resolver, tunnelServers []TunnelServer) *Outbound {
	return &Outbound{
		Resolvers:     resolvers,
		TunnelServers: tunnelServers,
	}
}

// Start begins accepting connections on bind and forwarding them through the
// first resolver/server pair.
func (o *Outbound) Start(bind string) error {
	resolver := o.Resolvers[0]
	tunnelServer := o.TunnelServers[0]

	tunnel, err := NewTunnel(resolver, tunnelServer)
	if err != nil {
		return fmt.Errorf("failed to create tunnel: %w", err)
	}
	o.tunnels = []*Tunnel{tunnel}

	return tunnel.ListenAndServe(bind)
}
