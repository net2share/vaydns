// dnstt-client is the client end of a DNS tunnel.
//
// Usage:
//
//	dnstt-client [-doh URL|-dot ADDR|-udp ADDR] -pubkey-file PUBKEYFILE -domain DOMAIN -listen LOCALADDR
//
// Examples:
//
//	dnstt-client -doh https://resolver.example/dns-query -pubkey-file server.pub -domain t.example.com -listen 127.0.0.1:7000
//	dnstt-client -dot resolver.example:853 -pubkey-file server.pub -domain t.example.com -listen 127.0.0.1:7000
//
// The program supports DNS over HTTPS (DoH), DNS over TLS (DoT), and UDP DNS.
// Use one of these options:
//
//	-doh https://resolver.example/dns-query
//	-dot resolver.example:853
//	-udp resolver.example:53
//
// You can give the server's public key as a file or as a hex string. Use
// "dnstt-server -gen-key" to get the public key.
//
//	-pubkey-file server.pub
//	-pubkey 0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff
//
// The -domain option specifies the root of the DNS zone reserved for the
// tunnel. See README for instructions on setting it up.
//
// The -listen option specifies the TCP address that will listen for connections
// and forward them over the tunnel.
//
// In -doh and -dot modes, the program's TLS fingerprint is camouflaged with
// uTLS by default. The specific TLS fingerprint is selected randomly from a
// weighted distribution. You can set your own distribution (or specific single
// fingerprint) using the -utls option. The special value "none" disables uTLS.
//
//	-utls '3*Firefox,2*Chrome,1*iOS'
//	-utls Firefox
//	-utls none
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	utls "github.com/refraction-networking/utls"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/noise"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

// dialerControl is an optional callback for setting socket options (e.g.,
// SO_MARK, SO_BINDTODEVICE) on raw UDP sockets before they are bound.
// nil means no special socket options.
var dialerControl func(network, address string, c syscall.RawConn) error

const (
	defaultIdleTimeout          = 10 * time.Second
	defaultKeepAlive            = 2 * time.Second
	defaultOpenStreamTimeout    = 10 * time.Second
	defaultReconnectDelay       = 1 * time.Second
	defaultReconnectMaxDelay    = 30 * time.Second
	defaultSessionCheckInterval = 500 * time.Millisecond
	defaultUDPResponseTimeout   = 400 * time.Millisecond
)

// dnsNameCapacity returns the number of raw bytes that can be encoded in a DNS
// query name, given the domain suffix and encoding constraints.
//
// maxQnameLen is the maximum total QNAME length in wire format (0 = 253 per RFC 1035).
// maxNumLabels is the maximum number of data labels (0 = unlimited).
// Labels are always chunked at 63 bytes (DNS maximum label size).
func dnsNameCapacity(domain dns.Name, maxQnameLen int, maxNumLabels int) int {
	const labelLen = 63 // DNS maximum label size

	// Default to RFC 1035 maximum if not specified.
	if maxQnameLen <= 0 || maxQnameLen > 253 {
		maxQnameLen = 253
	}

	// Calculate domain wire length (each label: 1 length byte + content).
	domainWireLen := 0
	for _, label := range domain {
		domainWireLen += 1 + len(label)
	}

	// Available wire bytes for data labels.
	availableWireBytes := maxQnameLen - domainWireLen
	if availableWireBytes <= 0 {
		return 0
	}

	// Each label requires len+1 bytes to encode (1 length byte + content).
	// So for N labels of max length L, we use N*(L+1) wire bytes to carry N*L encoded chars.
	encodedCapacity := availableWireBytes * labelLen / (labelLen + 1)

	// If maxNumLabels is limited, cap the encoded capacity.
	if maxNumLabels > 0 {
		maxEncoded := maxNumLabels * labelLen
		if encodedCapacity > maxEncoded {
			encodedCapacity = maxEncoded
		}
	}

	// Base32 expands every 5 bytes to 8 chars.
	rawCapacity := encodedCapacity * 5 / 8
	return rawCapacity
}

// readKeyFromFile reads a key from a named file.
func readKeyFromFile(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return noise.ReadKey(f)
}

// sampleUTLSDistribution parses a weighted uTLS Client Hello ID distribution
// string of the form "3*Firefox,2*Chrome,1*iOS", matches each label to a
// utls.ClientHelloID from utlsClientHelloIDMap, and randomly samples one
// utls.ClientHelloID from the distribution.
func sampleUTLSDistribution(spec string) (*utls.ClientHelloID, error) {
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
			id = utlsLookup(label)
			if id == nil {
				return nil, fmt.Errorf("unknown TLS fingerprint %q", label)
			}
		}
		ids = append(ids, id)
	}
	return ids[sampleWeighted(weights)], nil
}

type streamResult struct {
	stream *smux.Stream
	err    error
}

func handle(local *net.TCPConn, sess *smux.Session, conv uint32, openStreamTimeout time.Duration) error {
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
	case <-time.After(openStreamTimeout):
		go func() {
			r := <-ch
			if r.stream != nil {
				r.stream.Close()
			}
		}()
		return fmt.Errorf("session %08x opening stream: timed out after %v", conv, openStreamTimeout)
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
			// smux Stream.Write may return io.EOF.
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
			// smux Stream.WriteTo may return io.EOF.
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

func createTunnelSession(pconn net.PacketConn, remoteAddr net.Addr, pubkey []byte, mtu int, idleTimeout time.Duration, keepAlive time.Duration) (*kcp.UDPSession, *smux.Session, error) {
	conn, err := kcp.NewConn2(remoteAddr, nil, 0, 0, pconn)
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

	rw, err := noise.NewClient(conn, pubkey)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("noise handshake: %v", err)
	}

	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveInterval = keepAlive
	smuxConfig.KeepAliveTimeout = idleTimeout
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024
	sess, err := smux.Client(rw, smuxConfig)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("opening smux session: %v", err)
	}

	return conn, sess, nil
}

func run(pubkey []byte, domain dns.Name, localAddr *net.TCPAddr, remoteAddr net.Addr, pconn net.PacketConn, maxQnameLen int, maxNumLabels int, idleTimeout time.Duration, keepAlive time.Duration, reconnectMinDelay time.Duration, reconnectMaxDelay time.Duration, sessionCheckInterval time.Duration, streamTimeout time.Duration, maxStreams int, transportErrCh <-chan error, wireConfig turbotunnel.WireConfig) error {
	defer pconn.Close()

	mtu := dnsNameCapacity(domain, maxQnameLen, maxNumLabels) - wireConfig.DataOverhead()
	const kcpMinMTU = 50
	if mtu < kcpMinMTU {
		domainWireLen := 0
		for _, label := range domain {
			domainWireLen += 1 + len(label)
		}
		effectiveQname := maxQnameLen
		if effectiveQname <= 0 || effectiveQname > 253 {
			effectiveQname = 253
		}
		return fmt.Errorf("payload too small: %d bytes (need %d) — domain %s uses %d/%d QNAME bytes, max-qname-len=%d, max-num-labels=%d; try increasing -max-qname-len, -max-num-labels, or use a shorter domain",
			mtu, kcpMinMTU, domain, domainWireLen, effectiveQname, maxQnameLen, maxNumLabels)
	}
	log.Infof("effective MTU %d", mtu)

	ln, err := net.ListenTCP("tcp", localAddr)
	if err != nil {
		return fmt.Errorf("opening local listener: %v", err)
	}
	defer ln.Close()

	// Stream concurrency semaphore.
	var sem chan struct{}
	if maxStreams > 0 {
		sem = make(chan struct{}, maxStreams)
	}

	for {
		// Create a new tunnel session with exponential backoff on failure.
		var conn *kcp.UDPSession
		var sess *smux.Session
		delay := reconnectMinDelay
		for {
			conn, sess, err = createTunnelSession(pconn, remoteAddr, pubkey, mtu, idleTimeout, keepAlive)
			if err == nil {
				break
			}
			log.Warnf("session creation failed: %v; retrying in %v", err, delay)
			time.Sleep(delay)
			delay *= 2
			if delay > reconnectMaxDelay {
				delay = reconnectMaxDelay
			}
		}

		sessDone := sess.CloseChan()
		conv := conn.GetConv()

		// Accept connections until the session dies.
		sessionAlive := true
		for sessionAlive {
			ln.SetDeadline(time.Now().Add(sessionCheckInterval))
			local, err := ln.Accept()
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					// Check if session is still alive.
					select {
					case <-sessDone:
						sessionAlive = false
					case <-transportErrCh:
						sessionAlive = false
					default:
					}
					continue
				}
				// Fatal listener error.
				sess.Close()
				conn.Close()
				return err
			}

			// Check session health before spawning handler.
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
				err := handle(local.(*net.TCPConn), sess, conv, streamTimeout)
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

func main() {
	var dohURL string
	var dotAddr string
	var domainArg string
	var listenAddr string
	var pubkeyFilename string
	var pubkeyString string
	var udpAddr string
	var utlsDistribution string
	var maxQnameLen int
	var maxNumLabels int
	var rpsLimit float64
	var idleTimeoutStr string
	var keepAliveStr string
	var reconnectMinStr string
	var reconnectMaxStr string
	var sessionCheckIntervalStr string
	var openStreamTimeoutStr string
	var maxStreams int
	var udpWorkers int
	var udpSharedSocket bool
	var udpTimeoutStr string
	var udpAcceptErrors bool
	var compatDnstt bool
	var clientIDSize int

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), `Usage:
  %[1]s [-doh URL|-dot ADDR|-udp ADDR] -pubkey-file PUBKEYFILE -domain DOMAIN -listen LOCALADDR

Examples:
  %[1]s -doh https://resolver.example/dns-query -pubkey-file server.pub -domain t.example.com -listen 127.0.0.1:7000
  %[1]s -dot resolver.example:853 -pubkey-file server.pub -domain t.example.com -listen 127.0.0.1:7000

`, os.Args[0])
		flag.PrintDefaults()
		labels := make([]string, 0, len(utlsClientHelloIDMap))
		labels = append(labels, "none")
		for _, entry := range utlsClientHelloIDMap {
			labels = append(labels, entry.Label)
		}
		fmt.Fprintf(flag.CommandLine.Output(), `
Known TLS fingerprints for -utls are:
`)
		i := 0
		for i < len(labels) {
			var line strings.Builder
			fmt.Fprintf(&line, "  %s", labels[i])
			w := 2 + len(labels[i])
			i++
			for i < len(labels) && w+1+len(labels[i]) <= 72 {
				fmt.Fprintf(&line, " %s", labels[i])
				w += 1 + len(labels[i])
				i++
			}
			fmt.Fprintln(flag.CommandLine.Output(), line.String())
		}
	}
	flag.StringVar(&dohURL, "doh", "", "URL of DoH resolver")
	flag.StringVar(&dotAddr, "dot", "", "address of DoT resolver")
	flag.StringVar(&pubkeyString, "pubkey", "", fmt.Sprintf("server public key (%d hex digits)", noise.KeyLen*2))
	flag.StringVar(&pubkeyFilename, "pubkey-file", "", "read server public key from file")
	flag.StringVar(&udpAddr, "udp", "", "address of UDP DNS resolver")
	flag.StringVar(&utlsDistribution, "utls",
		"4*random,3*Firefox_120,1*Firefox_105,3*Chrome_120,1*Chrome_102,1*iOS_14,1*iOS_13",
		"choose TLS fingerprint from weighted distribution")
	flag.StringVar(&domainArg, "domain", "", "tunnel domain (e.g., t.example.com)")
	flag.StringVar(&listenAddr, "listen", "", "TCP address to listen on for local connections (e.g., 127.0.0.1:7000)")
	flag.IntVar(&maxQnameLen, "max-qname-len", 101, "maximum total QNAME length in wire format (0 = 253 per RFC 1035)")
	flag.IntVar(&maxNumLabels, "max-num-labels", 0, "maximum number of data labels in query name (0 = unlimited)")
	flag.Float64Var(&rpsLimit, "rps", 0, "limit outgoing DNS queries per second (0 = unlimited)")
	// idle-timeout: if no data is received from the server for this long,
	// the tunnel session is considered dead and the client will reconnect.
	// Lower values detect broken connections faster but may cause spurious
	// reconnects on slow or lossy DNS paths.
	flag.StringVar(&idleTimeoutStr, "idle-timeout", defaultIdleTimeout.String(), "session idle timeout (e.g. 10s, 1m); reconnects if no data received within this period")
	// keepalive: how often smux sends keepalive pings to detect dead sessions.
	// Must be shorter than idle-timeout so multiple pings are attempted
	// before the session is declared dead.
	flag.StringVar(&keepAliveStr, "keepalive", defaultKeepAlive.String(), "keepalive ping interval (e.g. 2s, 500ms); must be less than idle-timeout")
	flag.StringVar(&reconnectMinStr, "reconnect-min", defaultReconnectDelay.String(), "minimum delay before retrying session creation (e.g. 500ms, 1s)")
	flag.StringVar(&reconnectMaxStr, "reconnect-max", defaultReconnectMaxDelay.String(), "maximum delay before retrying session creation (e.g. 5s, 30s)")
	flag.StringVar(&sessionCheckIntervalStr, "session-check-interval", defaultSessionCheckInterval.String(), "interval for checking whether the current session is still alive (e.g. 100ms, 500ms)")
	flag.StringVar(&openStreamTimeoutStr, "open-stream-timeout", defaultOpenStreamTimeout.String(), "timeout for opening an smux stream (e.g. 500ms, 3s)")
	flag.IntVar(&maxStreams, "max-streams", 256, "max concurrent streams per session (0 = unlimited)")
	flag.IntVar(&udpWorkers, "udp-workers", 100, "number of concurrent UDP worker goroutines")
	flag.BoolVar(&udpSharedSocket, "udp-shared-socket", false, "use a single shared UDP socket instead of per-query sockets")
	// udp-timeout: how long each UDP worker waits for a DNS response after
	// sending a query. If no response arrives, the query is considered lost.
	flag.StringVar(&udpTimeoutStr, "udp-timeout", defaultUDPResponseTimeout.String(), "per-query UDP response timeout (e.g. 200ms, 1s)")
	// udp-accept-errors: when given, non-NOERROR DNS responses (SERVFAIL,
	// NXDOMAIN, REFUSED, etc.) are passed through instead of being dropped.
	// By default, error responses are silently dropped assuming they are
	// forged by censorship, and the worker keeps waiting for a real response
	// until udp-timeout.
	flag.BoolVar(&udpAcceptErrors, "udp-accept-errors", false, "accept DNS error responses instead of filtering them (disables censorship evasion)")
	flag.BoolVar(&compatDnstt, "dnstt-compat", false, "use original dnstt wire format (8-byte ClientID, padding prefixes)")
	flag.IntVar(&clientIDSize, "clientid-size", 2, "client ID size in bytes (ignored when -dnstt-compat is set)")

	var logLevel string
	flag.StringVar(&logLevel, "log-level", "warning", "log level (debug, info, warning, error)")
	flag.Parse()

	level, err := log.ParseLevel(logLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid log level: %s\n", logLevel)
		os.Exit(1)
	}
	log.SetLevel(level)
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true, TimestampFormat: "2006-01-02 15:04:05"})

	if flag.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "unexpected positional arguments\n")
		flag.Usage()
		os.Exit(1)
	}
	if domainArg == "" {
		fmt.Fprintf(os.Stderr, "the -domain option is required\n")
		os.Exit(1)
	}
	if listenAddr == "" {
		fmt.Fprintf(os.Stderr, "the -listen option is required\n")
		os.Exit(1)
	}
	domain, err := dns.ParseName(domainArg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid domain %+q: %v\n", domainArg, err)
		os.Exit(1)
	}
	log.Infof("using domain: %s", domain)
	localAddr, err := net.ResolveTCPAddr("tcp", listenAddr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	var pubkey []byte
	if pubkeyFilename != "" && pubkeyString != "" {
		fmt.Fprintf(os.Stderr, "only one of -pubkey and -pubkey-file may be used\n")
		os.Exit(1)
	} else if pubkeyFilename != "" {
		var err error
		pubkey, err = readKeyFromFile(pubkeyFilename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot read pubkey from file: %v\n", err)
			os.Exit(1)
		}
	} else if pubkeyString != "" {
		var err error
		pubkey, err = noise.DecodeKey(pubkeyString)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pubkey format error: %v\n", err)
			os.Exit(1)
		}
	}
	if len(pubkey) == 0 {
		fmt.Fprintf(os.Stderr, "the -pubkey or -pubkey-file option is required\n")
		os.Exit(1)
	}

	utlsClientHelloID, err := sampleUTLSDistribution(utlsDistribution)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parsing -utls: %v\n", err)
		os.Exit(1)
	}
	if utlsClientHelloID != nil {
		log.Infof("uTLS fingerprint %s %s", utlsClientHelloID.Client, utlsClientHelloID.Version)
	}

	// Iterate over the remote resolver address options and select one and
	// only one.
	var remoteAddr net.Addr
	var pconn net.PacketConn
	for _, opt := range []struct {
		s string
		f func(string) (net.Addr, net.PacketConn, error)
	}{
		// -doh
		{dohURL, func(s string) (net.Addr, net.PacketConn, error) {
			addr := turbotunnel.DummyAddr{}
			var rt http.RoundTripper
			if utlsClientHelloID == nil {
				transport := http.DefaultTransport.(*http.Transport).Clone()
				// Disable DefaultTransport's default Proxy =
				// ProxyFromEnvironment setting, for conformity
				// with utlsRoundTripper and with DoT mode,
				// which do not take a proxy from the
				// environment.
				transport.Proxy = nil
				rt = transport
			} else {
				rt = NewUTLSRoundTripper(nil, utlsClientHelloID)
			}
			pconn, err := NewHTTPPacketConn(rt, dohURL, 32)
			return addr, pconn, err
		}},
		// -dot
		{dotAddr, func(s string) (net.Addr, net.PacketConn, error) {
			addr := turbotunnel.DummyAddr{}
			var dialTLSContext func(ctx context.Context, network, addr string) (net.Conn, error)
			if utlsClientHelloID == nil {
				dialTLSContext = (&tls.Dialer{}).DialContext
			} else {
				dialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
					return utlsDialContext(ctx, network, addr, nil, utlsClientHelloID)
				}
			}
			pconn, err := NewTLSPacketConn(dotAddr, dialTLSContext)
			return addr, pconn, err
		}},
		// -udp
		{udpAddr, func(s string) (net.Addr, net.PacketConn, error) {
			addr, err := net.ResolveUDPAddr("udp", s)
			if err != nil {
				return nil, nil, err
			}
			if udpSharedSocket {
				lc := net.ListenConfig{Control: dialerControl}
				pconn, err := lc.ListenPacket(context.Background(), "udp", ":0")
				return addr, pconn, err
			}
			udpTimeout, err := time.ParseDuration(udpTimeoutStr)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid -udp-timeout: %v", err)
			}
			pconn, err := NewUDPPacketConn(addr, dialerControl, udpWorkers, udpTimeout, !udpAcceptErrors)
			return addr, pconn, err
		}},
	} {
		if opt.s == "" {
			continue
		}
		if pconn != nil {
			fmt.Fprintf(os.Stderr, "only one of -doh, -dot, and -udp may be given\n")
			os.Exit(1)
		}
		var err error
		remoteAddr, pconn, err = opt.f(opt.s)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if pconn == nil {
		fmt.Fprintf(os.Stderr, "one of -doh, -dot, or -udp is required\n")
		os.Exit(1)
	}

	idleTimeout, err := time.ParseDuration(idleTimeoutStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -idle-timeout: %v\n", err)
		os.Exit(1)
	}
	keepAlive, err := time.ParseDuration(keepAliveStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -keepalive: %v\n", err)
		os.Exit(1)
	}
	reconnectMinDelay, err := time.ParseDuration(reconnectMinStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -reconnect-min: %v\n", err)
		os.Exit(1)
	}
	reconnectMaxDelay, err := time.ParseDuration(reconnectMaxStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -reconnect-max: %v\n", err)
		os.Exit(1)
	}
	sessionCheckInterval, err := time.ParseDuration(sessionCheckIntervalStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -session-check-interval: %v\n", err)
		os.Exit(1)
	}
	openStreamTimeout, err := time.ParseDuration(openStreamTimeoutStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -open-stream-timeout: %v\n", err)
		os.Exit(1)
	}
	if keepAlive >= idleTimeout {
		fmt.Fprintf(os.Stderr, "-keepalive (%s) must be less than -idle-timeout (%s)\n", keepAlive, idleTimeout)
		os.Exit(1)
	}
	if reconnectMinDelay <= 0 {
		fmt.Fprintf(os.Stderr, "-reconnect-min (%s) must be greater than 0\n", reconnectMinDelay)
		os.Exit(1)
	}
	if reconnectMaxDelay < reconnectMinDelay {
		fmt.Fprintf(os.Stderr, "-reconnect-max (%s) must be greater than or equal to -reconnect-min (%s)\n", reconnectMaxDelay, reconnectMinDelay)
		os.Exit(1)
	}
	if sessionCheckInterval <= 0 {
		fmt.Fprintf(os.Stderr, "-session-check-interval (%s) must be greater than 0\n", sessionCheckInterval)
		os.Exit(1)
	}
	if openStreamTimeout <= 0 {
		fmt.Fprintf(os.Stderr, "-open-stream-timeout (%s) must be greater than 0\n", openStreamTimeout)
		os.Exit(1)
	}

	var wireConfig turbotunnel.WireConfig
	if compatDnstt {
		wireConfig = turbotunnel.WireConfig{ClientIDSize: 8, Compat: true}
		// Override vaydns defaults with dnstt-compatible values unless
		// the user explicitly set them.
		explicitFlags := make(map[string]bool)
		flag.Visit(func(f *flag.Flag) {
			explicitFlags[f.Name] = true
		})
		if !explicitFlags["max-qname-len"] {
			maxQnameLen = 253
		}
		if !explicitFlags["idle-timeout"] {
			idleTimeout = 2 * time.Minute
		}
		if !explicitFlags["keepalive"] {
			keepAlive = 10 * time.Second
		}
	} else {
		if clientIDSize <= 0 {
			fmt.Fprintf(os.Stderr, "-clientid-size must be positive\n")
			os.Exit(1)
		}
		wireConfig = turbotunnel.WireConfig{ClientIDSize: clientIDSize}
	}

	// Re-validate keepalive/idle after potential compat overrides.
	if keepAlive >= idleTimeout {
		fmt.Fprintf(os.Stderr, "-keepalive (%s) must be less than -idle-timeout (%s)\n", keepAlive, idleTimeout)
		os.Exit(1)
	}

	// Validate that the QNAME length produces a usable MTU.
	capacity := dnsNameCapacity(domain, maxQnameLen, maxNumLabels)
	overhead := wireConfig.DataOverhead()
	if capacity-overhead < 50 {
		fmt.Fprintf(os.Stderr, "-max-qname-len %d with %d-byte overhead leaves only %d bytes for payload (need 50); increase -max-qname-len\n",
			maxQnameLen, overhead, capacity-overhead)
		os.Exit(1)
	}

	log.Infof("wire config: clientid-size=%d compat=%v", wireConfig.ClientIDSize, wireConfig.Compat)

	rateLimiter := NewRateLimiter(rpsLimit)
	if rateLimiter != nil {
		log.Infof("rate limiting DNS queries to %.1f requests per second", rpsLimit)
	}
	dnsPconn := NewDNSPacketConn(pconn, remoteAddr, domain, rateLimiter, maxQnameLen, maxNumLabels, wireConfig)
	err = run(pubkey, domain, localAddr, remoteAddr, dnsPconn, maxQnameLen, maxNumLabels, idleTimeout, keepAlive, reconnectMinDelay, reconnectMaxDelay, sessionCheckInterval, openStreamTimeout, maxStreams, dnsPconn.TransportErrors(), wireConfig)
	if err != nil {
		log.Fatalf("%v", err)
	}
}
