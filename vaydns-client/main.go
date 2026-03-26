// vaydns-client is the client end of a DNS tunnel.
//
// Usage:
//
//	vaydns-client [-doh URL|-dot ADDR|-udp ADDR] [-pubkey HEX|-pubkey-file FILENAME] -domain DOMAIN -listen LOCALADDR
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/net2share/vaydns/client"
	"github.com/net2share/vaydns/noise"
)

func readKeyFromFile(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return noise.ReadKey(f)
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
		labels := make([]string, 0)
		labels = append(labels, "none")
		for _, entry := range client.UTLSClientHelloIDMap() {
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
	flag.StringVar(&idleTimeoutStr, "idle-timeout", client.DefaultIdleTimeout.String(), "session idle timeout (e.g. 10s, 1m); reconnects if no data received within this period")
	flag.StringVar(&keepAliveStr, "keepalive", client.DefaultKeepAlive.String(), "keepalive ping interval (e.g. 2s, 500ms); must be less than idle-timeout")
	flag.StringVar(&reconnectMinStr, "reconnect-min", client.DefaultReconnectDelay.String(), "minimum delay before retrying session creation (e.g. 500ms, 1s)")
	flag.StringVar(&reconnectMaxStr, "reconnect-max", client.DefaultReconnectMaxDelay.String(), "maximum delay before retrying session creation (e.g. 5s, 30s)")
	flag.StringVar(&sessionCheckIntervalStr, "session-check-interval", client.DefaultSessionCheckInterval.String(), "interval for checking whether the current session is still alive (e.g. 100ms, 500ms)")
	flag.StringVar(&openStreamTimeoutStr, "open-stream-timeout", client.DefaultOpenStreamTimeout.String(), "timeout for opening an smux stream (e.g. 500ms, 3s)")
	flag.IntVar(&maxStreams, "max-streams", client.DefaultMaxStreams, "max concurrent streams per session (0 = unlimited)")
	flag.IntVar(&udpWorkers, "udp-workers", client.DefaultUDPWorkers, "number of concurrent UDP worker goroutines")
	flag.BoolVar(&udpSharedSocket, "udp-shared-socket", false, "use a single shared UDP socket instead of per-query sockets")
	flag.StringVar(&udpTimeoutStr, "udp-timeout", client.DefaultUDPResponseTimeout.String(), "per-query UDP response timeout (e.g. 200ms, 1s)")
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
	log.Infof("using domain: %s", domainArg)

	// Resolve public key.
	var pubkeyHex string
	if pubkeyFilename != "" && pubkeyString != "" {
		fmt.Fprintf(os.Stderr, "only one of -pubkey and -pubkey-file may be used\n")
		os.Exit(1)
	} else if pubkeyFilename != "" {
		pubkey, err := readKeyFromFile(pubkeyFilename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot read pubkey from file: %v\n", err)
			os.Exit(1)
		}
		pubkeyHex = hex.EncodeToString(pubkey)
	} else if pubkeyString != "" {
		pubkeyHex = pubkeyString
	}
	if pubkeyHex == "" {
		fmt.Fprintf(os.Stderr, "the -pubkey or -pubkey-file option is required\n")
		os.Exit(1)
	}

	// Select uTLS fingerprint.
	utlsClientHelloID, err := client.SampleUTLSDistribution(utlsDistribution)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parsing -utls: %v\n", err)
		os.Exit(1)
	}
	if utlsClientHelloID != nil {
		log.Infof("uTLS fingerprint %s %s", utlsClientHelloID.Client, utlsClientHelloID.Version)
	}

	// Select resolver transport.
	var resolverType client.ResolverType
	var resolverAddr string
	transportCount := 0
	if dohURL != "" {
		resolverType = client.ResolverTypeDOH
		resolverAddr = dohURL
		transportCount++
	}
	if dotAddr != "" {
		resolverType = client.ResolverTypeDOT
		resolverAddr = dotAddr
		transportCount++
	}
	if udpAddr != "" {
		resolverType = client.ResolverTypeUDP
		resolverAddr = udpAddr
		transportCount++
	}
	if transportCount == 0 {
		fmt.Fprintf(os.Stderr, "one of -doh, -dot, or -udp is required\n")
		os.Exit(1)
	}
	if transportCount > 1 {
		fmt.Fprintf(os.Stderr, "only one of -doh, -dot, and -udp may be given\n")
		os.Exit(1)
	}

	// Parse durations.
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
	udpTimeout, err := time.ParseDuration(udpTimeoutStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -udp-timeout: %v\n", err)
		os.Exit(1)
	}

	// Validate.
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

	// Apply -dnstt-compat overrides.
	if compatDnstt {
		explicitFlags := make(map[string]bool)
		flag.Visit(func(f *flag.Flag) {
			explicitFlags[f.Name] = true
		})
		if !explicitFlags["max-qname-len"] {
			maxQnameLen = 253
		}
		if !explicitFlags["idle-timeout"] {
			idleTimeout = client.DnsttIdleTimeout
		}
		if !explicitFlags["keepalive"] {
			keepAlive = client.DnsttKeepAlive
		}
		// Re-validate after overrides.
		if keepAlive >= idleTimeout {
			fmt.Fprintf(os.Stderr, "-keepalive (%s) must be less than -idle-timeout (%s)\n", keepAlive, idleTimeout)
			os.Exit(1)
		}
	}

	// Build resolver.
	resolver, err := client.NewResolver(resolverType, resolverAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolver: %v\n", err)
		os.Exit(1)
	}
	resolver.UTLSClientHelloID = utlsClientHelloID
	resolver.UDPWorkers = udpWorkers
	resolver.UDPSharedSocket = udpSharedSocket
	resolver.UDPTimeout = udpTimeout
	resolver.UDPAcceptErrors = udpAcceptErrors
	if udpAcceptErrors {
		if udpSharedSocket {
			log.Warnf("-udp-accept-errors has no effect when -udp-shared-socket is set")
		} else {
			log.Warnf("-udp-accept-errors disables forged response filtering; per-query workers will accept the first response regardless of RCODE, which may cause connection failures under DNS injection")
		}
	}

	// Build tunnel server config.
	ts, err := client.NewTunnelServer(domainArg, pubkeyHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	ts.DnsttCompat = compatDnstt
	ts.ClientIDSize = clientIDSize
	ts.MaxQnameLen = maxQnameLen
	ts.MaxNumLabels = maxNumLabels
	ts.RPS = rpsLimit

	// Build tunnel.
	tunnel, err := client.NewTunnel(resolver, ts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	tunnel.IdleTimeout = idleTimeout
	tunnel.KeepAlive = keepAlive
	tunnel.OpenStreamTimeout = openStreamTimeout
	tunnel.MaxStreams = maxStreams
	tunnel.ReconnectMinDelay = reconnectMinDelay
	tunnel.ReconnectMaxDelay = reconnectMaxDelay
	tunnel.SessionCheckInterval = sessionCheckInterval

	if compatDnstt {
		log.Infof("wire config: clientid-size=8 compat=true")
	} else {
		log.Infof("wire config: clientid-size=%d compat=false", clientIDSize)
	}

	if rpsLimit > 0 {
		log.Infof("rate limiting DNS queries to %.1f requests per second", rpsLimit)
	}

	err = tunnel.ListenAndServe(listenAddr)
	if err != nil {
		log.Fatalf("%v", err)
	}
}
