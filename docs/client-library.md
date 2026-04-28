# Client Library

The `client` package provides a reusable Go library for building DNS tunnel clients.

## Import

```go
import "github.com/net2share/vaydns/client"
```

## Usage

There are two ways to use the library:

### Step-by-step API

For embedding in frameworks like xray-core where you need control over each layer:

```go
r, _ := client.NewResolver(client.ResolverTypeUDP, "8.8.8.8:53")
ts, _ := client.NewTunnelServer("t.example.com", "pubkey-hex")
t, _ := client.NewTunnel(r, ts)

t.InitiateResolverConnection()
t.InitiateDNSPacketConn(ts.Addr)
t.InitiateKCPConn(ts.MTU)
t.InitiateNoiseChannel()
t.InitiateSmuxSession()

stream, _ := t.OpenStream() // returns net.Conn
defer t.Close()
```

Each `Initiate*` method sets up one layer of the protocol stack. `OpenStream()` returns a `net.Conn` that can be used like any TCP connection.

### Managed API

For standalone clients that need automatic session management and reconnection:

```go
r, _ := client.NewResolver(client.ResolverTypeUDP, "8.8.8.8:53")
ts, _ := client.NewTunnelServer("t.example.com", "pubkey-hex")
t, _ := client.NewTunnel(r, ts)

t.ListenAndServe("127.0.0.1:7000") // blocks, handles reconnection
```

`ListenAndServe` opens a local TCP listener, creates tunnel sessions with automatic reconnection on failure, and forwards connections through the tunnel.

## Key types

| Type | Description |
|------|-------------|
| `Resolver` | DNS transport configuration (UDP, DoT, or DoH) |
| `TunnelServer` | Server domain + public key + wire protocol settings |
| `Tunnel` | Main tunnel connection with session and timeout configuration |
| `Outbound` | High-level API for multiple resolver/server pairs |

## Resolver types

```go
client.ResolverTypeUDP  // plaintext UDP DNS
client.ResolverTypeDOT  // DNS over TLS (RFC 7858)
client.ResolverTypeDOH  // DNS over HTTPS (RFC 8484)
```

## Configuration

All configuration is done through struct fields before calling `Initiate*` or `ListenAndServe`:

```go
// Resolver options
r.UTLSClientHelloID = &utls.ClientHelloID{...} // TLS fingerprint
r.RoundTripper = customTransport                // custom HTTP transport for DoH (overrides UTLSClientHelloID)
r.DialerControl = controlFunc                   // socket options callback (SO_MARK, SO_BINDTODEVICE, etc.)
r.UDPWorkers = 200                              // concurrent UDP workers
r.UDPSharedSocket = true                        // single socket mode
r.UDPTimeout = 500 * time.Millisecond           // per-query timeout
r.UDPAcceptErrors = true                        // accept non-NOERROR responses (disables forged filtering)

// Tunnel server options
ts.DnsttCompat = true    // original dnstt wire format
ts.ClientIDSize = 1      // smaller ClientID
ts.MaxQnameLen = 101     // QNAME length constraint
ts.MaxNumLabels = 2      // label count constraint
ts.RPS = 200             // rate limit queries/second
ts.RecordType = "cname"  // DNS record type for downstream data: txt, null, cname, a, aaaa, mx, ns, srv, caa (default: "txt")

// Session options
t.IdleTimeout = 60 * time.Second
t.KeepAlive = 10 * time.Second
t.OpenStreamTimeout = 10 * time.Second
t.MaxStreams = 256
t.SessionCheckInterval = 500 * time.Millisecond
t.ReconnectMinDelay = 1 * time.Second
t.ReconnectMaxDelay = 30 * time.Second
t.HandshakeTimeout = 15 * time.Second

// Transport queue options
t.PacketQueueSize = 512                                // queue capacity
t.KCPWindowSize = 256                                  // KCP window (0 = queue-size/2)
t.QueueOverflowMode = turbotunnel.QueueOverflowDrop    // "drop" or "block"
```

Zero values use sensible defaults. See the [README](../README.md) for flag descriptions — each flag maps directly to a struct field.
