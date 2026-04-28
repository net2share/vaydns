# VayDNS

Userspace DNS tunnel with support for DoH, DoT, and plaintext UDP.

> VayDNS is a fork of [dnstt](https://www.bamsoftware.com/software/dnstt/) by David Fifield, with protocol optimizations and additional features. The wire protocol differs from upstream dnstt by default, but the `-dnstt-compat` flag enables interoperability with original dnstt clients and servers.

## Features

- **Multiple transports** — DNS over HTTPS (DoH), DNS over TLS (DoT), and plaintext UDP
- **Reliable delivery** — KCP/smux session protocol with automatic retransmission
- **End-to-end encryption** — Noise protocol with server authentication by public key
- **TLS fingerprint camouflage** — uTLS randomizes the client's TLS fingerprint
- **Censorship resistance** — per-query UDP sockets with forged-response filtering
- **Auto-recovery** — client automatically reconnects on session failure

## Architecture

```
.------.  |            .---------.             .------.
|tunnel|  |            | public  |             |tunnel|
|client|<---DoH/DoT--->|recursive|<--UDP DNS-->|server|
'------'  |c           |resolver |             '------'
   |      |e           '---------'                |
.------.  |n                                   .------.
|local |  |s                                   |remote|
| app  |  |o                                   | app  |
'------'  |r                                   '------'
```

VayDNS is an application-layer tunnel that runs in userspace. It connects a local TCP port to a remote TCP port by way of a DNS resolver. It does not provide a TUN/TAP interface or a built-in proxy — pair it with a SOCKS or HTTP proxy on the server side.

## Quick start

### 1. Build

```sh
go build -o vaydns-server ./vaydns-server
go build -o vaydns-client ./vaydns-client
```

### 2. Generate keys

```sh
./vaydns-server -gen-key -privkey-file server.key -pubkey-file server.pub
```

Copy `server.pub` to the client. Keep `server.key` on the server only.

### 3. Run the server

```sh
./vaydns-server -udp :5300 -privkey-file server.key \
  -domain t.example.com -upstream 127.0.0.1:8000
```

You also need something for the server to forward to (a proxy, SSH, etc.). For testing, use an Ncat listener:

```sh
ncat -l -k -v 127.0.0.1 8000
```

### 4. Run the client

Choose a public resolver. Lists of DoH resolvers: [curl wiki](https://github.com/curl/curl/wiki/DNS-over-HTTPS#publicly-available-servers). DoT resolvers: [dnsprivacy.org](https://dnsprivacy.org/wiki/display/DP/DNS+Privacy+Public+Resolvers#DNSPrivacyPublicResolvers-DNS-over-TLS%28DoT%29), [dnsencryption.info](https://dnsencryption.info/imc19-doe.html).

Using plaintext UDP (no covertness):

```sh
./vaydns-client -udp 8.8.8.8:53 \
  -pubkey-file server.pub -domain t.example.com -listen 127.0.0.1:7000
```

Using DoH:

```sh
./vaydns-client -doh https://doh.example/dns-query \
  -pubkey-file server.pub -domain t.example.com -listen 127.0.0.1:7000
```

Using DoT:

```sh
./vaydns-client -dot dot.example:853 \
  -pubkey-file server.pub -domain t.example.com -listen 127.0.0.1:7000
```

### 5. Test

```sh
ncat -v 127.0.0.1 7000
```

## DNS zone setup

The server acts as an authoritative nameserver, so you need a domain with an NS record pointing to it. For example, if your domain is `example.com` and your server IP is `203.0.113.2`:

| Type | Name            | Value           |
| ---- | --------------- | --------------- |
| A    | tns.example.com | 203.0.113.2     |
| AAAA | tns.example.com | 2001:db8::2     |
| NS   | t.example.com   | tns.example.com |

- `tns` is the glue record pointing to your server's IP
- `t` is the tunnel subdomain (keep it short to maximize payload space)
- `tns` must **not** be a subdomain of `t`

Queries for `*.t.example.com` will now be forwarded to your tunnel server.

### Port forwarding

The server needs to receive DNS on port 53. Rather than running as root, listen on an unprivileged port and redirect:

```sh
sudo iptables -I INPUT -p udp --dport 5300 -j ACCEPT
sudo iptables -t nat -I PREROUTING -i eth0 -p udp --dport 53 -j REDIRECT --to-ports 5300
sudo ip6tables -I INPUT -p udp --dport 5300 -j ACCEPT
sudo ip6tables -t nat -I PREROUTING -i eth0 -p udp --dport 53 -j REDIRECT --to-ports 5300
```

## Configuration reference

### Server flags

| Flag                 | Description                                | Default    |
| -------------------- | ------------------------------------------ | ---------- |
| `-udp ADDR`          | Listen address for UDP DNS                                        | (required) |
| `-domain NAME`       | Tunnel domain                                                     | (required) |
| `-upstream ADDR`     | Forward tunnel streams to this TCP address                        | (required) |
| `-privkey-file PATH` | Server private key file                                           | —          |
| `-privkey HEX`       | Server private key as hex string                                  | —          |
| `-gen-key`           | Generate a new keypair and exit                                   | —          |
| `-mtu N`             | Max UDP payload size for responses                                | `1232`     |
| `-idle-timeout D`    | Session idle timeout (must match client)                          | `10s`      |
| `-keepalive D`       | Keepalive ping interval (must match client, must be < idle-timeout) | `2s`      |
| `-fallback ADDR`     | UDP endpoint to forward non-DNS packets to (e.g. `127.0.0.1:8888`) | —          |
| `-dnstt-compat`      | Use original dnstt wire format (8-byte ClientID, padding prefixes). Also sets `-idle-timeout` to 2m and `-keepalive` to 10s unless explicitly overridden. | `false`    |
| `-clientid-size N`   | ClientID size in bytes (ignored when `-dnstt-compat` is set)       | `2`        |
| `-record-type TYPE`  | DNS record type for downstream data: `txt`, `null`, `cname`, `a`, `aaaa`, `mx`, `ns`, `srv`, `caa`. Must match the client. Ignored (forced to `txt`) when `-dnstt-compat` is set. | `txt`      |
| `-queue-size N`      | Packet queue size for transport and DNS layers                    | `512`      |
| `-kcp-window-size N` | KCP send/receive window size in packets (0 = queue-size/2)        | `0`        |
| `-queue-overflow MODE` | Queue overflow behavior: `drop` (silent discard) or `block` (backpressure) | `drop`     |
| `-log-level LEVEL`   | Log level: debug, info, warning, error                            | `info`     |

### Client flags

#### Transport (pick one)

| Flag        | Description                                      |
| ----------- | ------------------------------------------------ |
| `-doh URL`  | Use DNS over HTTPS with the given resolver URL   |
| `-dot ADDR` | Use DNS over TLS with the given resolver address |
| `-udp ADDR` | Use plaintext UDP DNS (no covertness)            |

#### Required

| Flag                | Description                                                     |
| ------------------- | --------------------------------------------------------------- |
| `-domain NAME`      | Tunnel domain                                                   |
| `-listen ADDR`      | Local TCP listen address                                        |
| `-pubkey-file PATH` | Server public key file                                          |
| `-pubkey HEX`       | Server public key as hex string (alternative to `-pubkey-file`) |

#### Session and recovery

| Flag                        | Description                                        | Default |
| --------------------------- | -------------------------------------------------- | ------- |
| `-idle-timeout D`           | Session idle timeout (must match server)                                                    | `10s`   |
| `-keepalive D`              | Keepalive ping interval (must match server, must be < idle-timeout)                         | `2s`   |
| `-max-streams N`            | Max concurrent streams per session (0 = unlimited)                                          | `0`   |
| `-open-stream-timeout D`    | Timeout for opening an smux stream                                                          | `10s`   |
| `-reconnect-min D`          | Initial backoff delay for session reconnect                                                  | `1s`    |
| `-reconnect-max D`          | Max backoff delay (must be >= reconnect-min)                                                 | `30s`   |

> **Note:** `idle-timeout` and `keepalive` must be set to the same values on both client and server — mismatched values will cause one side to close the session before the other detects it. Keep `keepalive` well below `idle-timeout` (the default 5x ratio allows ~5 ping attempts before timeout).
>
> **How they relate:** `keepalive` controls how often smux sends ping frames to prove the session is alive. `idle-timeout` is how long smux waits with no received data (including pings) before declaring the session dead — it applies symmetrically on both sides.

#### UDP transport tuning

These flags only apply when using `-udp`. By default, each query is sent from a fresh socket with a randomized source port.

| Flag                 | Description                                                                                                                                                | Default |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- |
| `-udp-workers N`     | Concurrent UDP worker goroutines                                                                                                                           | `100`   |
| `-udp-timeout D`     | Per-query response timeout — the total time a worker waits for a valid (NOERROR) response. Forged responses are discarded but the deadline is not extended — if no valid response arrives within this window, the query is abandoned. | `500ms` |
| `-udp-shared-socket` | Use a single shared UDP socket instead of per-query sockets. By default, each query is sent from a new socket with a random ephemeral source port, making the tunnel harder to fingerprint or block by port. With this flag, all queries share one socket and source port for the lifetime of the client — blocking that port kills the tunnel. | `false` |
| `-udp-accept-errors` | In per-query mode, accept the first DNS response regardless of RCODE instead of waiting for a NOERROR response. This disables forged response filtering — the worker stops waiting after the first forged response, so the real response is likely lost. Only useful for debugging; not recommended in production. Ignored when `-udp-shared-socket` is set. | `false` |

#### Queue and KCP tuning

These flags apply to all transports (UDP, DoH, DoT) on the client side. The server has the same flags.

| Flag                   | Description                                                        | Default |
| ---------------------- | ------------------------------------------------------------------ | ------- |
| `-queue-size N`        | Packet queue size for transport and DNS layers                     | `512`   |
| `-kcp-window-size N`   | KCP send/receive window size in packets (0 = queue-size/2). Must be <= queue-size. | `0`     |
| `-queue-overflow MODE` | Queue overflow behavior: `drop` (silent discard, KCP retransmits) or `block` (backpressure). | `drop`  |

> **Note:** `drop` is the correct default for most deployments. It matches the original dnstt design where KCP handles retransmission of locally dropped packets. `block` mode applies backpressure instead of dropping — this can help in some censored network conditions but may slow down UDP transport significantly. Both client and server can use different modes independently.

#### QNAME constraints

Some resolvers reject queries with long QNAMEs or too many labels.

| Flag                | Description                                                                 | Default |
| ------------------- | --------------------------------------------------------------------------- | ------- |
| `-max-qname-len N`  | Max total QNAME length in wire format (0 = RFC 1035 max of 253)             | `101`   |
| `-max-num-labels N` | Max data labels before the tunnel domain (0 = unlimited, 1 = most DNS-like) | `0`     |

These reduce upstream throughput but improve compatibility. The minimum effective MTU is 50 bytes — below that the client exits with an error.

> **How these interact:** The client computes the upstream MTU from the tunnel domain length, `max-qname-len`, and `max-num-labels`. The relationship is:
>
> ```
> maxQnameLen >= dataLabelWireBytes + domainWireLen
> ```
>
> Where `domainWireLen` is the wire-format length of the tunnel domain (`1 + len` per label — e.g. `t.example.com` = 14 bytes), and `dataLabelWireBytes` must leave enough room for 53 raw bytes after base32 encoding and framing overhead (3 bytes in default mode, 13 bytes with `-dnstt-compat`). The default `max-qname-len=101` is sized to hit exactly 50 bytes MTU with a domain like `t.example.com`. With `-dnstt-compat`, the default is raised to 253 to accommodate the larger overhead. The client will exit with an error if the combination produces an MTU below 50 bytes.

#### Other

| Flag               | Description                                                | Default         |
| ------------------ | ---------------------------------------------------------- | --------------- |
| `-rps N`           | Rate limit outgoing DNS queries per second (0 = unlimited). Uses a token bucket with 1-second burst allowance. | `0`             |
| `-dnstt-compat`    | Use original dnstt wire format (8-byte ClientID, padding prefixes). Sets `-max-qname-len` to 253 unless explicitly overridden. Forces `-record-type` to `txt` with a warning if another type is set. | `false`         |
| `-clientid-size N` | ClientID size in bytes (ignored when `-dnstt-compat` is set) | `2`             |
| `-record-type TYPE` | DNS record type for downstream data: `txt`, `null`, `cname`, `a`, `aaaa`, `mx`, `ns`, `srv`, `caa`. Must match the server. | `txt`           |
| `-utls SPEC`       | TLS fingerprint distribution (see below)                   | weighted random |
| `-log-level LEVEL` | Log level: debug, info, warning, error                     | `info`          |

### TLS fingerprinting (client)

The client uses [uTLS](https://github.com/refraction-networking/utls) to disguise its TLS fingerprint. The `-utls` flag accepts a comma-separated list of fingerprints, optionally weighted:

```sh
./vaydns-client -utls '3*Firefox,2*Chrome,1*iOS' ...
./vaydns-client -utls Firefox ...
./vaydns-client -utls random ...   # fully randomized fingerprint
./vaydns-client -utls none ...     # native Go TLS (less covert, more compatible)
```

Run `./vaydns-client -help` to see all available fingerprint names.

## Proxy examples

VayDNS is only a tunnel — pair it with a proxy server for web browsing.

### HTTP proxy (Ncat)

> Ncat's proxy is not intended for use by untrusted clients — it won't prevent them from connecting to localhost ports on the server.

```sh
# Server
ncat -l -k --proxy-type http 127.0.0.1 8000
./vaydns-server -udp :5300 -privkey-file server.key -domain t.example.com -upstream 127.0.0.1:8000

# Client
./vaydns-client -doh https://doh.example/dns-query -pubkey-file server.pub -domain t.example.com -listen 127.0.0.1:7000
curl --proxy http://127.0.0.1:7000/ https://wtfismyip.com/text
```

### SOCKS5 proxy (SSH)

Server-side SOCKS (accessible to anyone with tunnel access):

```sh
# Server
ssh -N -D 127.0.0.1:8000 -o NoHostAuthenticationForLocalhost=yes 127.0.0.1
./vaydns-server -udp :5300 -privkey-file server.key -domain t.example.com -upstream 127.0.0.1:8000

# Client
./vaydns-client -doh https://doh.example/dns-query -pubkey-file server.pub -domain t.example.com -listen 127.0.0.1:7000
curl --proxy socks5h://127.0.0.1:7000/ https://wtfismyip.com/text
```

Client-side SOCKS (private, SSH through the tunnel). Ensure `AllowTcpForwarding yes` (default) is set in sshd_config. The `HostKeyAlias` option lets SSH verify the host key when connecting through the tunnel:

```sh
# Server — forward directly to SSH
./vaydns-server -udp :5300 -privkey-file server.key -domain t.example.com -upstream 127.0.0.1:22

# Client — tunnel SSH, then SOCKS through SSH
./vaydns-client -doh https://doh.example/dns-query -pubkey-file server.pub -domain t.example.com -listen 127.0.0.1:8000
ssh -N -D 127.0.0.1:7000 -o HostKeyAlias=tunnel-server -p 8000 127.0.0.1
curl --proxy socks5h://127.0.0.1:7000/ https://wtfismyip.com/text
```

### Tor bridge

```sh
# Server (ORPort 9001)
./vaydns-server -udp :5300 -privkey-file server.key -domain t.example.com -upstream 127.0.0.1:9001

# Client
./vaydns-client -doh https://doh.example/dns-query -pubkey-file server.pub -domain t.example.com -listen 127.0.0.1:7000
```

Add to `/etc/tor/torrc` or Tor Browser (`FINGERPRINT` from `/var/lib/tor/fingerprint`):

```
Bridge 127.0.0.1:7000 FINGERPRINT
```

System tor SOCKS port: `127.0.0.1:9050`. Tor Browser: `127.0.0.1:9150`.

## Security

### Encryption and authentication

The tunnel uses the [Noise protocol](https://noiseprotocol.org/noise.html) (`Noise_NK_25519_ChaChaPoly_BLAKE2s`) for end-to-end encryption, independent of DoH/DoT transport encryption. The NK handshake authenticates the server but not the client.

Protocol stack:

```
application data
smux              (stream multiplexing)
Noise             (encryption + authentication)
KCP               (reliable delivery over datagrams)
DNS messages
DoH / DoT / UDP
```

An observer at the resolver level can see KCP headers but cannot read smux frames or application data.

#### Key management

Generate and save keys to files:

```sh
./vaydns-server -gen-key -privkey-file server.key -pubkey-file server.pub
```

Or use hex strings directly:

```sh
./vaydns-server -gen-key
# privkey 0123456789abcdef...
# pubkey  0000111122223333...

./vaydns-server -udp :5300 -privkey 0123456789abcdef... -domain t.example.com -upstream 127.0.0.1:8000
./vaydns-client -dot dot.example:853 -pubkey 0000111122223333... -domain t.example.com -listen 127.0.0.1:7000
```

If no key is provided, the server generates a temporary keypair on each start.

### Covertness

DoH/DoT hides tunnel traffic from local network observers — they can see you're connecting to a resolver but not the tunnel destination or contents. An observer can likely infer from traffic volume that a tunnel is being used, but cannot determine the remote endpoint or read the contents. Without DoH/DoT (plaintext UDP), the tunnel is visible to anyone on the path, including its destination.

Observers between the resolver and the tunnel server (including the resolver itself) can identify the tunnel and its destination, but cannot read the encrypted contents.

An observer watching traffic leaving the tunnel server can see any unencrypted data the server forwards (e.g., to a proxy). To protect this leg, use end-to-end encryption (HTTPS, SSH, etc.) inside the tunnel.

### Payload sizes

Upstream (client → server) payload depends on the domain name length. Shorter domains = more space.

Downstream (server → client) payload depends on the UDP response size. The `-mtu` flag on the server controls the max UDP payload:

```sh
./vaydns-server -mtu 512 -udp :5300 -privkey-file server.key -domain t.example.com -upstream 127.0.0.1:8000
```

- Default: `1232` bytes (safe for most EDNS(0) resolvers)
- Max practical: `1452` (above this, IP fragmentation may hurt performance)
- Min compatible: `512` (reduced bandwidth)

Both client and server log their effective MTU at startup. The server's effective MTU is the minimum guaranteed across all responses (some responses may have more space depending on the query size).

## dnstt compatibility

By default, VayDNS uses a leaner wire protocol than dnstt (2-byte ClientID, no padding). The `-dnstt-compat` flag restores the original dnstt format on both client and server, enabling interoperability with upstream dnstt binaries.

```sh
# VayDNS server accepting connections from original dnstt clients
./vaydns-server -udp :5300 -dnstt-compat -privkey-file server.key \
  -domain t.example.com -upstream 127.0.0.1:8000

# VayDNS client connecting to an original dnstt server
./vaydns-client -doh https://doh.example/dns-query -dnstt-compat \
  -pubkey-file server.pub -domain t.example.com -listen 127.0.0.1:7000
```

Both sides must use the same mode — mixing compat and non-compat will fail silently.

The `-clientid-size` flag allows setting a custom ClientID size (e.g. 4 bytes) without enabling the full dnstt padding format. It is ignored when `-dnstt-compat` is set.

### What `-dnstt-compat` changes

On both client and server, `-dnstt-compat` switches to the original dnstt wire format (8-byte ClientID, padding prefixes) and overrides the following defaults to match dnstt's values:

| Setting | VayDNS default | With `-dnstt-compat` | Applies to |
| ------- | -------------- | -------------------- | ---------- |
| `-max-qname-len` | `101` | `253` | client |
| `-idle-timeout` | `10s` | `2m` | client and server |
| `-keepalive` | `2s` | `10s` | client and server |

All three can be explicitly overridden even when `-dnstt-compat` is set — the flag only changes the defaults, it does not lock the values. For example, `-dnstt-compat -idle-timeout 30s` uses the dnstt wire format with a 30-second idle timeout.

> **Note:** `-dnstt-compat` forces `-record-type` to `txt` (with a warning if another type was set). dnstt only supports TXT records, so other record types are incompatible.
>
> The timeout defaults are critical for interop with original dnstt binaries. dnstt uses a 10-second keepalive interval (smux default) and a 2-minute idle timeout. Setting `-idle-timeout` below 10s in compat mode will cause sessions to churn because dnstt peers only send keepalives every 10 seconds. When connecting to dnstt, keep the compat defaults unless you know what you're doing.

### Record types

VayDNS supports multiple DNS record types for downstream data encoding. Both client and server must use the same `-record-type`. The default is `txt`, which is compatible with original dnstt and older VayDNS versions.

| Type | Description | Capacity |
| ---- | ----------- | -------- |
| `txt` | TXT record (default). Highest capacity, compatible with dnstt. | Bounded by UDP payload (~1200 bytes) |
| `null` | NULL record. Raw binary payload in a single RR. Some recursive resolvers may filter or refuse to relay NULL records. | Bounded by UDP payload |
| `cname` | CNAME record. Data encoded as a DNS name under the tunnel domain. | Bounded by 255-byte DNS name limit |
| `ns` | NS record. Same encoding as CNAME. | Same as CNAME |
| `mx` | MX record. 2-byte preference header + name encoding. | Same as CNAME |
| `srv` | SRV record. 6-byte header + name encoding. | Same as CNAME |
| `a` | A records. Data split into 4-byte chunks across multiple answer RRs. | Bounded by UDP payload |
| `aaaa` | AAAA records. Data split into 16-byte chunks across multiple answer RRs. | Bounded by UDP payload |
| `caa` | CAA record. Payload encoded in the value portion of a fixed `issue` property. | Bounded by UDP payload |

> **Compatibility:** Old VayDNS clients (pre-record-type) only send TXT queries. A new server with the default `-record-type txt` is fully compatible with old clients. Using a non-TXT type requires updating both client and server.

### Wire protocol differences

| Aspect | VayDNS (default) | dnstt / `-dnstt-compat` |
| ------ | ---------------- | ----------------------- |
| ClientID | 2 bytes | 8 bytes |
| Data packet | `[ClientID][DataLen:1][Data]` | `[ClientID][224+3][Padding:3][DataLen:1][Data]` |
| Poll packet | `[ClientID][Nonce:4]` | `[ClientID][224+8][Padding:8]` |
| Max data/query | 255 bytes | 223 bytes |

## Client library

The `client` package (`github.com/net2share/vaydns/client`) provides a reusable Go library for embedding VayDNS in other applications. See [docs/client-library.md](docs/client-library.md) for usage and examples.

## E2E tests

End-to-end tests run the full tunnel stack in Docker containers. Requires Docker.

```sh
# Run all tests
bash e2e/run-test.sh

# Or individually
bash e2e/tunnel/run.sh           # basic tunnel (TXT, default)
bash e2e/tunnel/run.sh cname     # tunnel with CNAME records
bash e2e/socks-download/run.sh   # 10MB file download via SOCKS5
bash e2e/recovery/run.sh         # server crash recovery
```

## License

VayDNS is a fork of [dnstt](https://www.bamsoftware.com/software/dnstt/) by David Fifield. The original dnstt is public domain.
