package turbotunnel

// WireConfig holds wire protocol parameters that differ between VayDNS and
// dnstt compatibility mode.
type WireConfig struct {
	// ClientIDSize is the number of bytes used for the ClientID on the wire.
	// Default is 2 (VayDNS). dnstt compatibility mode sets this to 8.
	ClientIDSize int
	// Compat enables the original dnstt wire format with padding prefixes.
	Compat bool
}

// IsDnstt reports whether dnstt wire compatibility is active.
func (wc WireConfig) IsDnstt() bool {
	return wc.Compat
}

// DataOverhead returns the number of bytes consumed by per-query framing
// (ClientID, padding, length prefix) before the actual data payload.
func (wc WireConfig) DataOverhead() int {
	if wc.IsDnstt() {
		// dnstt: [ClientID][PaddingPrefix:1][Padding:3][DataLen:1]
		return wc.ClientIDSize + 1 + 3 + 1
	}
	// vaydns: [ClientID][DataLen:1]
	return wc.ClientIDSize + 1
}

// MaxDataLen returns the maximum number of data bytes that can be carried
// in a single upstream query packet.
func (wc WireConfig) MaxDataLen() int {
	if wc.IsDnstt() {
		// In dnstt, prefix bytes >= 224 are reserved for padding.
		return 223
	}
	return 255
}
