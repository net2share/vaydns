// Package turbotunnel is facilities for embedding packet-based reliability
// protocols inside other protocols.
//
// https://github.com/net4people/bbs/issues/9
package turbotunnel

import (
	"errors"
	"fmt"
	"strings"
)

// QueueSize is the size of send and receive queues in QueuePacketConn and
// RemoteMap.
const QueueSize = 512

// QueueOverflowMode controls how QueuePacketConn behaves when its queues are
// full.
type QueueOverflowMode string

const (
	// QueueOverflowDrop silently drops packets when queues are full. This is
	// the original dnstt/vaydns behavior and the correct default for
	// KCP-over-DNS where KCP handles retransmission of lost packets.
	QueueOverflowDrop QueueOverflowMode = "drop"
	// QueueOverflowBlock applies backpressure by blocking writers until queue
	// space is available or the connection is closed.
	QueueOverflowBlock QueueOverflowMode = "block"

	DefaultQueueOverflowMode = QueueOverflowDrop
)

// ParseQueueOverflowMode validates a queue overflow mode string.
func ParseQueueOverflowMode(s string) (QueueOverflowMode, error) {
	switch mode := QueueOverflowMode(strings.ToLower(s)); mode {
	case "":
		return DefaultQueueOverflowMode, nil
	case QueueOverflowDrop, QueueOverflowBlock:
		return mode, nil
	default:
		return "", fmt.Errorf("invalid queue overflow mode %q (want drop or block)", s)
	}
}

var errClosedPacketConn = errors.New("operation on closed connection")
var errNotImplemented = errors.New("not implemented")

// DummyAddr is a placeholder net.Addr, for when a programming interface
// requires a net.Addr but there is none relevant. All DummyAddrs compare equal
// to each other.
type DummyAddr struct{}

func (addr DummyAddr) Network() string { return "dummy" }
func (addr DummyAddr) String() string  { return "dummy" }
