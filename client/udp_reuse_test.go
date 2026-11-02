package client

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/net2share/vaydns/turbotunnel"
)

// With ReuseSockets a worker keeps one socket: each query gets its own answer
// (matched by DNS ID), a late answer to an earlier query is skipped, and the
// worker's source port stays the same.
func TestUDPPacketConnReuseSockets(t *testing.T) {
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	var mu sync.Mutex
	ports := map[string]bool{}
	go func() {
		buf := make([]byte, 512)
		var last []byte
		for {
			n, from, err := server.ReadFrom(buf)
			if err != nil {
				return
			}
			mu.Lock()
			ports[from.String()] = true
			mu.Unlock()
			q := append([]byte(nil), buf[:n]...)
			if last != nil {
				_, _ = server.WriteTo(last, from) // the previous answer again, late
			}
			resp := append([]byte(nil), q...)
			resp[2] |= 0x80 // QR
			_, _ = server.WriteTo(resp, from)
			last = resp
		}
	}()
	conn, _, err := NewUDPPacketConn(server.LocalAddr(), nil, 1, time.Second, true, 16, turbotunnel.QueueOverflowBlock)
	if err != nil {
		t.Fatal(err)
	}
	conn.ReuseSockets.Store(true)
	defer conn.Close()
	for id := 1; id <= 5; id++ {
		q := make([]byte, 12)
		q[0], q[1] = byte(id>>8), byte(id)
		q[5] = 0 // no questions: enough for the transport
		if _, err := conn.WriteTo(q, server.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 512)
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			t.Fatalf("query %d: %v", id, err)
		}
		if got := int(buf[0])<<8 | int(buf[1]); n < 12 || got != id {
			t.Fatalf("query %d got the answer of %d", id, got)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(ports) != 1 {
		t.Fatalf("the worker used %d source ports, want 1", len(ports))
	}
}
