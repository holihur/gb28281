package sip

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestChaosUSPLossRetransmission(t *testing.T) {
	// 50% UDP packet loss; the NICT must eventually deliver the 200 via retransmits.
	clientTp, serverTp := newTestPair(t)
	dropped := uint64(0)
	total := uint64(0)
	clientTp.SetDropHook(func(msg Message, dst Addr) bool {
		if _, ok := msg.(*Request); ok {
			atomic.AddUint64(&total, 1)
			if atomic.LoadUint64(&total)%2 == 1 {
				atomic.AddUint64(&dropped, 1)
				return true
			}
		}
		return false
	})
	cm := NewTxManager(clientTp, "127.0.0.1", clientTp.UDPPort())
	sm := NewTxManager(serverTp, "127.0.0.1", serverTp.UDPPort())
	cm.SetConfig(fastConfig())
	sm.SetConfig(fastConfig())
	sm.SetOnRequest(func(req *Request, src Addr, stx *ServerTx) {
		_ = stx.Respond(NewResponse(200, ""))
	})
	cm.Run()
	sm.Run()

	req := NewRequest(OPTIONS, &Uri{Scheme: "sip", User: "a", Host: "127.0.0.1", Port: serverTp.UDPPort()})
	req.Headers().Set(NewHeader("From", "<sip:a@b.com>;tag=x"))
	req.Headers().Set(NewHeader("To", "<sip:c@d.com>"))
	ctx, err := cm.Request(req, Addr{Network: "udp", Host: "127.0.0.1", Port: serverTp.UDPPort()})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-ctx.Events():
		if ev.Err != nil {
			t.Fatal(ev.Err)
		}
		if ev.Response.StatusCode != 200 {
			t.Fatal(ev.Response.StartLine())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no response despite retransmissions")
	}
	if atomic.LoadUint64(&dropped) == 0 {
		t.Fatal("drop hook never triggered")
	}
}

func TestChaosAllRequestsLost(t *testing.T) {
	clientTp, serverTp := newTestPair(t)
	clientTp.SetDropHook(func(msg Message, dst Addr) bool {
		_, isReq := msg.(*Request)
		return isReq
	})
	cm := NewTxManager(clientTp, "127.0.0.1", clientTp.UDPPort())
	cm.SetConfig(TxConfig{T1: 10 * time.Millisecond, T2: 20 * time.Millisecond, TimerF: 80 * time.Millisecond})
	cm.Run()
	req := NewRequest(OPTIONS, &Uri{Scheme: "sip", User: "a", Host: "127.0.0.1", Port: serverTp.UDPPort()})
	req.Headers().Set(NewHeader("From", "<sip:a@b.com>;tag=x"))
	req.Headers().Set(NewHeader("To", "<sip:c@d.com>"))
	ctx, err := cm.Request(req, Addr{Network: "udp", Host: "127.0.0.1", Port: serverTp.UDPPort()})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-ctx.Events():
		if ev.Err != ErrTimeout {
			t.Fatalf("want timeout, got %+v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no timeout")
	}
}

func TestTCPIdleClose(t *testing.T) {
	a, err := NewTransport("127.0.0.1", -1, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	a.dropHookMu.Lock()
	a.TCPIdleTimeout = 50 * time.Millisecond
	a.dropHookMu.Unlock()
	b, err := NewTransport("127.0.0.1", -1, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	req := NewRequest(MESSAGE, &Uri{Scheme: "sip", User: "a", Host: "127.0.0.1", Port: b.TCPPort()})
	req.Headers().Set(NewHeader("Via", "SIP/2.0/TCP 127.0.0.1:1;branch=z9hG4bKidle"))
	req.Headers().Set(NewHeader("From", "<sip:a@b.com>;tag=t"))
	req.Headers().Set(NewHeader("To", "<sip:c@d.com>"))
	req.Headers().Set(NewHeader("Call-ID", "idle1"))
	req.Headers().Set(&CSeq{Seq: 1, Method: MESSAGE})
	network, _, port := a.TransportFor(&Uri{Scheme: "sip", Host: "127.0.0.1", Port: b.TCPPort(), Params: NewParams().Set("transport", "tcp")})
	if err := a.Send(network, Addr{Network: network, Host: "127.0.0.1", Port: port}, req); err != nil {
		t.Fatal(err)
	}
	select {
	case <-b.Packets():
	case <-time.After(3 * time.Second):
		t.Fatal("no packet")
	}
	a.mu.Lock()
	n := len(a.tcpConns)
	a.mu.Unlock()
	if n == 0 {
		t.Fatal("conn not pooled")
	}
	time.Sleep(700 * time.Millisecond)
	a.mu.Lock()
	n = len(a.tcpConns)
	a.mu.Unlock()
	if n != 0 {
		t.Fatalf("idle conns not reaped: %d", n)
	}
}

func TestMetricsCounters(t *testing.T) {
	clientTp, serverTp := newTestPair(t)
	m := NewMetrics()
	called := make(chan string, 8)
	m.OnEvent = func(name string, v uint64) { called <- name }
	cm := NewTxManager(clientTp, "127.0.0.1", clientTp.UDPPort())
	cm.Metrics = m
	sm := NewTxManager(serverTp, "127.0.0.1", serverTp.UDPPort())
	cm.SetConfig(fastConfig())
	sm.SetConfig(fastConfig())
	sm.SetOnRequest(func(req *Request, src Addr, stx *ServerTx) {
		_ = stx.Respond(NewResponse(200, ""))
	})
	cm.Run()
	sm.Run()
	req := NewRequest(OPTIONS, &Uri{Scheme: "sip", User: "a", Host: "127.0.0.1", Port: serverTp.UDPPort()})
	req.Headers().Set(NewHeader("From", "<sip:a@b.com>;tag=x"))
	req.Headers().Set(NewHeader("To", "<sip:c@d.com>"))
	ctx, err := cm.Request(req, Addr{Network: "udp", Host: "127.0.0.1", Port: serverTp.UDPPort()})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Events():
	case <-time.After(3 * time.Second):
		t.Fatal("no response")
	}
	if m.Get("packets_received") == 0 {
		t.Fatal("no packets counted")
	}
	snap := m.Snapshot()
	if snap["packets_received"] != m.Get("packets_received") {
		t.Fatal("snapshot")
	}
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("OnEvent not called")
	}
}

func TestSlogLogger(t *testing.T) {
	l := NewSlogLogger(nil)
	l.Debugf("x %d", 1)
	l.Infof("x %d", 1)
	l.Warnf("x %d", 1)
	l.Errorf("x %d", 1)
	dl := discardLogger{}
	dl.Debugf("x")
	dl.Infof("x")
	dl.Warnf("x")
	dl.Errorf("x")
}
