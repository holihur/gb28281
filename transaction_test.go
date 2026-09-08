package sip

import (
	"testing"
	"time"
)

func fastConfig() TxConfig {
	return TxConfig{
		T1:     20 * time.Millisecond,
		T2:     80 * time.Millisecond,
		TimerD: 100 * time.Millisecond,
		TimerF: 300 * time.Millisecond,
		TimerJ: 100 * time.Millisecond,
	}
}

func newTestPair(t *testing.T) (*Transport, *Transport) {
	t.Helper()
	a, err := NewTransport("127.0.0.1", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewTransport("127.0.0.1", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a, b
}

func TestNewBranch(t *testing.T) {
	b := NewBranch()
	if len(b) < 8 || b[:7] != "z9hG4bK" {
		t.Fatal(b)
	}
	if b == NewBranch() {
		t.Fatal("branches collide")
	}
}

func TestTxStateString(t *testing.T) {
	if TxStateCalling.String() != "calling" || TxState(99).String() != "unknown" {
		t.Fatal("state string")
	}
}

func TestDefaultConfig(t *testing.T) {
	c := DefaultTxConfig()
	if c.T1 != 500*time.Millisecond || c.T2 != 4*time.Second || c.TimerD != 32*time.Second {
		t.Fatal(c)
	}
}

func TestNictTimeout(t *testing.T) {
	dead, err := NewTransport("127.0.0.1", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	port := dead.UDPPort()
	_ = dead.Close()
	tp, err := NewTransport("127.0.0.1", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tp.Close() }()
	m := NewTxManager(tp, "127.0.0.1", tp.UDPPort())
	m.SetConfig(TxConfig{T1: 10 * time.Millisecond, T2: 20 * time.Millisecond, TimerF: 50 * time.Millisecond})
	m.Run()
	req := NewRequest(OPTIONS, &Uri{Scheme: "sip", User: "a", Host: "127.0.0.1", Port: port})
	ctx, err := m.Request(req, Addr{Network: "udp", Host: "127.0.0.1", Port: port})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-ctx.Events():
		if ev.Err != ErrTimeout {
			t.Fatalf("want timeout, got %+v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no timeout event")
	}
	select {
	case <-ctx.Terminated():
	case <-time.After(time.Second):
		t.Fatal("tx not terminated")
	}
}

func TestNictFullFlow(t *testing.T) {
	clientTp, serverTp := newTestPair(t)
	cm := NewTxManager(clientTp, "127.0.0.1", clientTp.UDPPort())
	sm := NewTxManager(serverTp, "127.0.0.1", serverTp.UDPPort())
	cm.SetConfig(fastConfig())
	sm.SetConfig(fastConfig())
	sm.SetOnRequest(func(req *Request, src Addr, stx *ServerTx) {
		if req.Method != OPTIONS {
			t.Errorf("unexpected method %s", req.Method)
			return
		}
		if stx.State() != TxStateProceeding {
			t.Errorf("server state %s", stx.State())
		}
		resp := NewResponse(200, "")
		if err := stx.Respond(resp); err != nil {
			t.Errorf("respond: %v", err)
		}
		if err := stx.Respond(resp); err != nil {
			t.Errorf("duplicate respond should be nil, got %v", err)
		}
	})
	cm.Run()
	sm.Run()

	srvAddr := Addr{Network: "udp", Host: "127.0.0.1", Port: serverTp.UDPPort()}
	req := NewRequest(OPTIONS, &Uri{Scheme: "sip", User: "a", Host: "127.0.0.1", Port: serverTp.UDPPort()})
	req.Headers().Set(NewHeader("From", "<sip:a@b.com>;tag=x"))
	req.Headers().Set(NewHeader("To", "<sip:c@d.com>"))
	ctx, err := cm.Request(req, srvAddr)
	if err != nil {
		t.Fatal(err)
	}
	if ctx.State() != TxStateTrying {
		t.Fatal(ctx.State())
	}
	if ctx.Key() == "" || ctx.Request() != req {
		t.Fatal("ctx accessors")
	}
	select {
	case ev := <-ctx.Events():
		if ev.Err != nil {
			t.Fatal(ev.Err)
		}
		if ev.Response.StatusCode != 200 {
			t.Fatal(ev.Response.StartLine())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no response")
	}
	select {
	case <-ctx.Terminated():
	case <-time.After(time.Second):
		t.Fatal("not terminated")
	}
}

func TestInviteClientFlow(t *testing.T) {
	clientTp, serverTp := newTestPair(t)
	cm := NewTxManager(clientTp, "127.0.0.1", clientTp.UDPPort())
	sm := NewTxManager(serverTp, "127.0.0.1", serverTp.UDPPort())
	cm.SetConfig(fastConfig())
	sm.SetConfig(fastConfig())
	finalCh := make(chan *ServerTx, 1)
	sm.SetOnRequest(func(req *Request, src Addr, stx *ServerTx) {
		if req.Method != INVITE {
			return
		}
		go func() {
			_ = stx.Respond(NewResponse(180, ""))
			_ = stx.Respond(NewResponse(200, ""))
			finalCh <- stx
		}()
	})
	cm.Run()
	sm.Run()

	srvAddr := Addr{Network: "udp", Host: "127.0.0.1", Port: serverTp.UDPPort()}
	req := NewRequest(INVITE, &Uri{Scheme: "sip", User: "b", Host: "127.0.0.1", Port: serverTp.UDPPort()})
	req.Headers().Set(NewHeader("From", "<sip:a@b.com>;tag=x"))
	req.Headers().Set(NewHeader("To", "<sip:c@d.com>"))
	ctx, err := cm.Request(req, srvAddr)
	if err != nil {
		t.Fatal(err)
	}
	if ctx.State() != TxStateCalling {
		t.Fatal(ctx.State())
	}
	got200 := false
	deadline := time.After(3 * time.Second)
	for {
		select {
		case ev := <-ctx.Events():
			if ev.Err != nil {
				t.Fatal(ev.Err)
			}
			if ev.Response.StatusCode == 180 {
				if ctx.State() != TxStateProceeding {
					t.Fatal(ctx.State())
				}
			}
			if ev.Response.StatusCode == 200 {
				got200 = true
			}
		case <-deadline:
			t.Fatal("timeout waiting responses")
		}
		if got200 {
			break
		}
	}
	select {
	case stx := <-finalCh:
		select {
		case <-stx.Terminated():
		case <-time.After(2 * time.Second):
			t.Fatal("server tx not terminated")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no final on server")
	}
}

func TestInviteFinalFailureSendsAck(t *testing.T) {
	clientTp, serverTp := newTestPair(t)
	cm := NewTxManager(clientTp, "127.0.0.1", clientTp.UDPPort())
	sm := NewTxManager(serverTp, "127.0.0.1", serverTp.UDPPort())
	cm.SetConfig(fastConfig())
	sm.SetConfig(fastConfig())
	ackSeen := make(chan *ServerTx, 1)
	sm.SetOnRequest(func(req *Request, src Addr, stx *ServerTx) {
		if req.Method == INVITE {
			_ = stx.Respond(NewResponse(486, ""))
			ackSeen <- stx
		}
	})
	cm.Run()
	sm.Run()

	req := NewRequest(INVITE, &Uri{Scheme: "sip", User: "b", Host: "127.0.0.1", Port: serverTp.UDPPort()})
	req.Headers().Set(NewHeader("From", "<sip:a@b.com>;tag=x"))
	req.Headers().Set(NewHeader("To", "<sip:c@d.com>"))
	ctx, _ := cm.Request(req, Addr{Network: "udp", Host: "127.0.0.1", Port: serverTp.UDPPort()})
	select {
	case ev := <-ctx.Events():
		if ev.Response.StatusCode != 486 {
			t.Fatal(ev.Response.StartLine())
		}
		if ctx.State() != TxStateCompleted && ctx.State() != TxStateTerminated {
			t.Fatal(ctx.State())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no final response")
	}
	select {
	case stx := <-ackSeen:
		select {
		case <-stx.Terminated():
		case <-time.After(3 * time.Second):
			t.Fatal("server tx not terminated after ACK")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no server tx")
	}
}

func TestServerTxInvite(t *testing.T) {
	_, serverTp := newTestPair(t)
	sm := NewTxManager(serverTp, "127.0.0.1", serverTp.UDPPort())
	sm.SetConfig(fastConfig())
	req := NewRequest(INVITE, &Uri{Scheme: "sip", User: "b", Host: "127.0.0.1", Port: 9})
	via := &Via{Proto: "SIP/2.0/UDP", Host: "127.0.0.1", Port: serverTp.UDPPort(), Params: NewParams()}
	via.SetBranch("z9hG4bKtest1")
	req.Headers().Add(via)
	req.Headers().Set(NewHeader("From", "<sip:a@b.com>;tag=x"))
	req.Headers().Set(NewHeader("To", "<sip:c@d.com>"))
	req.Headers().Set(NewHeader("Call-ID", "cid1"))
	req.Headers().Set(&CSeq{Seq: 1, Method: INVITE})
	key := serverTxKey(req)
	sm.txs[key] = &ServerTx{
		m:          sm,
		req:        req,
		key:        key,
		src:        Addr{Network: "udp", Host: "127.0.0.1", Port: 9},
		state:      TxStateProceeding,
		terminated: make(chan struct{}),
		stop:       make(chan struct{}),
	}
	stx := sm.txs[key].(*ServerTx)
	if stx.Key() != key || stx.Request() != req {
		t.Fatal("accessors")
	}
	if err := stx.Respond(NewResponse(700, "")); err == nil {
		t.Fatal("expected invalid")
	}
	if err := stx.Respond(NewResponse(100, "")); err != nil {
		t.Fatal(err)
	}
	if stx.State() != TxStateProceeding {
		t.Fatal(stx.State())
	}
	if err := stx.Respond(NewResponse(200, "")); err != nil {
		t.Fatal(err)
	}
	if stx.State() != TxStateCompleted {
		t.Fatal(stx.State())
	}
	stx.receiveACK(nil)
	if stx.State() != TxStateConfirmed {
		t.Fatal(stx.State())
	}
	select {
	case <-stx.Terminated():
	case <-time.After(2 * time.Second):
		t.Fatal("not terminated")
	}
}

func TestTxManagerDuplicateRequest(t *testing.T) {
	clientTp, serverTp := newTestPair(t)
	cm := NewTxManager(clientTp, "127.0.0.1", clientTp.UDPPort())
	sm := NewTxManager(serverTp, "127.0.0.1", serverTp.UDPPort())
	cm.SetConfig(fastConfig())
	sm.SetConfig(fastConfig())
	count := make(chan *Request, 10)
	sm.SetOnRequest(func(req *Request, src Addr, stx *ServerTx) {
		count <- req
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
	case <-ctx.Terminated():
	case <-time.After(3 * time.Second):
		t.Fatal("tx never terminated")
	}
	got := 0
	for {
		select {
		case <-count:
			got++
		case <-time.After(100 * time.Millisecond):
			if got == 0 {
				t.Fatal("request not delivered")
			}
			return
		}
	}
}

func TestClientTxCancel(t *testing.T) {
	tp, err := NewTransport("127.0.0.1", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tp.Close() }()
	m := NewTxManager(tp, "127.0.0.1", tp.UDPPort())
	m.SetConfig(fastConfig())
	m.Run()
	deadPort := 1
	req := NewRequest(INVITE, &Uri{Scheme: "sip", User: "b", Host: "127.0.0.1", Port: deadPort})
	req.Headers().Set(NewHeader("From", "<sip:a@b.com>;tag=x"))
	req.Headers().Set(NewHeader("To", "<sip:c@d.com>"))
	ctx, err := m.Request(req, Addr{Network: "udp", Host: "127.0.0.1", Port: deadPort})
	if err != nil {
		t.Fatal(err)
	}
	if err := ctx.Cancel(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if err := ctx.Cancel(); err == nil && ctx.State() == TxStateTerminated {
		t.Log("cancel after finish")
	}
}

func TestTxManagerDuplicateClientTx(t *testing.T) {
	tp, err := NewTransport("127.0.0.1", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tp.Close() }()
	m := NewTxManager(tp, "127.0.0.1", tp.UDPPort())
	req := NewRequest(OPTIONS, &Uri{Scheme: "sip", User: "a", Host: "127.0.0.1", Port: 9})
	req.Headers().Add(&Via{Proto: "SIP/2.0/UDP", Host: "h", Params: NewParams().Set("branch", "z9hG4bKsame")})
	if _, err := m.Request(req, Addr{Network: "udp", Host: "127.0.0.1", Port: 9}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Request(req.Clone().(*Request), Addr{Network: "udp", Host: "127.0.0.1", Port: 9}); err != ErrTxExists {
		t.Fatalf("want ErrTxExists, got %v", err)
	}
	m.remove("C|z9hG4bKsame|OPTIONS")
	if m.tp == nil {
		t.Fatal("tp nil")
	}
	_ = FormatPort(5060)
}

func TestTxManagerHandleResponseUnknown(t *testing.T) {
	tp, err := NewTransport("127.0.0.1", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tp.Close() }()
	m := NewTxManager(tp, "127.0.0.1", tp.UDPPort())
	errs := make(chan error, 1)
	m.OnError = func(err error, src Addr) { errs <- err }
	resp := NewResponse(200, "")
	resp.Headers().Add(&Via{Proto: "SIP/2.0/UDP", Host: "h", Params: NewParams().Set("branch", "z9hG4bKnone")})
	resp.Headers().Set(NewHeader("From", "<sip:a@b.com>;tag=x"))
	resp.Headers().Set(NewHeader("To", "<sip:b@b.com>"))
	resp.Headers().Set(NewHeader("Call-ID", "1"))
	resp.Headers().Set(&CSeq{Seq: 1, Method: INVITE})
	m.handleResponse(resp, Addr{})
	select {
	case <-errs:
	case <-time.After(time.Second):
		t.Fatal("no error event")
	}
	m.handleResponse(NewResponse(200, ""), Addr{})
	m.handleRequest(NewRequest(OPTIONS, &Uri{Scheme: "sip", Host: "x"}), Addr{})
}

func TestFormatPort(t *testing.T) {
	if FormatPort(5060) != "5060" {
		t.Fatal("port")
	}
}
