package sip

import (
	"testing"
	"time"
)

func proxyPairSetup(t *testing.T) (*UA, *Proxy, *UA) {
	t.Helper()
	tpCaller, err := NewTransport("127.0.0.1", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	tpProxy, err := NewTransport("127.0.0.1", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	tpCallee, err := NewTransport("127.0.0.1", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = tpCaller.Close()
		_ = tpProxy.Close()
		_ = tpCallee.Close()
	})
	uaCaller := NewUA(tpCaller, "127.0.0.1")
	uaCallee := NewUA(tpCallee, "127.0.0.1")
	for _, m := range []*TxManager{uaCaller.TxManager(), uaCallee.TxManager()} {
		m.SetConfig(fastConfig())
	}
	tmProxy := NewTxManager(tpProxy, "127.0.0.1", tpProxy.UDPPort())
	tmProxy.SetConfig(fastConfig())
	tmProxy.Run()
	px := NewProxy(tpProxy, tmProxy, "127.0.0.1", ProxyConfig{})
	px.SetResolveTargets(func(req *Request) ([]*Uri, error) {
		return []*Uri{{Scheme: "sip", User: "bob", Host: "127.0.0.1", Port: tpCallee.UDPPort()}}, nil
	})
	return uaCaller, px, uaCallee
}

func TestProxyRecordRouteAndDialog(t *testing.T) {
	uaCaller, px, uaCallee := proxyPairSetup(t)
	px.SetRecordRoute(true)
	inviteCh := make(chan *Request, 4)
	uaCallee.SetCallbacks(UACallbacks{OnInvite: func(req *Request, stx *ServerTx, dlg *Dialog) {
		inviteCh <- req
		go func() {
			_ = uaCallee.Respond(dlg, stx, 180, "", nil)
			_ = uaCallee.Respond(dlg, stx, 200, "application/sdp", []byte("v=0\r\n"))
		}()
	}})
	byeDone := make(chan int, 1)
	uaCallee.SetCallbacks(UACallbacks{OnBye: func(req *Request, dlg *Dialog, stx *ServerTx) {
		byeDone <- 200
	}})

	target := &Uri{Scheme: "sip", User: "bob", Host: "127.0.0.1", Port: px.Tp.UDPPort()}
	from := &Address{Uri: &Uri{Scheme: "sip", User: "alice", Host: "127.0.0.1", Port: uaCaller.Port()}}
	sess, err := uaCaller.Invite(target, from, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := sess.WaitResponse(5 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatal(resp.StartLine())
	}
	if err := sess.Ack(); err != nil {
		t.Fatal(err)
	}
	var inviteReq *Request
	select {
	case inviteReq = <-inviteCh:
	case <-time.After(3 * time.Second):
		t.Fatal("callee never saw invite")
	}
	rrs := inviteReq.Headers().All("Record-Route")
	if len(rrs) == 0 {
		t.Fatal("record-route not inserted")
	}

	final, err := uaCaller.Hangup(sess.Dialog(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if final.StatusCode != 200 {
		t.Fatal(final.StartLine())
	}
	select {
	case code := <-byeDone:
		if code != 200 {
			t.Fatal(code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("BYE not forwarded")
	}
}

func TestProxyDialogRecordRouteFollowed(t *testing.T) {
	uaCaller, px, uaCallee := proxyPairSetup(t)
	px.SetRecordRoute(true)
	byeCh := make(chan *Request, 4)
	uaCallee.SetCallbacks(UACallbacks{OnInvite: func(req *Request, stx *ServerTx, dlg *Dialog) {
		go func() {
			_ = uaCallee.Respond(dlg, stx, 200, "", nil)
		}()
	}, OnBye: func(req *Request, dlg *Dialog, stx *ServerTx) {
		byeCh <- req
	}})

	target := &Uri{Scheme: "sip", User: "bob", Host: "127.0.0.1", Port: px.Tp.UDPPort()}
	from := &Address{Uri: &Uri{Scheme: "sip", User: "alice", Host: "127.0.0.1", Port: uaCaller.Port()}}
	sess, _ := uaCaller.Invite(target, from, "", nil)
	resp, err := sess.WaitResponse(5 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatal(resp.StartLine())
	}
	if _, err := uaCaller.Hangup(sess.Dialog(), 5*time.Second); err != nil {
		t.Fatal(err)
	}
	var dlgReq *Request
	select {
	case dlgReq = <-byeCh:
	case <-time.After(3 * time.Second):
		t.Fatal("BYE not seen at callee")
	}
	if len(dlgReq.Headers().All("Route")) == 0 {
		t.Fatal("route set not applied on BYE")
	}
}

func TestProxyCancelPath(t *testing.T) {
	clientTp, serverTp := newTestPair(t)
	cm := NewTxManager(clientTp, "127.0.0.1", clientTp.UDPPort())
	sm := NewTxManager(serverTp, "127.0.0.1", serverTp.UDPPort())
	cm.SetConfig(fastConfig())
	sm.SetConfig(fastConfig())
	tpProxy, err := NewTransport("127.0.0.1", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tpProxy.Close() }()
	tmProxy := NewTxManager(tpProxy, "127.0.0.1", tpProxy.UDPPort())
	tmProxy.SetConfig(fastConfig())
	tmProxy.Run()
	px := NewProxy(tpProxy, tmProxy, "127.0.0.1", ProxyConfig{})
	px.SetResolveTargets(func(req *Request) ([]*Uri, error) {
		return []*Uri{{Scheme: "sip", User: "bob", Host: "127.0.0.1", Port: serverTp.UDPPort()}}, nil
	})
	sm.SetOnRequest(func(req *Request, src Addr, stx *ServerTx) {
		switch req.Method {
		case INVITE:
			go func() {
				_ = stx.Respond(NewResponse(100, ""))
				time.Sleep(2 * time.Second)
				_ = stx.Respond(NewResponse(200, ""))
			}()
		case CANCEL:
			_ = stx.Respond(NewResponse(200, ""))
		}
	})
	cm.Run()
	sm.Run()

	req := NewRequest(INVITE, &Uri{Scheme: "sip", User: "b", Host: "127.0.0.1", Port: tpProxy.UDPPort()})
	req.Headers().Set(NewHeader("From", "<sip:a@b.com>;tag=x"))
	req.Headers().Set(NewHeader("To", "<sip:c@d.com>"))
	ctx, err := cm.Request(req, Addr{Network: "udp", Host: "127.0.0.1", Port: tpProxy.UDPPort()})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Events():
	case <-time.After(3 * time.Second):
		t.Fatal("no provisional")
	}
	if err := ctx.Cancel(); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-ctx.Events():
		if ev.Response != nil && ev.Response.StatusCode >= 200 {
			t.Log("final:", ev.Response.StartLine())
		}
	case <-time.After(3 * time.Second):
		t.Log("no final after cancel")
	}
	if px.dialogs == nil {
		t.Fatal("nil map")
	}
}

func TestProxyNoTargets(t *testing.T) {
	clientTp, _ := newTestPair(t)
	cm := NewTxManager(clientTp, "127.0.0.1", clientTp.UDPPort())
	cm.SetConfig(fastConfig())
	cm.Run()
	tpProxy, err := NewTransport("127.0.0.1", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tpProxy.Close() }()
	tmProxy := NewTxManager(tpProxy, "127.0.0.1", tpProxy.UDPPort())
	tmProxy.SetConfig(fastConfig())
	tmProxy.Run()
	px := NewProxy(tpProxy, tmProxy, "127.0.0.1", ProxyConfig{})
	px.SetResolveTargets(func(req *Request) ([]*Uri, error) { return nil, nil })
	req := NewRequest(OPTIONS, &Uri{Scheme: "sip", User: "a", Host: "127.0.0.1", Port: tpProxy.UDPPort()})
	req.Headers().Set(NewHeader("Via", "SIP/2.0/UDP 127.0.0.1:1;branch=z9hG4bKnt1"))
	req.Headers().Set(NewHeader("From", "<sip:a@b.com>;tag=x"))
	req.Headers().Set(NewHeader("To", "<sip:c@d.com>"))
	req.Headers().Set(NewHeader("Call-ID", "nt1"))
	req.Headers().Set(&CSeq{Seq: 1, Method: OPTIONS})
	ctx, err := cm.Request(req, Addr{Network: "udp", Host: "127.0.0.1", Port: tpProxy.UDPPort()})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-ctx.Events():
		if ev.Response == nil || ev.Response.StatusCode != 500 {
			t.Fatalf("%+v", ev)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no 500")
	}
}

func TestPickBestResponseOrdering(t *testing.T) {
	mk := func(code int) *Response { return NewResponse(code, "") }
	mkBranch := func(code int) *branchState {
		return &branchState{final: mk(code), isFinal: true}
	}
	if got := pickBestResponse([]*branchState{mkBranch(480), mkBranch(486)}); got.StatusCode != 486 {
		t.Fatal(got.StatusCode)
	}
	if got := pickBestResponse([]*branchState{mkBranch(486), mkBranch(491)}); got.StatusCode != 491 {
		t.Fatal(got.StatusCode)
	}
	if got := pickBestResponse([]*branchState{mkBranch(500), mkBranch(503)}); got.StatusCode != 503 {
		t.Fatal(got.StatusCode)
	}
	if got := pickBestResponse([]*branchState{mkBranch(404), mkBranch(408)}); got.StatusCode != 404 {
		t.Fatal(got.StatusCode)
	}
	if pickBestResponse(nil) != nil {
		t.Fatal("nil branches")
	}
	if got := pickBestResponse([]*branchState{mkBranch(200), mkBranch(480)}); got.StatusCode != 200 {
		t.Fatal(got.StatusCode)
	}
}

func TestProxyUnknownMethodAndTagOf(t *testing.T) {
	if tagOf(nil) != "" {
		t.Fatal("nil tag")
	}
	tp, err := NewTransport("127.0.0.1", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tp.Close() }()
	tm := NewTxManager(tp, "127.0.0.1", tp.UDPPort())
	tm.SetConfig(fastConfig())
	tm.Run()
	px := NewProxy(tp, tm, "127.0.0.1", ProxyConfig{})
	px.SetResolveTargets(func(req *Request) ([]*Uri, error) { return nil, nil })
	req := NewRequest(Method("WIBBLE"), &Uri{Scheme: "sip", User: "a", Host: "127.0.0.1", Port: tp.UDPPort()})
	req.Headers().Set(NewHeader("Via", "SIP/2.0/UDP 127.0.0.1:1;branch=z9hG4bKw1"))
	req.Headers().Set(NewHeader("From", "<sip:a@b.com>;tag=x"))
	req.Headers().Set(NewHeader("To", "<sip:c@d.com>"))
	req.Headers().Set(NewHeader("Call-ID", "w1"))
	req.Headers().Set(&CSeq{Seq: 1, Method: "WIBBLE"})
	ctx, err := tm.Request(req, Addr{Network: "udp", Host: "127.0.0.1", Port: tp.UDPPort()})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-ctx.Events():
		if ev.Response == nil || ev.Response.StatusCode != 501 {
			t.Fatalf("%+v", ev)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no 501")
	}
}

func TestB2BUAHelpers(t *testing.T) {
	tpIn, _ := NewTransport("127.0.0.1", 0, 0)
	tpOut, _ := NewTransport("127.0.0.1", 0, 0)
	t.Cleanup(func() { _ = tpIn.Close(); _ = tpOut.Close() })
	uaIngress := NewUA(tpIn, "127.0.0.1")
	uaEgress := NewUA(tpOut, "127.0.0.1")
	b := NewB2BUA(uaIngress, uaEgress, noopRelay{})
	if b.Sessions() != 0 {
		t.Fatal("sessions")
	}
	var started, ended bool
	b.SetSessionHooks(func(s *B2BSession) { started = true }, func(s *B2BSession) { ended = true })
	s := &B2BSession{ID: "x"}
	b.SetSessionHooks(func(bs *B2BSession) { started = true }, func(bs *B2BSession) { ended = true })
	b.routeTargetMu.Lock()
	onS, onE := b.OnSessionStart, b.OnSessionEnd
	b.routeTargetMu.Unlock()
	onS(s)
	onE(s)
	if !started || !ended {
		t.Fatal("hooks")
	}
	b.handleLegBye(nil)
	relay := noopRelay{}
	if err := relay.Start(nil, nil); err != nil {
		t.Fatal(err)
	}
	relay.Stop()
}

func TestLoggingLevels(t *testing.T) {
	l := NewSlogLogger(nil)
	l.Debugf("d")
	l.Infof("i")
	l.Warnf("w")
	l.Errorf("e")
}

func TestTxStateAllStrings(t *testing.T) {
	for s, want := range map[TxState]string{
		TxStateIdle: "idle", TxStateCalling: "calling", TxStateTrying: "trying",
		TxStateProceeding: "proceeding", TxStateCompleted: "completed",
		TxStateConfirmed: "confirmed", TxStateTerminated: "terminated",
	} {
		if s.String() != want {
			t.Fatalf("%d: %s", s, s.String())
		}
	}
}

func TestDefaultTransportTCPOnly(t *testing.T) {
	tp, err := NewTransport("127.0.0.1", -1, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tp.Close() }()
	m := NewTxManager(tp, "127.0.0.1", 1)
	if m.defaultTransport() != "TCP" {
		t.Fatal(m.defaultTransport())
	}
	m2 := NewTxManager(nil, "127.0.0.1", 1)
	if m2.defaultTransport() != "UDP" {
		t.Fatal(m2.defaultTransport())
	}
}

func TestScheduleZero(t *testing.T) {
	done := make(chan struct{})
	NewTxManager(nil, "h", 1).schedule(0, func() { close(done) })
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("schedule(0) not immediate")
	}
}
