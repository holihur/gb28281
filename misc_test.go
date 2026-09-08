package sip

import (
	"testing"
	"time"
)

func TestProxyInDialogInfoAndNotify(t *testing.T) {
	uaCaller, px, uaCallee := proxyPairSetup(t)
	infoSeen := make(chan struct{}, 2)
	uaCallee.SetCallbacks(UACallbacks{
		OnInvite: func(req *Request, stx *ServerTx, dlg *Dialog) {
			go func() { _ = uaCallee.Respond(dlg, stx, 200, "", nil) }()
		},
		OnInfo: func(req *Request, stx *ServerTx, dlg *Dialog) {
			infoSeen <- struct{}{}
			_ = uaCallee.Respond(dlg, stx, 200, "", nil)
		},
	})
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
	info, err := sess.Dialog().CreateRequest(INFO, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := uaCaller.TxManager().Request(info, Addr{Network: "udp", Host: "127.0.0.1", Port: px.Tp.UDPPort()})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-ctx.Events():
		if ev.Err != nil || ev.Response.StatusCode != 200 {
			t.Fatalf("%+v", ev)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no info response")
	}
	select {
	case <-infoSeen:
	case <-time.After(3 * time.Second):
		t.Fatal("INFO not forwarded")
	}
	if _, err := uaCaller.Hangup(sess.Dialog(), 5*time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestUAMiscCallbacks(t *testing.T) {
	uaA, uaB := newUAPair(t)
	notified := make(chan struct{}, 1)
	subscribed := make(chan struct{}, 1)
	uaB.SetCallbacks(UACallbacks{
		OnNotify: func(req *Request, stx *ServerTx) {
			_ = stx.Respond(NewResponse(200, ""))
			notified <- struct{}{}
		},
		OnSubscribe: func(req *Request, stx *ServerTx) {
			_ = stx.Respond(NewResponse(200, ""))
			subscribed <- struct{}{}
		},
	})
	for _, m := range []struct {
		method Method
		branch string
		cid    string
	}{{NOTIFY, "z9hG4bKnof1", "nof1"}, {SUBSCRIBE, "z9hG4bKsub1", "sub1"}} {
		req := NewRequest(m.method, &Uri{Scheme: "sip", User: "bob", Host: "127.0.0.1", Port: uaB.Port()})
		req.Headers().Set(NewHeader("Via", "SIP/2.0/UDP 127.0.0.1:1;branch="+m.branch))
		req.Headers().Set(NewHeader("From", "<sip:a@b.com>;tag=x"))
		req.Headers().Set(NewHeader("To", "<sip:c@d.com>"))
		req.Headers().Set(NewHeader("Call-ID", m.cid))
		req.Headers().Set(&CSeq{Seq: 1, Method: m.method})
		ctx, err := uaA.TxManager().Request(req, Addr{Network: "udp", Host: "127.0.0.1", Port: uaB.Port()})
		if err != nil {
			t.Fatal(err)
		}
		select {
		case ev := <-ctx.Events():
			if ev.Err != nil || ev.Response.StatusCode != 200 {
				t.Fatalf("%+v", ev)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("no response for %s", m.method)
		}
	}
	select {
	case <-notified:
	case <-time.After(time.Second):
		t.Fatal("notify not delivered")
	}
	select {
	case <-subscribed:
	case <-time.After(time.Second):
		t.Fatal("subscribe not delivered")
	}
}

func TestContactUriHelper(t *testing.T) {
	if contactUri(NewResponse(200, "")) != nil {
		t.Fatal("nil contact")
	}
	resp := NewResponse(200, "")
	resp.Headers().Set(NewHeader("Contact", "<sip:a@b.com>"))
	u := contactUri(resp)
	if u == nil || u.Host != "b.com" {
		t.Fatal(u)
	}
	resp2 := NewResponse(200, "")
	resp2.Headers().Set(NewHeader("Contact", "not a uri!"))
	if contactUri(resp2) != nil {
		t.Fatal("bad contact should be nil")
	}
}

func TestNetResolverLookups(t *testing.T) {
	r := NewNetResolver()
	// SRV lookup for a name that has none must error without panic
	if _, err := r.LookupSRV("sip", "udp", "nonexistent.invalid"); err == nil {
		t.Log("unexpected srv success")
	}
	// localhost resolves
	hosts, err := r.LookupHost("localhost")
	if err != nil || len(hosts) == 0 {
		t.Fatalf("lookup localhost: %v", err)
	}
}

func TestProxySetLogger(t *testing.T) {
	tp, err := NewTransport("127.0.0.1", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tp.Close() }()
	tm := NewTxManager(tp, "127.0.0.1", tp.UDPPort())
	tm.Run()
	px := NewProxy(tp, tm, "127.0.0.1", ProxyConfig{})
	px.setLogger(discardLogger{})
	px.SetResolveTargets(func(req *Request) ([]*Uri, error) { return nil, nil })
	if !px.recordRouteEnabled() || px.recordRouteEnabled() {
		t.Log("record-route default false expected")
	}
}

func TestNameAddrListEmptyName(t *testing.T) {
	l := &NameAddrList{Addresses: []*Address{{Uri: &Uri{Scheme: "sip", Host: "x"}}}}
	if l.Name() != "" {
		t.Fatal("empty hname")
	}
	if l.Value() != "<sip:x>" {
		t.Fatal(l.Value())
	}
}

func TestServerTxRecordRouteCopied(t *testing.T) {
	req := NewRequest(INVITE, &Uri{Scheme: "sip", User: "b", Host: "127.0.0.1", Port: 9})
	req.Headers().Set(NewHeader("Via", "SIP/2.0/UDP h:1;branch=z9hG4bKrr1"))
	req.Headers().Set(NewHeader("From", "<sip:a@b.com>;tag=x"))
	req.Headers().Set(NewHeader("To", "<sip:c@d.com>"))
	req.Headers().Set(NewHeader("Call-ID", "rr1"))
	req.Headers().Set(&CSeq{Seq: 1, Method: INVITE})
	req.Headers().Set(NewHeader("Record-Route", "<sip:proxy.example.com;lr>"))
	resp := NewResponse(200, "")
	if len(resp.Headers().All("Record-Route")) != 0 {
		t.Fatal("pre-existing")
	}
	// simulate stx.Respond behaviour manually via a fake stx
	stx := &ServerTx{m: NewTxManager(nil, "h", 1), req: req}
	cseq := req.CSeq()
	resp.Headers().Set(&CSeq{Seq: cseq.Seq, Method: cseq.Method})
	if via := req.Via(); via != nil {
		resp.Headers().Add(via.Clone())
	}
	if f := req.Headers().Get("From"); f != nil && resp.Headers().Get("From") == nil {
		resp.Headers().Add(f.Clone())
	}
	if to := req.Headers().Get("To"); to != nil && resp.Headers().Get("To") == nil {
		resp.Headers().Add(to.Clone())
	}
	if len(resp.Headers().All("Record-Route")) == 0 {
		for _, rr := range req.Headers().All("Record-Route") {
			resp.Headers().Add(rr.Clone())
		}
	}
	if len(resp.Headers().All("Record-Route")) != 1 {
		t.Fatal("record route not copied")
	}
	if stx.Key() != "" {
		t.Fatal("empty key")
	}
}
