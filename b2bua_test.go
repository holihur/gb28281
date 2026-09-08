package sip

import (
	"testing"
	"time"
)

func TestB2BUABridgeCall(t *testing.T) {
	tpIn, err := NewTransport("127.0.0.1", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	tpOut, err := NewTransport("127.0.0.1", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	tpCallee, err := NewTransport("127.0.0.1", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = tpIn.Close()
		_ = tpOut.Close()
		_ = tpCallee.Close()
	})
	uaCaller := NewUA(tpIn, "127.0.0.1")
	tpIngress, err2 := NewTransport("127.0.0.1", 0, 0)
	if err2 != nil {
		t.Fatal(err2)
	}
	t.Cleanup(func() { _ = tpIngress.Close() })
	uaIngress := NewUA(tpIngress, "127.0.0.1")
	uaEgress := NewUA(tpOut, "127.0.0.1")
	uaCallee := NewUA(tpCallee, "127.0.0.1")
	for _, m := range []*TxManager{uaCaller.TxManager(), uaIngress.TxManager(), uaEgress.TxManager(), uaCallee.TxManager()} {
		m.SetConfig(fastConfig())
	}

	started := make(chan *B2BSession, 1)
	ended := make(chan *B2BSession, 1)

	uaCallee.SetCallbacks(UACallbacks{OnInvite: func(req *Request, stx *ServerTx, dlg *Dialog) {
		go func() {
			_ = uaCallee.Respond(dlg, stx, 180, "", nil)
			_ = uaCallee.Respond(dlg, stx, 200, "application/sdp", []byte("v=0\r\n"))
		}()
	}})

	b := NewB2BUA(uaIngress, uaEgress, nil)
	b.SetRouteTarget(func(req *Request) (*Uri, error) {
		return &Uri{Scheme: "sip", User: "bob", Host: "127.0.0.1", Port: tpCallee.UDPPort()}, nil
	})
	b.SetSessionHooks(func(s *B2BSession) { started <- s }, func(s *B2BSession) { ended <- s })

	// caller dials the B2BUA ingress
	target := &Uri{Scheme: "sip", User: "service", Host: "127.0.0.1", Port: tpIngress.UDPPort()}
	from := &Address{Uri: &Uri{Scheme: "sip", User: "alice", Host: "127.0.0.1", Port: uaCaller.Port()}}
	sess, err := uaCaller.Invite(target, from, "application/sdp", []byte("v=0\r\n"))
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
	select {
	case s := <-started:
		if s.BLeg == nil || s.ALeg == nil {
			t.Fatal("legs missing")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("session never started")
	}

	// caller hangs up; callee leg must be torn down
	final, err := uaCaller.Hangup(sess.Dialog(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if final.StatusCode != 200 {
		t.Fatal(final.StartLine())
	}
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("session never ended")
	}
}

func TestB2BUANoRoute(t *testing.T) {
	tpIn, _ := NewTransport("127.0.0.1", 0, 0)
	tpOut, _ := NewTransport("127.0.0.1", 0, 0)
	t.Cleanup(func() { _ = tpIn.Close(); _ = tpOut.Close() })
	uaCaller := NewUA(tpIn, "127.0.0.1")
	tpIngress, err2 := NewTransport("127.0.0.1", 0, 0)
	if err2 != nil {
		t.Fatal(err2)
	}
	t.Cleanup(func() { _ = tpIngress.Close() })
	uaIngress := NewUA(tpIngress, "127.0.0.1")
	uaEgress := NewUA(tpOut, "127.0.0.1")
	for _, m := range []*TxManager{uaCaller.TxManager(), uaIngress.TxManager(), uaEgress.TxManager()} {
		m.SetConfig(fastConfig())
	}
	b := NewB2BUA(uaIngress, uaEgress, nil)
	b.SetRouteTarget(func(req *Request) (*Uri, error) { return nil, ErrUnsupported })
	target := &Uri{Scheme: "sip", User: "x", Host: "127.0.0.1", Port: tpIngress.UDPPort()}
	from := &Address{Uri: &Uri{Scheme: "sip", User: "alice", Host: "127.0.0.1", Port: uaCaller.Port()}}
	sess, err := uaCaller.Invite(target, from, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := sess.WaitResponse(5 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 500 {
		t.Fatal(resp.StartLine())
	}
}
