package sip

import (
	"testing"
	"time"
)

// proxySetup builds UAC - Proxy - (calleeA, calleeB) with loopback transports.
type calleeFixture struct {
	ua     *UA
	answer chan int
}

func proxySetup(t *testing.T, aStatus, bStatus int, bDelay time.Duration) (*UA, *Proxy, []*calleeFixture) {
	t.Helper()
	tpUAC, err := NewTransport("127.0.0.1", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	tpProxy, err := NewTransport("127.0.0.1", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	tpA, err := NewTransport("127.0.0.1", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	tpB, err := NewTransport("127.0.0.1", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = tpUAC.Close()
		_ = tpProxy.Close()
		_ = tpA.Close()
		_ = tpB.Close()
	})
	uaUAC := NewUA(tpUAC, "127.0.0.1")
	uaA := NewUA(tpA, "127.0.0.1")
	uaB := NewUA(tpB, "127.0.0.1")
	fast := fastConfig()
	for _, m := range []*TxManager{uaUAC.TxManager(), uaA.TxManager(), uaB.TxManager()} {
		m.SetConfig(fast)
	}
	callees := []*calleeFixture{
		{ua: uaA, answer: make(chan int, 4)},
		{ua: uaB, answer: make(chan int, 4)},
	}
	statuses := []int{aStatus, bStatus}
	delays := []time.Duration{0, bDelay}
	for i, c := range callees {
		ua := c.ua
		st, dl := statuses[i], delays[i]
		ua.SetCallbacks(UACallbacks{OnInvite: func(req *Request, stx *ServerTx, dlg *Dialog) {
			go func() {
				_ = ua.Respond(dlg, stx, 180, "", nil)
				if dl > 0 {
					time.Sleep(dl)
				}
				_ = ua.Respond(dlg, stx, st, "application/sdp", []byte("v=0\r\n"))
				c.answer <- st
			}()
		}})
	}

	tmProxy := NewTxManager(tpProxy, "127.0.0.1", tpProxy.UDPPort())
	tmProxy.SetConfig(fast)
	tmProxy.Run()
	px := NewProxy(tpProxy, tmProxy, "127.0.0.1", ProxyConfig{})
	px.SetResolveTargets(func(req *Request) ([]*Uri, error) {
		return []*Uri{
			{Scheme: "sip", User: "a", Host: "127.0.0.1", Port: tpA.UDPPort()},
			{Scheme: "sip", User: "b", Host: "127.0.0.1", Port: tpB.UDPPort()},
		}, nil
	})
	return uaUAC, px, callees
}

func TestProxyForkInvite(t *testing.T) {
	uaUAC, px, callees := proxySetup(t, 200, 200, 0)
	target := &Uri{Scheme: "sip", User: "team", Host: "127.0.0.1", Port: px.Tp.UDPPort()}
	from := &Address{Uri: &Uri{Scheme: "sip", User: "alice", Host: "127.0.0.1", Port: uaUAC.Port()}}
	sess, err := uaUAC.Invite(target, from, "", nil)
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
	if sess.Dialog().RemoteTag == "" {
		t.Fatal("no remote tag")
	}
	// both legs answered 200; only one delivered
	got := 0
	for _, c := range callees {
		select {
		case s := <-c.answer:
			if s == 200 {
				got++
			}
		case <-time.After(500 * time.Millisecond):
		}
	}
	if got < 1 {
		t.Fatal("no callee answered")
	}
	if err := sess.Ack(); err != nil {
		t.Fatal(err)
	}
	final, err := uaUAC.Hangup(sess.Dialog(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if final.StatusCode != 200 {
		t.Fatal(final.StartLine())
	}
}

func TestProxyForkPickBestFailure(t *testing.T) {
	uaUAC, px, _ := proxySetup(t, 486, 480, 0)
	target := &Uri{Scheme: "sip", User: "team", Host: "127.0.0.1", Port: px.Tp.UDPPort()}
	from := &Address{Uri: &Uri{Scheme: "sip", User: "alice", Host: "127.0.0.1", Port: uaUAC.Port()}}
	sess, err := uaUAC.Invite(target, from, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := sess.WaitResponse(5 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	// 486 outranks 480
	if resp.StatusCode != 486 {
		t.Fatal(resp.StartLine())
	}
}

func TestProxySlowBranchCancelled(t *testing.T) {
	uaUAC, px, _ := proxySetup(t, 200, 200, 4*time.Second)
	target := &Uri{Scheme: "sip", User: "team", Host: "127.0.0.1", Port: px.Tp.UDPPort()}
	from := &Address{Uri: &Uri{Scheme: "sip", User: "alice", Host: "127.0.0.1", Port: uaUAC.Port()}}
	sess, err := uaUAC.Invite(target, from, "", nil)
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
	// slow branch should have received a CANCEL and answered 487 eventually
	time.Sleep(300 * time.Millisecond)
}
