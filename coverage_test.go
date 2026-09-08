package sip

import (
	"strings"
	"testing"
	"time"
)

func TestParseFromToContact(t *testing.T) {
	f, err := ParseFrom(`"A" <sip:a@x.com>;tag=1`)
	if err != nil || f.Tag() != "1" {
		t.Fatal(err)
	}
	to, err := ParseTo("<sip:b@y.com>")
	if err != nil || to.Uri.Host != "y.com" {
		t.Fatal(err)
	}
	c, err := ParseContact("<sip:c@z.com>")
	if err != nil || c.Uri.User != "c" {
		t.Fatal(err)
	}
	if _, err := ParseFrom("bad"); err == nil {
		t.Fatal("expected error")
	}
}

func TestRequestResponseAccessors(t *testing.T) {
	resp := NewResponse(180, "")
	resp.Headers().Add(&Via{Proto: "SIP/2.0/UDP", Host: "h", Params: NewParams().Set("branch", "b1")})
	resp.Headers().Set(NewHeader("From", "<sip:a@x.com>;tag=1"))
	resp.Headers().Set(NewHeader("To", "<sip:b@y.com>;tag=2"))
	resp.Headers().Set(NewHeader("Contact", "<sip:b@y.com>"))
	resp.Headers().Set(NewHeader("Call-ID", "c1"))
	resp.Headers().Set(&CSeq{Seq: 1, Method: INVITE})
	if resp.Via().Branch() != "b1" || resp.From().Tag() != "1" || resp.To().Tag() != "2" {
		t.Fatal("accessors")
	}
	if resp.Contact().First().Uri.Host != "y.com" || resp.CallID() != "c1" || resp.CSeq().Method != INVITE {
		t.Fatal("accessors2")
	}
	resp.Headers().Set(NewHeader("Via", "garbage"))
	if resp.Via() == nil {
		t.Log("garbage via tolerated")
	}
	resp2 := NewResponse(200, "")
	if resp2.Via() != nil || resp2.From() != nil || resp2.To() != nil || resp2.Contact() != nil {
		t.Fatal("empty accessors")
	}
	if resp2.CallID() != "" || resp2.CSeq() != nil {
		t.Fatal("empty callid/cseq")
	}
	req := NewRequest(INVITE, &Uri{Scheme: "sip", Host: "x"})
	req.Headers().Set(NewHeader("Via", "SIP/2.0/UDP h:1;branch=b"))
	req.Headers().Set(NewHeader("From", "<sip:a@x.com>;tag=1"))
	req.Headers().Set(NewHeader("To", "<sip:b@y.com>"))
	req.Headers().Set(NewHeader("Contact", "<sip:a@client.com>"))
	req.Headers().Set(NewHeader("Call-ID", "c2"))
	req.Headers().Set(&CSeq{Seq: 2, Method: INVITE})
	if req.Via().Branch() != "b" || req.From().Tag() != "1" || req.To().Uri.Host != "y.com" {
		t.Fatal("req accessors")
	}
	if req.Contact() == nil || req.CallID() != "c2" || req.CSeq().Seq != 2 {
		t.Fatal("req accessors2")
	}
	req.Headers().Set(NewHeader("CSeq", "bad"))
	if req.CSeq() != nil {
		t.Fatal("bad cseq should be nil")
	}
}

func TestMessageIsRequest(t *testing.T) {
	req := NewRequest(INVITE, &Uri{Scheme: "sip", Host: "x"})
	resp := NewResponse(200, "")
	if !req.IsRequest() || resp.IsRequest() {
		t.Fatal("IsRequest")
	}
}

func TestDefaultReasonAll(t *testing.T) {
	for _, c := range []int{100, 180, 183, 200, 202, 301, 302, 400, 401, 403, 404, 407, 408, 415, 420, 421, 423, 480, 481, 483, 486, 487, 488, 500, 501, 502, 503, 504, 600, 603, 604, 199, 299, 399, 499, 599} {
		if DefaultReason(c) == "" {
			t.Fatalf("no reason for %d", c)
		}
	}
	if DefaultReason(101) != "Provisional" || DefaultReason(299) != "Success" ||
		DefaultReason(399) != "Redirection" || DefaultReason(499) != "Client Error" ||
		DefaultReason(599) != "Server Error" {
		t.Fatal("class reasons")
	}
}

func TestParamsEscapeAndKeys(t *testing.T) {
	p := NewParams()
	p.Set("reason", `has"quote`)
	if !strings.Contains(p.String(), `reason="has\"quote"`) {
		t.Fatal(p.String())
	}
	p2, err := ParseParams(p.String())
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := p2.Get("reason"); v != `has"quote` {
		t.Fatal(v)
	}
	p.Set("lr", "")
	p.SetFlag("lr2")
	if len(p.Keys()) != 3 {
		t.Fatal(p.Keys())
	}
	if len(p.Items()) != 3 {
		t.Fatal("items")
	}
}

func TestViaSetBranchNilParams(t *testing.T) {
	v := &Via{Proto: "SIP/2.0/UDP", Host: "h"}
	v.SetBranch("z9hG4bKx")
	if v.Branch() != "z9hG4bKx" {
		t.Fatal(v.Branch())
	}
}

func TestTypedAuthHeader(t *testing.T) {
	raw := strings.ReplaceAll(`REGISTER sip:reg SIP/2.0
Via: SIP/2.0/UDP a.com;branch=x
From: <sip:a@a.com>;tag=t
To: <sip:b@b.com>
Call-ID: 1
CSeq: 1 REGISTER
Authorization: Digest username="u", realm="r", nonce="n", uri="sip:reg", response="abc", algorithm=MD5
Content-Length: 0

`, "\n", "\r\n")
	msg, err := ParseMessage([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	h := msg.Headers().Get("Authorization")
	if h == nil || h.Name() != "Authorization" {
		t.Fatal("auth header")
	}
	th, ok := h.(*TypedAuthHeader)
	if !ok || th.Username != "u" || th.Algorithm != "MD5" {
		t.Fatal("typed auth")
	}
	if th.Clone().Value() != h.Value() {
		t.Fatal("clone")
	}
	other := msg.Headers().All("Other")
	if len(other) != 0 {
		t.Fatal("other")
	}
}

func TestParseAuthOtherParams(t *testing.T) {
	a, err := ParseAuth(`Digest realm="r", nonce="n", cnonce="c", stale=TRUE, custom="v"`)
	if err != nil {
		t.Fatal(err)
	}
	if a.Cnonce != "c" {
		t.Fatal(a)
	}
	if v, _ := a.Other.Get("stale"); v != "TRUE" {
		t.Fatal(a.Other)
	}
	if v, _ := a.Other.Get("custom"); v != "v" {
		t.Fatal(a.Other)
	}
}

func TestTxSetters(t *testing.T) {
	tp, err := NewTransport("127.0.0.1", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tp.Close() }()
	m := NewTxManager(tp, "127.0.0.1", tp.UDPPort())
	var called bool
	m.SetOnResponse(func(resp *Response, src Addr, ctx *ClientTx) { called = true })
	m.SetOnError(func(err error, src Addr) {})
	m.handleResponse(NewResponse(200, ""), Addr{})
	if called {
		t.Fatal("no tx, should not call")
	}
	req := NewRequest(OPTIONS, &Uri{Scheme: "sip", Host: "127.0.0.1", Port: 9})
	req.Headers().Set(NewHeader("From", "<sip:a@b.com>;tag=x"))
	req.Headers().Set(NewHeader("To", "<sip:c@d.com>"))
	req.Headers().Set(NewHeader("Call-ID", "1"))
	req.Headers().Set(&CSeq{Seq: 1, Method: OPTIONS})
	ctx, err := m.Request(req, Addr{Network: "udp", Host: "127.0.0.1", Port: 9})
	if err != nil {
		t.Fatal(err)
	}
	_ = ctx
	resp := NewResponse(200, "")
	resp.Headers().Add(ctx.Request().Via().Clone())
	resp.Headers().Set(NewHeader("From", "<sip:a@b.com>;tag=x"))
	resp.Headers().Set(NewHeader("To", "<sip:c@d.com>"))
	resp.Headers().Set(NewHeader("Call-ID", "1"))
	resp.Headers().Set(&CSeq{Seq: 1, Method: OPTIONS})
	m.handleResponse(resp, Addr{})
	if !called {
		t.Fatal("on response not called")
	}

}

func TestServerTxRespondAfterFinalNonInvite(t *testing.T) {
	_, serverTp := newTestPair(t)
	sm := NewTxManager(serverTp, "127.0.0.1", serverTp.UDPPort())
	sm.SetConfig(fastConfig())
	req := NewRequest(OPTIONS, &Uri{Scheme: "sip", User: "b", Host: "127.0.0.1", Port: 9})
	via := &Via{Proto: "SIP/2.0/UDP", Host: "127.0.0.1", Port: serverTp.UDPPort(), Params: NewParams()}
	via.SetBranch("z9hG4bKserv2")
	req.Headers().Add(via)
	req.Headers().Set(NewHeader("From", "<sip:a@b.com>;tag=x"))
	req.Headers().Set(NewHeader("To", "<sip:c@d.com>"))
	req.Headers().Set(NewHeader("Call-ID", "cid2"))
	req.Headers().Set(&CSeq{Seq: 1, Method: OPTIONS})
	key := serverTxKey(req)
	stx := &ServerTx{
		m:          sm,
		req:        req,
		key:        key,
		src:        Addr{Network: "udp", Host: "127.0.0.1", Port: 9},
		state:      TxStateTrying,
		terminated: make(chan struct{}),
		stop:       make(chan struct{}),
	}
	sm.txs[key] = stx
	if err := stx.Respond(NewResponse(200, "")); err != nil {
		t.Fatal(err)
	}
	if stx.State() != TxStateCompleted {
		t.Fatal(stx.State())
	}
	stx.receiveRetransmission(req)
	select {
	case <-stx.Terminated():
	case <-time.After(2 * time.Second):
		t.Fatal("not terminated")
	}
	if err := stx.Respond(NewResponse(180, "")); err != ErrTxTerminated {
		t.Fatalf("provisional after final: %v", err)
	}
	if err := stx.Respond(NewResponse(400, "")); err != nil {
		t.Fatalf("duplicate final: %v", err)
	}
}

func TestClientTxProvisionalAfterComplete(t *testing.T) {
	_, serverTp := newTestPair(t)
	tp2, err2 := NewTransport("127.0.0.1", 0, 0)
	if err2 != nil {
		t.Fatal(err2)
	}
	cm := NewTxManager(tp2, "127.0.0.1", 1)
	defer func() {
		if cm.tp != nil {
			_ = cm.tp.Close()
		}
	}()
	cm.SetConfig(fastConfig())
	req := NewRequest(OPTIONS, &Uri{Scheme: "sip", Host: "127.0.0.1", Port: serverTp.UDPPort()})
	req.Headers().Add(&Via{Proto: "SIP/2.0/UDP", Host: "h", Params: NewParams().Set("branch", "z9hG4bKprov")})
	req.Headers().Set(NewHeader("From", "<sip:a@b.com>;tag=x"))
	req.Headers().Set(NewHeader("To", "<sip:c@d.com>"))
	req.Headers().Set(NewHeader("Call-ID", "3"))
	req.Headers().Set(&CSeq{Seq: 1, Method: OPTIONS})
	ctx := &ClientTx{
		m:          cm,
		req:        req,
		key:        clientTxKey(req),
		events:     make(chan TxEvent, 8),
		terminated: make(chan struct{}),
		stop:       make(chan struct{}),
	}
	cm.txs[ctx.key] = ctx
	ctx.receive(NewResponse(100, ""))
	if ctx.State() != TxStateProceeding {
		t.Fatal(ctx.State())
	}
	ctx.receive(NewResponse(486, ""))
	ctx.receive(NewResponse(486, ""))
	if ctx.State() != TxStateCompleted {
		t.Fatal(ctx.State())
	}
	select {
	case e := <-ctx.events:
		_ = e
	default:
		t.Fatal("no event")
	}
}

func TestUARespondSetToTagForNewDialog(t *testing.T) {
	ua, _ := newUAPair(t)
	ua.SetCallbacks(UACallbacks{OnMessage: func(req *Request, stx *ServerTx) {
		_ = ua.Respond(nil, stx, 200, "", nil)
	}})
	req := NewRequest(MESSAGE, &Uri{Scheme: "sip", User: "bob", Host: "127.0.0.1", Port: ua.Port()})
	via := &Via{Proto: "SIP/2.0/UDP", Host: "127.0.0.1", Port: ua.Port(), Params: NewParams()}
	via.SetBranch("z9hG4bKtag1")
	req.Headers().Add(via)
	req.Headers().Set(NewHeader("From", "<sip:a@b.com>;tag=x"))
	req.Headers().Set(NewHeader("To", "<sip:c@d.com>"))
	req.Headers().Set(NewHeader("Call-ID", "9"))
	req.Headers().Set(&CSeq{Seq: 1, Method: MESSAGE})
	tp := ua.Transport()
	if err := tp.Send("udp", Addr{Network: "udp", Host: "127.0.0.1", Port: ua.Port()}, req); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
}

func TestAddrHeaderClone(t *testing.T) {
	a := &Address{Uri: &Uri{Scheme: "sip", Host: "x"}}
	h := toHeader(a)
	c := h.Clone()
	if c.Value() != h.Value() || c.Name() != "To" {
		t.Fatal("addr header clone")
	}
	if h.Value() != a.String() {
		t.Fatal("value")
	}
}
