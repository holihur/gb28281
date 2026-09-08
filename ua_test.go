package sip

import (
	"strings"
	"testing"
	"time"
)

func newUAPair(t *testing.T) (*UA, *UA) {
	t.Helper()
	tpA, err := NewTransport("127.0.0.1", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	tpB, err := NewTransport("127.0.0.1", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tpA.Close(); _ = tpB.Close() })
	uaA := NewUA(tpA, "127.0.0.1")
	uaB := NewUA(tpB, "127.0.0.1")
	cfg := fastConfig()
	uaA.tm.SetConfig(cfg)
	uaB.tm.SetConfig(cfg)
	return uaA, uaB
}

func TestUARegister(t *testing.T) {
	uaA, uaB := newUAPair(t)
	registered := make(chan *Request, 1)
	uaB.SetCallbacks(UACallbacks{OnRegister: func(req *Request, stx *ServerTx) {
		registered <- req
		_ = stx.Respond(NewResponse(200, ""))
	}})
	aor := &Uri{Scheme: "sip", User: "alice", Host: "127.0.0.1", Port: uaB.Port()}
	ctx, err := uaA.Register(aor, nil, 3600, nil)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-ctx.Events():
		if ev.Err != nil || ev.Response.StatusCode != 200 {
			t.Fatalf("%+v", ev)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no register response")
	}
	select {
	case req := <-registered:
		if req.Method != REGISTER || req.CSeq().Method != REGISTER {
			t.Fatal(req.StartLine())
		}
		if v := req.Headers().Get("Expires").Value(); v != "3600" {
			t.Fatal(v)
		}
		if !strings.Contains(req.Headers().Get("Contact").Value(), "expires=3600") {
			t.Fatal(req.Headers().Get("Contact").Value())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("REGISTER not delivered")
	}
}

func TestUAInviteCall(t *testing.T) {
	uaA, uaB := newUAPair(t)
	ringingCh := make(chan *Dialog, 1)
	uaB.SetCallbacks(UACallbacks{OnInvite: func(req *Request, stx *ServerTx, dlg *Dialog) {
		ringingCh <- dlg
		_ = uaB.Respond(dlg, stx, 180, "", nil)
		_ = uaB.Respond(dlg, stx, 200, "application/sdp", []byte("v=0\r\n"))
	}})

	uaB.SetCallbacks(UACallbacks{OnBye: func(req *Request, dlg *Dialog, stx *ServerTx) {
		if dlg != nil {
			t.Logf("bye on dialog %s", dlg.ID())
		}
	}})

	target := &Uri{Scheme: "sip", User: "bob", Host: "127.0.0.1", Port: uaB.Port()}
	from := &Address{Uri: &Uri{Scheme: "sip", User: "alice", Host: "127.0.0.1", Port: uaA.Port()}}
	sess, err := uaA.Invite(target, from, "application/sdp", []byte("v=0\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := sess.WaitResponse(3 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatal(resp.StartLine())
	}
	dlg := sess.Dialog()
	if dlg.RemoteTag == "" || dlg.GetState() != DialogConfirmed {
		t.Fatalf("dialog %+v", dlg)
	}
	if dlg.RemoteTarget.Host != "127.0.0.1" {
		t.Fatal(dlg.RemoteTarget)
	}
	if err := sess.Ack(); err != nil {
		t.Fatal(err)
	}
	if uaA.dialogs.Len() != 1 || uaB.dialogs.Len() != 1 {
		t.Fatalf("dialogs: %d %d", uaA.dialogs.Len(), uaB.dialogs.Len())
	}
	final, err := uaA.Hangup(dlg, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if final.StatusCode != 200 {
		t.Fatal(final.StartLine())
	}
	select {
	case bdlg := <-ringingCh:
		_ = bdlg
	case <-time.After(time.Second):
		t.Fatal("no invite on B")
	}
	time.Sleep(300 * time.Millisecond)
}

func TestUAInviteCancel(t *testing.T) {
	uaA, uaB := newUAPair(t)
	gotInvite := make(chan struct{}, 1)
	uaB.SetCallbacks(UACallbacks{OnInvite: func(req *Request, stx *ServerTx, dlg *Dialog) {
		gotInvite <- struct{}{}
		_ = uaB.Respond(dlg, stx, 100, "", nil)
	}})
	target := &Uri{Scheme: "sip", User: "bob", Host: "127.0.0.1", Port: uaB.Port()}
	from := &Address{Uri: &Uri{Scheme: "sip", User: "alice", Host: "127.0.0.1", Port: uaA.Port()}}
	sess, err := uaA.Invite(target, from, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-gotInvite:
	case <-time.After(3 * time.Second):
		t.Fatal("no invite")
	}
	if err := sess.Tx().Cancel(); err != nil {
		t.Fatal(err)
	}
}

func TestUAMessage(t *testing.T) {
	uaA, uaB := newUAPair(t)
	got := make(chan string, 1)
	uaB.SetCallbacks(UACallbacks{OnMessage: func(req *Request, stx *ServerTx) {
		got <- string(req.Body())
		_ = stx.Respond(NewResponse(200, ""))
	}})
	req := NewRequest(MESSAGE, &Uri{Scheme: "sip", User: "bob", Host: "127.0.0.1", Port: uaB.Port()})
	req.Headers().Set(NewHeader("Via", "SIP/2.0/UDP 127.0.0.1:1;branch=z9hG4bKmsg1"))
	req.Headers().Set(NewHeader("From", "<sip:a@b.com>;tag=t"))
	req.Headers().Set(NewHeader("To", "<sip:c@d.com>"))
	req.Headers().Set(NewHeader("Call-ID", "m1"))
	req.Headers().Set(&CSeq{Seq: 1, Method: MESSAGE})
	req.SetBody("text/plain", []byte("hello sip"))
	ctx, err := uaA.tm.Request(req, Addr{Network: "udp", Host: "127.0.0.1", Port: uaB.Port()})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-ctx.Events():
		if ev.Err != nil || ev.Response.StatusCode != 200 {
			t.Fatalf("%+v", ev)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no response")
	}
	select {
	case body := <-got:
		if body != "hello sip" {
			t.Fatal(body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("body not delivered")
	}
}

func TestUADigest(t *testing.T) {
	ch, err := ParseAuth(`Digest realm="example.com", nonce="abc123", qop="auth"`)
	if err != nil {
		t.Fatal(err)
	}
	a := DigestResponse(ch, REGISTER, "sip:example.com", "alice", "secret", "cn", "00000001")
	if a.Response == "" || a.Username != "alice" {
		t.Fatal(a)
	}
	if a.Nonce != "abc123" || a.Nc != "00000001" || a.Cnonce != "cn" {
		t.Fatal(a)
	}
	if !strings.Contains(a.Value(), `response="`) {
		t.Fatal(a.Value())
	}
	md5noQop := MD5Hex(MD5Hex("alice:example.com:secret") + ":abc123:" + MD5Hex("REGISTER:sip:example.com"))
	if a.Qop != "" && md5noQop == a.Response {
		t.Fatal("qop should differ from no-qop digest")
	}
	ch2, _ := ParseAuth(`Digest realm="r", nonce="n"`)
	b := DigestResponse(ch2, REGISTER, "sip:x", "u", "p", "", "")
	if b.Qop != "" || b.Response != MD5Hex(MD5Hex("u:r:p")+":n:"+MD5Hex("REGISTER:sip:x")) {
		t.Fatal(b)
	}
}

func TestUAUnknownRequest(t *testing.T) {
	uaA, uaB := newUAPair(t)
	req := NewRequest(Method("FOO"), &Uri{Scheme: "sip", User: "bob", Host: "127.0.0.1", Port: uaB.Port()})
	req.Headers().Set(NewHeader("Via", "SIP/2.0/UDP 127.0.0.1:1;branch=z9hG4bKu1"))
	req.Headers().Set(NewHeader("From", "<sip:a@b.com>;tag=t"))
	req.Headers().Set(NewHeader("To", "<sip:c@d.com>"))
	req.Headers().Set(NewHeader("Call-ID", "u1"))
	req.Headers().Set(&CSeq{Seq: 1, Method: "FOO"})
	ctx, err := uaA.tm.Request(req, Addr{Network: "udp", Host: "127.0.0.1", Port: uaB.Port()})
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

func TestUAByeUnknownDialog(t *testing.T) {
	uaA, uaB := newUAPair(t)
	req := NewRequest(BYE, &Uri{Scheme: "sip", User: "bob", Host: "127.0.0.1", Port: uaB.Port()})
	req.Headers().Set(NewHeader("Via", "SIP/2.0/UDP 127.0.0.1:1;branch=z9hG4bKb1"))
	req.Headers().Set(NewHeader("From", "<sip:a@b.com>;tag=t"))
	req.Headers().Set(NewHeader("To", "<sip:c@d.com>;tag=other"))
	req.Headers().Set(NewHeader("Call-ID", "b1"))
	req.Headers().Set(&CSeq{Seq: 2, Method: BYE})
	ctx, err := uaA.tm.Request(req, Addr{Network: "udp", Host: "127.0.0.1", Port: uaB.Port()})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-ctx.Events():
		if ev.Response == nil || ev.Response.StatusCode != 481 {
			t.Fatalf("%+v", ev)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no 481")
	}
}

func TestUANilCallback(t *testing.T) {
	_, uaB := newUAPair(t)
	tp, err := NewTransport("127.0.0.1", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tp.Close() }()
	uaC := NewUA(tp, "127.0.0.1")
	uaC.tm.SetConfig(fastConfig())
	// INVITE to UA with no OnInvite -> 501
	req := NewRequest(INVITE, &Uri{Scheme: "sip", User: "bob", Host: "127.0.0.1", Port: uaB.Port()})
	req.Headers().Set(NewHeader("Via", "SIP/2.0/UDP 127.0.0.1:1;branch=z9hG4bKn1"))
	req.Headers().Set(NewHeader("From", "<sip:a@b.com>;tag=t"))
	req.Headers().Set(NewHeader("To", "<sip:c@d.com>"))
	req.Headers().Set(NewHeader("Call-ID", "n1"))
	req.Headers().Set(&CSeq{Seq: 1, Method: INVITE})
	ctx, err := uaC.tm.Request(req, Addr{Network: "udp", Host: "127.0.0.1", Port: uaB.Port()})
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
	_ = uaC.Port()
}

func TestUARegisterAuthHeader(t *testing.T) {
	tp, err := NewTransport("127.0.0.1", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tp.Close() }()
	ua := NewUA(tp, "127.0.0.1")
	aor := &Uri{Scheme: "sip", User: "alice", Host: "127.0.0.1", Port: 9}
	ctx, err := ua.Register(aor, nil, 60, &Credentials{Username: "alice", Password: "pw", Realm: "r"})
	if err != nil {
		t.Fatal(err)
	}
	auth := ctx.Request().Headers().Get("Authorization")
	if auth == nil || !strings.Contains(auth.Value(), "alice") {
		t.Fatal("no auth header")
	}
}

func TestUARespondErrors(t *testing.T) {
	ua, _ := newUAPair(t)
	if err := ua.Respond(nil, nil, 200, "", nil); err != ErrUnsupported {
		t.Fatal(err)
	}
}

func TestUAInviteSessionAckNoFinal(t *testing.T) {
	s := &ClientInviteSession{}
	if err := s.Ack(); err != ErrInvalidResponse {
		t.Fatal(err)
	}
}

func TestUAHangupBadDialog(t *testing.T) {
	ua, _ := newUAPair(t)
	d := &Dialog{State: DialogTerminated}
	if _, err := ua.Hangup(d, time.Second); err != ErrDialogNotFound {
		t.Fatal(err)
	}
}

func TestUAAccessors(t *testing.T) {
	uaA, _ := newUAPair(t)
	if uaA.TxManager() == nil || uaA.Transport() == nil || uaA.Dialogs() == nil || uaA.UserAgent == "" {
		t.Fatal("accessors")
	}
}
