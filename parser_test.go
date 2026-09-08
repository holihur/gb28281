package sip

import (
	"strings"
	"testing"
)

const sampleInvite = `INVITE sip:bob@biloxi.com SIP/2.0
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds
Max-Forwards: 70
To: <sip:bob@biloxi.com>
From: "Alice" <sip:alice@atlanta.com>;tag=1928301774
Call-ID: a84b4c76e66710@pc33.atlanta.com
CSeq: 314159 INVITE
Contact: <sip:alice@pc33.atlanta.com>
Content-Type: application/sdp
Content-Length: 31

v=0
o=- 1 1 IN IP4 127.0.0.1
`

func TestParseRequest(t *testing.T) {
	msg, err := ParseMessage([]byte(strings.ReplaceAll(sampleInvite, "\n", "\r\n")))
	if err != nil {
		t.Fatal(err)
	}
	req, ok := msg.(*Request)
	if !ok {
		t.Fatal("not a request")
	}
	if req.Method != INVITE || req.Uri.User != "bob" || req.Proto != SipVersion {
		t.Fatal(req.StartLine())
	}
	if req.CallID() != "a84b4c76e66710@pc33.atlanta.com" {
		t.Fatal(req.CallID())
	}
	cseq := req.CSeq()
	if cseq == nil || cseq.Seq != 314159 || cseq.Method != INVITE {
		t.Fatal("cseq")
	}
	if req.From().Tag() != "1928301774" || req.To().Uri.User != "bob" {
		t.Fatal("from/to")
	}
	via := req.Via()
	if via == nil || via.Branch() != "z9hG4bK776asdhds" {
		t.Fatal("via")
	}
	if !strings.HasPrefix(string(req.Body()), "v=0") {
		t.Fatalf("body: %q", req.Body())
	}
	if req.Validate() != nil {
		t.Fatal("validate")
	}
}

func TestParseResponse(t *testing.T) {
	raw := strings.ReplaceAll(`SIP/2.0 200 OK
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds
To: <sip:bob@biloxi.com>;tag=a6c85cf
From: "Alice" <sip:alice@atlanta.com>;tag=1928301774
Call-ID: a84b4c76e66710@pc33.atlanta.com
CSeq: 314159 INVITE
Contact: <sip:bob@biloxi.com>
Content-Length: 0

`, "\n", "\r\n")
	msg, err := ParseMessage([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	resp, ok := msg.(*Response)
	if !ok {
		t.Fatal("not a response")
	}
	if resp.StatusCode != 200 || resp.Reason != "OK" {
		t.Fatal(resp.StartLine())
	}
	if resp.To().Tag() != "a6c85cf" {
		t.Fatal("to tag")
	}
	if resp.Validate() != nil {
		t.Fatal("validate")
	}
}

func TestParseErrors(t *testing.T) {
	cases := map[string]string{
		"short":              "SIP/2.0",
		"bad start":          "HELLO world",
		"no colon header":    "INVITE sip:a@b.com SIP/2.0\r\nno-colon\r\n",
		"bad uri":            "INVITE notauri SIP/2.0\r\nVia: SIP/2.0/UDP a.com;branch=x\r\nFrom: <sip:a@b.com>\r\nTo: <sip:b@b.com>\r\nCall-ID: 1\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n",
		"missing headers":    "INVITE sip:a@b.com SIP/2.0\r\nContent-Length: 0\r\n\r\n",
		"short body":         "INVITE sip:a@b.com SIP/2.0\r\nVia: SIP/2.0/UDP a.com;branch=x\r\nFrom: <sip:a@b.com>\r\nTo: <sip:b@b.com>\r\nCall-ID: 1\r\nCSeq: 1 INVITE\r\nContent-Length: 10\r\n\r\nabc",
		"bad code":           "SIP/2.0 abc OK\r\nVia: a\r\nFrom: a\r\nTo: a\r\nCall-ID: 1\r\nCSeq: 1 INVITE\r\n\r\n",
		"empty line":         "\r\n\r\n",
		"continuation first": "INVITE sip:a@b.com SIP/2.0\r\n continued\r\nVia: SIP/2.0/UDP a.com;branch=x\r\nFrom: <sip:a@b.com>\r\nTo: <sip:b@b.com>\r\nCall-ID: 1\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n",
		"bad response range": "SIP/2.0 99 Weird\r\nVia: SIP/2.0/UDP a.com;branch=x\r\nFrom: <sip:a@b.com>\r\nTo: <sip:b@b.com>\r\nCall-ID: 1\r\nCSeq: 1 INVITE\r\n\r\n",
	}
	for name, raw := range cases {
		if _, err := ParseMessage([]byte(raw)); err == nil {
			t.Errorf("expected error for %s", name)
		}
	}
}

func TestParseFoldedHeader(t *testing.T) {
	raw := "REGISTER sip:registrar SIP/2.0\r\nVia: SIP/2.0/UDP a.com;branch=x\r\nFrom: <sip:a@a.com>\r\nTo: <sip:b@b.com>\r\nCall-ID: 1\r\nCSeq: 1 REGISTER\r\nSubject: hello\r\n world\r\nContent-Length: 0\r\n\r\n"
	msg, err := ParseMessage([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	req := msg.(*Request)
	if !strings.Contains(req.Headers().Get("Subject").Value(), "world") {
		t.Fatal(req.Headers().Get("Subject").Value())
	}
}

func TestStreamSplitter(t *testing.T) {
	s := &StreamSplitter{}
	m1 := strings.ReplaceAll(sampleInvite, "\n", "\r\n")
	m2 := "REGISTER sip:x SIP/2.0\r\nContent-Length: 0\r\n\r\n"
	var got [][]byte
	chunks := []byte(m1 + m2)
	for i := 0; i < len(chunks); i += 7 {
		end := i + 7
		if end > len(chunks) {
			end = len(chunks)
		}
		msgs, err := s.Feed(chunks[i:end])
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, msgs...)
	}
	if len(got) != 2 {
		t.Fatalf("got %d messages", len(got))
	}
	if _, err := s.Feed([]byte("INVITE sip:b SIP/2.0\r\nContent-Length: abc\r\n\r\n")); err == nil {
		t.Fatal("expected error")
	}
}

func TestMessageBuilders(t *testing.T) {
	req := NewRequest(OPTIONS, &Uri{Scheme: "sip", User: "a", Host: "b.com"})
	req.SetBody("text/plain", []byte("hello"))
	if !strings.Contains(req.String(), "Content-Length: 5") {
		t.Fatal(req.String())
	}
	if !strings.Contains(req.String(), "Content-Type: text/plain") {
		t.Fatal(req.String())
	}
	req.SetBody("", nil)
	if strings.Contains(req.String(), "Content-Length") {
		t.Fatal("body removed")
	}
	resp := NewResponse(486, "")
	if resp.Reason != "Busy Here" {
		t.Fatal(resp.StartLine())
	}
	if resp.StartLine() != "SIP/2.0 486 Busy Here" {
		t.Fatal(resp.StartLine())
	}
	resp2 := NewResponse(999, "")
	if resp2.Reason != "Global Failure" {
		t.Fatal(resp2.Reason)
	}
	resp3 := NewResponse(650, "")
	if resp3.Reason != "Global Failure" {
		t.Fatal(resp3.Reason)
	}
}

func TestMessageClone(t *testing.T) {
	req, _ := ParseMessage([]byte(strings.ReplaceAll(sampleInvite, "\n", "\r\n")))
	c := req.Clone().(*Request)
	c.Headers().Set(NewHeader("X-New", "1"))
	c.SetBody("x/y", []byte("z"))
	if req.Headers().Get("X-New") != nil || string(req.Body()) == "z" {
		t.Fatal("clone aliasing")
	}
	resp := NewResponse(200, "OK")
	rc := resp.Clone().(*Response)
	rc.SetBody("a/b", []byte("q"))
	if len(resp.Body()) != 0 {
		t.Fatal("response clone aliasing")
	}
}

func TestRoundtripRender(t *testing.T) {
	req, _ := ParseMessage([]byte(strings.ReplaceAll(sampleInvite, "\n", "\r\n")))
	msg2, err := ParseMessage([]byte(req.String()))
	if err != nil {
		t.Fatal(err)
	}
	r2 := msg2.(*Request)
	reqR := req.(*Request)
	if r2.Method != INVITE || r2.CallID() != reqR.CallID() || r2.CSeq().Seq != 314159 {
		t.Fatal("roundtrip mismatch")
	}
	if string(r2.Body()) != string(req.Body()) {
		t.Fatal("body mismatch")
	}
}

func TestRequestValidateErrors(t *testing.T) {
	req := NewRequest("", nil)
	if req.Validate() == nil {
		t.Fatal("empty method")
	}
	req.Method = INVITE
	if req.Validate() == nil {
		t.Fatal("nil uri")
	}
}

func TestResponseValidateErrors(t *testing.T) {
	resp := NewResponse(200, "")
	if resp.Validate() == nil {
		t.Fatal("missing headers")
	}
	resp.StatusCode = 99
	if resp.Validate() == nil {
		t.Fatal("bad code")
	}
}

func TestAddressOfUnknownHeader(t *testing.T) {
	h := &Headers{}
	if addressOf(nil) != nil {
		t.Fatal("nil")
	}
	if nameAddrListOf(nil) != nil {
		t.Fatal("nil")
	}
	h.Set(NewHeader("From", "not a uri !!"))
	if addressOf(h.Get("From")) != nil {
		t.Fatal("bad address")
	}
	h.Set(NewHeader("Contact", "bad !!"))
	if nameAddrListOf(h.Get("Contact")) != nil {
		t.Fatal("bad contact")
	}
	cseqOf(nil)
	cseqOf(NewHeader("CSeq", "bad"))
}

func TestDefaultReasons(t *testing.T) {
	if DefaultReason(180) != "Ringing" || DefaultReason(100) != "Trying" ||
		DefaultReason(500) != "Server Internal Error" || DefaultReason(603) != "Decline" ||
		DefaultReason(655) != "Global Failure" {
		t.Fatal("reason map")
	}
}
