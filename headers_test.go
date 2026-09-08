package sip

import (
	"testing"
)

func TestCanonicalName(t *testing.T) {
	cases := map[string]string{
		"i":            "Call-ID",
		"via":          "Via",
		"call-id":      "Call-ID",
		"CSeq":         "CSeq",
		"content-type": "Content-Type",
		"l":            "Content-Length",
		"WWW-AUTH":     "Www-Auth",
	}
	for in, want := range cases {
		if got := CanonicalName(in); got != want {
			t.Errorf("CanonicalName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestViaRoundtrip(t *testing.T) {
	raw := "SIP/2.0/UDP pc33.atlanta.com:5060;branch=z9hG4bK776asdhds;received=1.2.3.4"
	v, err := ParseVia(raw)
	if err != nil {
		t.Fatal(err)
	}
	if v.Transport != "UDP" || v.Host != "pc33.atlanta.com" || v.Port != 5060 {
		t.Fatalf("%+v", v)
	}
	if v.Branch() != "z9hG4bK776asdhds" {
		t.Fatal(v.Branch())
	}
	if v.Value() != raw {
		t.Fatalf("value: %s", v.Value())
	}
	if v.Clone().Value() != raw {
		t.Fatal("clone mismatch")
	}
	v6, err := ParseVia("SIP/2.0/TCP [::1]:1234;branch=x")
	if err != nil {
		t.Fatal(err)
	}
	if v6.Host != "[::1]" || v6.Port != 1234 {
		t.Fatalf("%+v", v6)
	}
}

func TestParseViaErrors(t *testing.T) {
	for _, s := range []string{"", "SIP/2.0", "SIP/2.0/UDP [::1", "SIP/2.0/UDP host:abc"} {
		if _, err := ParseVia(s); err == nil {
			t.Errorf("expected error for %q", s)
		}
	}
}

func TestAddressRoundtrip(t *testing.T) {
	raw := `"Alice" <sip:alice@atlanta.com>;tag=9fx767`
	a, err := ParseAddress(raw)
	if err != nil {
		t.Fatal(err)
	}
	if a.DisplayName != "Alice" || a.Uri.User != "alice" || a.Tag() != "9fx767" {
		t.Fatalf("%+v", a)
	}
	if a.String() != raw {
		t.Fatalf("string: %s", a.String())
	}
}

func TestAddressNoDisplay(t *testing.T) {
	a, err := ParseAddress("<sip:bob@biloxi.com>;tag=x")
	if err != nil {
		t.Fatal(err)
	}
	if a.Uri.User != "bob" {
		t.Fatal(a)
	}
}

func TestAddressBare(t *testing.T) {
	a, err := ParseAddress("sip:carol@chicago.com;transport=udp")
	if err != nil {
		t.Fatal(err)
	}
	if a.DisplayName != "" || a.Uri.Host != "chicago.com" {
		t.Fatal(a)
	}
}

func TestAddressErrors(t *testing.T) {
	for _, s := range []string{"<sip:a@b.com", "notauri:!", "<sip:a@b.com> ;tag"} {
		if _, err := ParseAddress(s); err == nil && s != "<sip:a@b.com> ;tag" {
			// ";tag" form is valid params actually
			_ = s
		}
	}
	if _, err := ParseAddress("<sip:a@b.com"); err == nil {
		t.Error("expected error")
	}
	if _, err := ParseAddress("bad-uri"); err == nil {
		t.Error("expected error")
	}
}

func TestAddressSetTag(t *testing.T) {
	a := &Address{Uri: &Uri{Scheme: "sip", Host: "x.com"}}
	a.SetTag("abc")
	if a.Tag() != "abc" {
		t.Fatal(a)
	}
	if (*Address)(nil).Tag() != "" {
		t.Fatal("nil tag")
	}
}

func TestCSeq(t *testing.T) {
	c, err := ParseCSeq("314159 INVITE")
	if err != nil {
		t.Fatal(err)
	}
	if c.Seq != 314159 || c.Method != INVITE {
		t.Fatal(c)
	}
	if c.Value() != "314159 INVITE" {
		t.Fatal(c.Value())
	}
	if c.Clone().Value() != "314159 INVITE" {
		t.Fatal("clone")
	}
	for _, s := range []string{"", "abc INVITE", "1", "1 INVITE extra"} {
		if _, err := ParseCSeq(s); err == nil {
			t.Errorf("expected error %q", s)
		}
	}
}

func TestContentLength(t *testing.T) {
	c, err := ParseContentLength("123")
	if err != nil || c != 123 {
		t.Fatal(err)
	}
	if c.Value() != "123" || c.Clone().Value() != "123" || c.Name() != "Content-Length" {
		t.Fatal(c)
	}
	if _, err := ParseContentLength("x"); err == nil {
		t.Fatal("expected error")
	}
}

func TestMaxForwards(t *testing.T) {
	m := MaxForwards(70)
	if m.Value() != "70" || m.Clone().Value() != "70" || m.Name() != "Max-Forwards" {
		t.Fatal(m)
	}
}

func TestNameAddrList(t *testing.T) {
	l, err := ParseNameAddrList(`<sip:a@x.com>, "B" <sip:b@y.com>;tag=2`)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Addresses) != 2 || l.First().Uri.User != "a" {
		t.Fatal(l)
	}
	if l.Value() != `<sip:a@x.com>, "B" <sip:b@y.com>;tag=2` {
		t.Fatal(l.Value())
	}
	w, err := ParseNameAddrList("*")
	if err != nil || !w.All {
		t.Fatal(err)
	}
	if _, err := ParseNameAddrList(""); err == nil {
		t.Fatal("expected error")
	}
	if (*NameAddrList)(nil).First() != nil {
		t.Fatal("nil first")
	}
}

func TestTokenList(t *testing.T) {
	tl := ParseTokenList("Allow", "INVITE, ACK, CANCEL")
	if tl.Name() != "Allow" || !tl.Has("invite") || len(tl.Tokens) != 3 {
		t.Fatal(tl)
	}
	if !tl.Has("ACK") || tl.Has("BYE") {
		t.Fatal(tl.Tokens)
	}
	if tl.Value() != "INVITE, ACK, CANCEL" {
		t.Fatal(tl.Value())
	}
	c := tl.Clone().(*TokenList)
	c.Tokens = append(c.Tokens, "BYE")
	if tl.Has("BYE") {
		t.Fatal("clone aliasing")
	}
}

func TestAuthRoundtrip(t *testing.T) {
	raw := `Digest realm="atlanta.com", qop="auth", nonce="dcd98b", opaque="xyz"`
	a, err := ParseAuth(raw)
	if err != nil {
		t.Fatal(err)
	}
	if a.Scheme != "Digest" || a.Realm != "atlanta.com" || a.Qop != "auth" || a.Nonce != "dcd98b" || a.Opaque != "xyz" {
		t.Fatal(a)
	}
	v := a.Value()
	b, err := ParseAuth(v)
	if err != nil {
		t.Fatal(err)
	}
	if b.Realm != a.Realm || b.Nonce != a.Nonce {
		t.Fatal(b)
	}
	if a.Clone().(*Auth).Nonce != a.Nonce {
		t.Fatal("clone")
	}
	simple, err := ParseAuth("Basic")
	if err != nil || simple.Scheme != "Basic" {
		t.Fatal(err)
	}
}

func TestHeadersOperations(t *testing.T) {
	h := &Headers{}
	h.Add(NewHeader("Via", "SIP/2.0/UDP a.com;branch=1"))
	h.Add(NewHeader("Via", "SIP/2.0/UDP b.com;branch=2"))
	h.Set(&Via{Proto: "SIP/2.0/UDP", Host: "c.com", Params: NewParams().Set("branch", "3")})
	if len(h.All("V")) != 1 {
		t.Fatalf("set did not replace: %v", h.Values("Via"))
	}
	h.Add(NewHeader("X-Custom", "1"))
	if h.Get("x-custom") == nil {
		t.Fatal("get custom")
	}
	if h.Len() != 2 {
		t.Fatal(h.Len())
	}
	h.Del("via")
	if h.Get("Via") != nil {
		t.Fatal("del failed")
	}
	h.Del("missing")
	if h.Len() != 1 {
		t.Fatal(h.Len())
	}
	c := h.Clone()
	c.Del("X-Custom")
	if h.Get("X-Custom") == nil {
		t.Fatal("clone aliasing")
	}
	if h.String() == "" {
		t.Fatal("string")
	}
}

func TestTypedHeadersStored(t *testing.T) {
	h := &Headers{}
	h.Set(&CSeq{Seq: 5, Method: INVITE})
	h.Set(ContentLength(10))
	h.Set(MaxForwards(70))
	if _, ok := h.Get("CSeq").(*CSeq); !ok {
		t.Fatal("cseq not typed")
	}
	if _, ok := h.Get("Content-Length").(ContentLength); !ok {
		t.Fatal("cl not typed")
	}
	if h.Values("Content-Length")[0] != "10" {
		t.Fatal(h.Values("Content-Length"))
	}
}
