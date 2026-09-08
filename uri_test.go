package sip

import (
	"testing"
)

func TestParseUriBasic(t *testing.T) {
	u, err := ParseUri("sip:alice@atlanta.com")
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "sip" || u.User != "alice" || u.Host != "atlanta.com" {
		t.Fatalf("got %+v", u)
	}
	if u.String() != "sip:alice@atlanta.com" {
		t.Fatalf("string: %s", u.String())
	}
}

func TestParseUriFull(t *testing.T) {
	u, err := ParseUri("sips:alice:secret@atlanta.com:5061;transport=tcp;lr?X=1&Y=2")
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "sips" || u.User != "alice" || u.Password != "secret" ||
		u.Host != "atlanta.com" || u.Port != 5061 {
		t.Fatalf("got %+v", u)
	}
	if v, _ := u.Params.Get("transport"); v != "tcp" {
		t.Fatalf("transport param: %v", u.Params)
	}
	if !u.Params.Has("lr") {
		t.Fatal("missing lr flag")
	}
	if x, _ := u.Headers.Get("X"); x != "1" {
		t.Fatalf("header X: %s", x)
	}
	if got := u.String(); got != "sips:alice:secret@atlanta.com:5061;transport=tcp;lr?X=1&Y=2" {
		t.Fatalf("string: %s", got)
	}
}

func TestParseUriIPv6(t *testing.T) {
	u, err := ParseUri("sip:bob@[2001:db8::1]:5060")
	if err != nil {
		t.Fatal(err)
	}
	if u.Host != "[2001:db8::1]" || u.Port != 5060 {
		t.Fatalf("got %+v", u)
	}
}

func TestParseUriErrors(t *testing.T) {
	for _, s := range []string{
		"", "http://example.com", "sip:",
		"sip:bob@[2001:db8::1", "sip:bob@host:abc", "sip:bob@host:port:x",
	} {
		if _, err := ParseUri(s); err == nil {
			t.Errorf("expected error for %q", s)
		}
	}
}

func TestUriEffectivePort(t *testing.T) {
	u, _ := ParseUri("sip:a@b.com")
	if u.EffectivePort() != 5060 {
		t.Fatal("default sips port wrong")
	}
	u2, _ := ParseUri("sips:a@b.com")
	if u2.EffectivePort() != 5061 {
		t.Fatal("sips port wrong")
	}
}

func TestUriEqual(t *testing.T) {
	a, _ := ParseUri("sip:alice@atlanta.com;transport=tcp")
	b, _ := ParseUri("SIP:ALICE@ATLANTA.COM;transport=tcp")
	if !a.Equal(b) {
		t.Fatal("expected equal")
	}
	c, _ := ParseUri("sip:alice@atlanta.com;transport=udp")
	if a.Equal(c) {
		t.Fatal("expected unequal")
	}
	if !a.Equal(a.Clone()) {
		t.Fatal("clone not equal")
	}
}

func TestUriClone(t *testing.T) {
	a, _ := ParseUri("sip:a@b.com;tag=1")
	c := a.Clone()
	c.Params.Set("tag", "2")
	if v, _ := a.Params.Get("tag"); v != "1" {
		t.Fatal("clone aliasing")
	}
}

func TestUriHostPort(t *testing.T) {
	u, _ := ParseUri("sip:a@b.com:1234")
	if u.HostPort() != "b.com:1234" {
		t.Fatal(u.HostPort())
	}
}

func TestParamsOperations(t *testing.T) {
	p := NewParams()
	p.Set("tag", "abc").SetFlag("lr").Set("tag", "xyz")
	if v, ok := p.Get("TAG"); !ok || v != "xyz" {
		t.Fatal("case-insensitive set failed")
	}
	if p.Len() != 2 {
		t.Fatal(p.Items())
	}
	p.Del("lr")
	if p.Has("lr") {
		t.Fatal("del failed")
	}
	if p.String() != ";tag=xyz" {
		t.Fatal(p.String())
	}
	var nilP *Params
	if nilP.Len() != 0 || nilP.String() != "" || nilP.Has("x") {
		t.Fatal("nil params")
	}
}

func TestParseParamsErrors(t *testing.T) {
	if _, err := ParseParams(";=value"); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseParamsQuoted(t *testing.T) {
	p, err := ParseParams(`;reason="SIP ;hello";lr`)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := p.Get("reason"); v != "SIP ;hello" {
		t.Fatalf("reason: %q", v)
	}
}
