//go:build bench_fuzz

// Benchmarks and fuzz targets are gated behind the `bench_fuzz` build tag so
// they never run in normal `go test` or CI.
//
//	go test -tags=bench_fuzz ./...          # fuzz seed corpus (fast)
//	go test -tags=bench_fuzz -fuzz=FuzzParseMessage -fuzztime=30s .
//	go test -tags=bench_fuzz -bench=. -benchmem .

package sip

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// ---------- Fuzz targets ----------

func FuzzParseMessage(f *testing.F) {
	seeds := []string{
		"OPTIONS sip:x SIP/2.0\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\nFrom: <sip:a@h>;tag=t\r\nTo: <sip:b@h>\r\nCall-ID: 1\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n",
		"SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\nFrom: <sip:a@h>;tag=t\r\nTo: <sip:b@h>;tag=u\r\nCall-ID: 1\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n",
		"REGISTER sip:reg SIP/2.0\r\nAuthorization: Digest username=\"u\", realm=\"r\", nonce=\"n\", response=\"x\", algorithm=SHA-256\r\nContent-Length: 0\r\n\r\n",
		"INVITE sip:a@h SIP/2.0\r\nVia: SIP/2.0/UDP [::1]:5060;branch=z9hG4bK2\r\nFrom: <sip:a@h>\r\nTo: <sip:b@h>\r\nCall-ID: 2\r\nCSeq: 1 INVITE\r\nContact: <sip:a@h:1;maddr=127.0.0.1>\r\nContent-Type: application/sdp\r\nContent-Length: 5\r\n\r\nv=0\r\n",
		"BYE sip:h SIP/2.0\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK3\r\nSubject: folded\n continuation\r\nContent-Length: 0\r\n\r\n",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := ParseMessage(data)
		if err != nil {
			return
		}
		// Round-trip: re-parsing the rendered message must succeed.
		out := []byte(msg.String())
		if _, err := ParseMessage(out); err != nil {
			t.Fatalf("re-parse failed: %v\norig: %q", err, data)
		}
		// Clone must render identically.
		if msg.Clone().String() != msg.String() {
			t.Fatalf("clone mismatch\norig: %q", data)
		}
		// Invariants that must hold for any accepted message.
		if len(data) <= MaxMessageSize && len(out) > 4*MaxMessageSize {
			t.Fatal("rendered message implausibly large")
		}
	})
}

func FuzzParseUri(f *testing.F) {
	for _, s := range []string{"sip:a@h", "sips:b@[::1]:5061;transport=tls?X=1", "tel:+15551234", "sip:h:99999", "sip:u:p@h;lr;opaque=\"v\""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		u, err := ParseUri(s)
		if err != nil {
			return
		}
		// Reparse the rendering must succeed.
		if u2, err := ParseUri(u.String()); err != nil {
			t.Fatalf("reparse %q failed: %v", u.String(), err)
		} else if u2.Host != u.Host || u2.User != u.User || u2.Port != u.Port || u2.Scheme != u.Scheme {
			t.Fatalf("round-trip mismatch: %q -> %q", s, u.String())
		}
		// No control characters may leak into rendered URIs.
		out := u.String()
		if strings.ContainsAny(out, "\r\n") {
			t.Fatalf("CRLF injection in rendered uri: %q", out)
		}
	})
}

func FuzzParseVia(f *testing.F) {
	for _, s := range []string{"SIP/2.0/UDP h:5060;branch=z9hG4bK1", "SIP/2.0/TCP [::1]:1;rport", "SIP/2.0/UDP h"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		v, err := ParseVia(s)
		if err != nil {
			return
		}
		if strings.ContainsAny(v.Value(), "\r\n") {
			t.Fatalf("CRLF in via value: %q", v.Value())
		}
		if v.Branch() != "" && !strings.HasPrefix(v.Branch(), "z9hG4bK") {
			// branch may be arbitrary; just ensure retrieval is stable
			if v.Branch() != v.Branch() {
				t.Fatal("unstable branch")
			}
		}
	})
}

func FuzzParseAddress(f *testing.F) {
	for _, s := range []string{`"Bob" <sip:b@h>;tag=t`, "<sip:b@h:1>", "sip:b@h"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		a, err := ParseAddress(s)
		if err != nil {
			return
		}
		if a.Uri == nil {
			t.Fatal("nil uri without error")
		}
		if strings.ContainsAny(a.String(), "\r\n") {
			t.Fatalf("CRLF in rendered address: %q", a.String())
		}
	})
}

func FuzzStreamSplitter(f *testing.F) {
	one := []byte("OPTIONS sip:x SIP/2.0\r\nVia: SIP/2.0/UDP h;branch=b\r\nFrom: <sip:a@h>\r\nTo: <sip:b@h>\r\nCall-ID: 1\r\nCSeq: 1 OPTIONS\r\nContent-Length: 2\r\n\r\nhi")
	f.Add(one, []byte{})
	f.Add(one[:10], one[10:])
	f.Fuzz(func(t *testing.T, a, b []byte) {
		s := &StreamSplitter{}
		msgs, err := s.Feed(a)
		if err != nil {
			return
		}
		m2, err := s.Feed(b)
		if err != nil {
			return
		}
		msgs = append(msgs, m2...)
		for _, m := range msgs {
			// Splitter guarantees framing; the message may still be
			// semantically invalid, which ParseMessage may reject.
			if _, err := ParseMessage(m); err != nil {
				continue
			}
		}
	})
}

func FuzzDigestResponse(f *testing.F) {
	for _, s := range []string{"n", "", "x;y", "\"q\""} {
		f.Add(s, s, s, s, s)
	}
	f.Fuzz(func(t *testing.T, nonce, realm, algo, qop, user string) {
		ch := &Auth{Scheme: "Digest", Nonce: nonce, Realm: realm, Algorithm: algo, Qop: qop}
		a := DigestResponse(ch, REGISTER, "sip:x", user, "pw", "cn", "1")
		if a.Response == "" {
			t.Fatal("empty digest response")
		}
	})
}

// ---------- Benchmarks ----------

func benchRequest() *Request {
	u, _ := ParseUri("sip:alice@example.com;transport=udp")
	req := NewRequest(INVITE, u)
	req.Headers().Set(NewHeader("Via", "SIP/2.0/UDP proxy.example.com:5060;branch=z9hG4bKdeadbeefdeadbeef"))
	req.Headers().Set(NewHeader("From", "\"Alice\" <sip:alice@example.com>;tag=9fxCEDc8xx"))
	req.Headers().Set(NewHeader("To", "<sip:bob@example.com>"))
	req.Headers().Set(NewHeader("Call-ID", "3848276298220188511@example.com"))
	req.Headers().Set(&CSeq{Seq: 1, Method: INVITE})
	req.Headers().Set(MaxForwards(70))
	req.SetBody("application/sdp", []byte("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=x\r\nt=0 0\r\n"))
	return req
}

func BenchmarkParseRequest(b *testing.B) {
	raw := []byte(benchRequest().String())
	b.SetBytes(int64(len(raw)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := ParseMessage(raw); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRenderRequest(b *testing.B) {
	req := benchRequest()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = req.String()
	}
}

func BenchmarkCloneRequest(b *testing.B) {
	req := benchRequest()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req.Clone()
	}
}

func BenchmarkParseUri(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := ParseUri("sip:alice@example.com:5060;transport=udp?Priority=urgent"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseAddress(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := ParseAddress(`"Alice" <sip:alice@example.com:5060;transport=udp>;tag=9fxCEDc8xx`); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStreamSplitterFeed(b *testing.B) {
	raw := []byte(benchRequest().String())
	payload := bytes.Repeat(raw, 16) // 16 messages per feed
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s := &StreamSplitter{}
		msgs, err := s.Feed(payload)
		if err != nil || len(msgs) != 16 {
			b.Fatalf("got %d msgs err %v", len(msgs), err)
		}
	}
}

func BenchmarkDigestSHA256(b *testing.B) {
	ch := &Auth{Scheme: "Digest", Realm: "example.com", Nonce: "abcdef0123456789", Algorithm: "SHA-256", Qop: "auth"}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		DigestResponse(ch, REGISTER, "sip:example.com", "alice", "secret", "cnonce", "00000001")
	}
}

func BenchmarkNewBranch(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		NewBranch()
	}
}

func BenchmarkSendBodyHash(b *testing.B) {
	body := bytes.Repeat([]byte("x"), 1024)
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sum := sha256.Sum256(body)
		_ = hex.EncodeToString(sum[:])
	}
}
