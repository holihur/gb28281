package sip

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestParseRejectsOversizedBody(t *testing.T) {
	raw := "OPTIONS sip:x SIP/2.0\r\nVia: SIP/2.0/UDP h;branch=b\r\nFrom: <sip:a@h>\r\nTo: <sip:b@h>\r\nCall-ID: 1\r\nCSeq: 1 OPTIONS\r\nContent-Length: 2147483647\r\n\r\n"
	if _, err := ParseMessage([]byte(raw)); err == nil {
		t.Fatal("accepted absurd content-length")
	}
}

func TestParseRejectsTooManyHeaders(t *testing.T) {
	var b bytes.Buffer
	b.WriteString("OPTIONS sip:x SIP/2.0\r\nVia: SIP/2.0/UDP h;branch=b\r\nFrom: <sip:a@h>\r\nTo: <sip:b@h>\r\nCall-ID: 1\r\nCSeq: 1 OPTIONS\r\n")
	for i := 0; i < 200; i++ {
		b.WriteString("X-Pad: 1\r\n")
	}
	b.WriteString("Content-Length: 0\r\n\r\n")
	if _, err := ParseMessage(b.Bytes()); err == nil {
		t.Fatal("accepted too many headers")
	}
}

func TestStreamSplitterRejectsOversizedMessage(t *testing.T) {
	s := &StreamSplitter{}
	big := bytes.Repeat([]byte("A"), MaxMessageSize+1)
	if _, err := s.Feed(big); err == nil {
		t.Fatal("accepted oversized stream buffer")
	}
}

func TestRejectsMessageOverGlobalLimit(t *testing.T) {
	big := bytes.Repeat([]byte("x"), MaxMessageSize+1)
	if _, err := ParseMessage(big); err == nil {
		t.Fatal("accepted oversized message")
	}
}

func TestRedactUri(t *testing.T) {
	u := &Uri{Scheme: "sip", User: "alice", Password: "secret", Host: "h"}
	r := RedactUri(u)
	if strings.Contains(r, "secret") || !strings.Contains(r, "***") {
		t.Fatal(r)
	}
	if strings.Contains(RedactUri(nil), "@") {
		t.Fatal("nil uri")
	}
}

func TestEscapeAuthValue(t *testing.T) {
	if got := escapeAuthValue(`a"b`); got != `a\"b` {
		t.Fatal(got)
	}
}

func TestSameHost(t *testing.T) {
	if !sameHost("127.0.0.1", "127.0.0.1") || sameHost("1.2.3.4", "5.6.7.8") {
		t.Fatal("sameHost")
	}
}

// TestProxyRejectsSpoofedInDialog verifies in-dialog requests from unknown
// sources are rejected by the source check (9.9.9.9 is not either dialog leg).
func TestProxyRejectsSpoofedInDialog(t *testing.T) {
	tp, _ := NewTransport("127.0.0.1", 0, 0)
	t.Cleanup(func() { _ = tp.Close() })
	tm := NewTxManager(tp, "127.0.0.1", tp.UDPPort())
	tm.SetConfig(fastConfig())
	tm.Run()
	px := NewProxy(tp, tm, "127.0.0.1", ProxyConfig{})
	px.SetResolveTargets(func(req *Request) ([]*Uri, error) {
		return []*Uri{{Scheme: "sip", Host: "127.0.0.1", Port: tp.UDPPort()}}, nil
	})
	px.mu.Lock()
	px.dialogs["spoof-cid"] = &proxyDialog{
		callID:     "spoof-cid",
		callerAddr: Addr{Network: "udp", Host: "127.0.0.1", Port: 1},
		remoteLeg:  &Uri{Scheme: "sip", Host: "127.0.0.2", Port: 2},
	}
	px.mu.Unlock()

	bye := NewRequest(BYE, &Uri{Scheme: "sip", Host: "127.0.0.1", Port: tp.UDPPort()})
	bye.Headers().Set(NewHeader("Via", "SIP/2.0/UDP 127.0.0.1:9;branch=z9hG4bKspoof"))
	bye.Headers().Set(NewHeader("From", "<sip:mallory@evil.com>;tag=x"))
	bye.Headers().Set(NewHeader("To", "<sip:bob@127.0.0.1>;tag=y"))
	bye.Headers().Set(NewHeader("Call-ID", "spoof-cid"))
	bye.Headers().Set(&CSeq{Seq: 1, Method: BYE})
	bye.Headers().Set(MaxForwards(70))
	stx := &ServerTx{
		m:          tm,
		req:        bye,
		key:        serverTxKey(bye),
		src:        Addr{Network: "udp", Host: "9.9.9.9", Port: 55555},
		state:      TxStateProceeding,
		terminated: make(chan struct{}),
		stop:       make(chan struct{}),
	}
	px.handleInDialog(bye, stx)
	time.Sleep(100 * time.Millisecond)
	if px.getDialog("spoof-cid") == nil {
		t.Fatal("spoofed BYE tore down the dialog")
	}
	if !px.dialogSourceAllowed(px.getDialog("spoof-cid"), Addr{Host: "127.0.0.1"}) {
		t.Fatal("legitimate caller should be allowed")
	}
	if px.dialogSourceAllowed(px.getDialog("spoof-cid"), Addr{Host: "9.9.9.9"}) {
		t.Fatal("spoofed source should be rejected")
	}
}

func TestDigestSHA256(t *testing.T) {
	ch := &Auth{Scheme: "Digest", Realm: "r", Nonce: "n", Algorithm: "SHA-256"}
	a := DigestResponse(ch, REGISTER, "sip:x", "u", "p", "", "")
	if a.Algorithm != "SHA-256" {
		t.Fatal(a.Algorithm)
	}
	want := sha256.Sum256([]byte("u:r:p"))
	ha1 := hex.EncodeToString(want[:])
	want2 := sha256.Sum256([]byte("REGISTER:sip:x"))
	ha2 := hex.EncodeToString(want2[:])
	if a.Response != digestHashHex(ch.Algorithm, ha1+":n:"+ha2) {
		t.Fatal("bad sha-256 digest")
	}
	// MD5 default for empty algorithm still matches MD5Hex semantics
	ch2 := &Auth{Scheme: "Digest", Realm: "r", Nonce: "n2"}
	b := DigestResponse(ch2, REGISTER, "sip:x", "u", "p", "", "")
	if b.Response != MD5Hex(MD5Hex("u:r:p")+":n2:"+MD5Hex("REGISTER:sip:x")) {
		t.Fatal("md5 digest changed")
	}
}

func TestNewBranchUnique(t *testing.T) {
	seen := make(map[string]bool, 1000)
	for i := 0; i < 1000; i++ {
		b := NewBranch()
		if seen[b] {
			t.Fatal("duplicate branch")
		}
		seen[b] = true
	}
}
