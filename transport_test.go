package sip

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestUDPTransportSendReceive(t *testing.T) {
	a, b := newTestPair(t)
	req := NewRequest(OPTIONS, &Uri{Scheme: "sip", User: "a", Host: "127.0.0.1", Port: b.UDPPort()})
	req.Headers().Set(NewHeader("Via", "SIP/2.0/UDP 127.0.0.1:1;branch=z9hG4bKx"))
	req.Headers().Set(NewHeader("From", "<sip:a@b.com>;tag=t"))
	req.Headers().Set(NewHeader("To", "<sip:c@d.com>"))
	req.Headers().Set(NewHeader("Call-ID", "1"))
	req.Headers().Set(&CSeq{Seq: 1, Method: OPTIONS})
	if err := a.Send("udp", Addr{Network: "udp", Host: "127.0.0.1", Port: b.UDPPort()}, req); err != nil {
		t.Fatal(err)
	}
	select {
	case pkt := <-b.Packets():
		if pkt.Msg.StartLine() != req.StartLine() {
			t.Fatal(pkt.Msg.StartLine())
		}
		if pkt.Src.Network != "udp" || pkt.Src.Port != a.UDPPort() {
			t.Fatal(pkt.Src)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no packet")
	}
}

func TestTCPTransportSendReceive(t *testing.T) {
	a, err := NewTransport("127.0.0.1", -1, 0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewTransport("127.0.0.1", -1, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	req := NewRequest(MESSAGE, &Uri{Scheme: "sip", User: "a", Host: "127.0.0.1", Port: b.TCPPort()})
	req.Headers().Set(NewHeader("Via", "SIP/2.0/TCP 127.0.0.1:1;branch=z9hG4bKx"))
	req.Headers().Set(NewHeader("From", "<sip:a@b.com>;tag=t"))
	req.Headers().Set(NewHeader("To", "<sip:c@d.com>"))
	req.Headers().Set(NewHeader("Call-ID", "1"))
	req.Headers().Set(&CSeq{Seq: 1, Method: MESSAGE})
	req.SetBody("text/plain", []byte("hi there"))
	network, _, port := a.TransportFor(&Uri{Scheme: "sip", Host: "127.0.0.1", Port: b.TCPPort(), Params: NewParams().Set("transport", "tcp")})
	if network != "tcp" {
		t.Fatal(network)
	}
	if err := a.Send(network, Addr{Network: network, Host: "127.0.0.1", Port: port}, req); err != nil {
		t.Fatal(err)
	}
	select {
	case pkt := <-b.Packets():
		if pkt.Msg.StartLine() != req.StartLine() || string(pkt.Msg.Body()) != "hi there" {
			t.Fatal(pkt.Msg.StartLine())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no packet")
	}
	// reuse pooled connection
	if err := a.Send("tcp", Addr{Network: "tcp", Host: "127.0.0.1", Port: port}, req.Clone()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-b.Packets():
	case <-time.After(2 * time.Second):
		t.Fatal("no second packet")
	}
}

func TestTransportFor(t *testing.T) {
	tp, err := NewTransport("127.0.0.1", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tp.Close() }()
	network, _, port := tp.TransportFor(&Uri{Scheme: "sips", User: "a", Host: "h.com"})
	if network != "tcp" || port != 5061 {
		t.Fatal(network, port)
	}
	network, _, port = tp.TransportFor(&Uri{Scheme: "sip", User: "a", Host: "h.com", Params: NewParams().Set("transport", "tcp")})
	if network != "tcp" || port != 5060 {
		t.Fatal(network, port)
	}
	network, _, _ = tp.TransportFor(&Uri{Scheme: "sip", Host: "h.com", Params: NewParams().Set("transport", "tls")})
	if network != "tcp" {
		t.Fatal(network)
	}
	network, _, _ = tp.TransportFor(&Uri{Scheme: "sip", Host: "h.com", Params: NewParams().Set("transport", "udp")})
	if network != "udp" {
		t.Fatal(network)
	}
	if tp.UDPPort() == 0 {
		t.Fatal("no udp port")
	}
}

func TestTransportCloseIdempotent(t *testing.T) {
	tp, err := NewTransport("127.0.0.1", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := tp.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tp.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tp.Send("udp", Addr{Network: "udp", Host: "127.0.0.1", Port: 5060}, NewRequest(OPTIONS, &Uri{Scheme: "sip", Host: "127.0.0.1"})); err == nil {
		t.Fatal("send after close should fail... or succeed; ignoring")
	}
}

func TestTransportSendUnknownHost(t *testing.T) {
	tp, err := NewTransport("127.0.0.1", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tp.Close() }()
	err = tp.Send("udp", Addr{Network: "udp", Host: "nonexistent.invalid", Port: 5060}, NewRequest(OPTIONS, &Uri{Scheme: "sip", Host: "nonexistent.invalid"}))
	if err == nil {
		t.Log("resolution unexpectedly succeeded")
	}
	err = tp.Send("sctp", Addr{}, NewRequest(OPTIONS, &Uri{Scheme: "sip", Host: "127.0.0.1"}))
	if err == nil || !strings.Contains(err.Error(), "sctp") {
		t.Fatal(err)
	}
}

func TestAddrString(t *testing.T) {
	a := Addr{Network: "udp", Host: "1.2.3.4", Port: 5060}
	if a.String() != "udp:1.2.3.4:5060" {
		t.Fatal(a.String())
	}
	ua := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1}
	if AddrFromUDP(ua).Network != "udp" {
		t.Fatal("fromudp")
	}
	ta := &net.TCPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 2}
	if AddrFromTCP(ta).Network != "tcp" {
		t.Fatal("fromtcp")
	}
}

func TestStreamSplitterPartial(t *testing.T) {
	s := &StreamSplitter{}
	raw := "MESSAGE sip:x SIP/2.0\r\nContent-Length: 2\r\n\r\nok"
	msgs, err := s.Feed([]byte(raw[:5]))
	if err != nil || len(msgs) != 0 {
		t.Fatal(err, msgs)
	}
	msgs, err = s.Feed([]byte(raw[5:]))
	if err != nil || len(msgs) != 1 {
		t.Fatal(err, msgs)
	}
	msgs, err = s.Feed([]byte(raw))
	if err != nil || len(msgs) != 1 {
		t.Fatal(err, msgs)
	}
}
