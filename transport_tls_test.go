package sip

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

func selfSignedCert(t *testing.T) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses:  nil,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP("127.0.0.1"))
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestTLSTransport(t *testing.T) {
	cert := selfSignedCert(t)
	serverCfg := &tls.Config{Certificates: []tls.Certificate{*cert}}
	clientCfg := &tls.Config{InsecureSkipVerify: true}

	srv, err := NewTLSTransport("127.0.0.1", -1, -1, 0, serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	cli, err := NewTLSTransport("127.0.0.1", -1, -1, 0, clientCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cli.Close() }()

	req := NewRequest(OPTIONS, &Uri{Scheme: "sips", User: "a", Host: "127.0.0.1", Port: srv.TLSPort()})
	req.Headers().Set(NewHeader("Via", "SIP/2.0/TLS 127.0.0.1:1;branch=z9hG4bKtls1"))
	req.Headers().Set(NewHeader("From", "<sip:a@b.com>;tag=x"))
	req.Headers().Set(NewHeader("To", "<sip:c@d.com>"))
	req.Headers().Set(NewHeader("Call-ID", "tls1"))
	req.Headers().Set(&CSeq{Seq: 1, Method: OPTIONS})

	network, host, port := cli.TransportFor(req.Uri)
	if network != "tls" {
		t.Fatal(network)
	}
	if err := cli.Send("tls", Addr{Network: "tls", Host: host, Port: port}, req); err != nil {
		t.Fatal(err)
	}
	select {
	case pkt := <-srv.Packets():
		if pkt.Msg.StartLine() != req.StartLine() || pkt.Src.Network != "tls" {
			t.Fatalf("%s %v", pkt.Msg.StartLine(), pkt.Src)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no packet over TLS")
	}
}
