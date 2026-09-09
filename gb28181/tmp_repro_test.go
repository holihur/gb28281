package gb28181

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

const DEVICEID = "34020000001320000001"

func TestTmpReproNoResp(t *testing.T) {
	pc, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 25097})
	defer pc.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d, _ := NewDevice(DeviceConfig{
		DeviceID: testDeviceID, Password: "12345678", ServerID: testServerID,
		ServerHost: "127.0.0.1", ServerPort: 25097, LocalHost: "127.0.0.1", LocalPort: 25098,
		KeepaliveInterval: 5 * time.Second,
	})
	go func() { _ = d.Start(ctx) }()
	registered, queried := false, false
	deadline := time.Now().Add(13 * time.Second)
	for time.Now().Before(deadline) {
		pc.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		buf := make([]byte, 65535)
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			continue
		}
		txt := string(buf[:n])
		t.Log("stub got:", firstLineOf(txt))
		heads := coreHeads(txt)
		switch {
		case strings.HasPrefix(txt, "SIP/"):
			// response, ignore
		case !registered && hasAuthorization(txt):
			respondRaw(pc, src, "SIP/2.0 200 OK\r\n"+heads+"To: <sip:x>;tag=ok\r\nContent-Length: 0\r\n\r\n")
			registered = true
			t.Log("registered")
		case !registered:
			respondRaw(pc, src, "SIP/2.0 401 Unauthorized\r\n"+heads+
				"WWW-Authenticate: Digest realm=\"r\", nonce=\"n1\"\r\nContent-Length: 0\r\n\r\n")
		case !queried:
			query := "MESSAGE sip:" + DEVICEID + " SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:25097;branch=z9hG4bKq1\r\nFrom: <sip:34020000002000000001@x>;tag=q\r\nTo: <sip:" + DEVICEID + "@x>\r\nCall-ID: q1\r\nCSeq: 1 MESSAGE\r\nMax-Forwards: 70\r\nContent-Type: application/MANSCDP+xml\r\nContent-Length: "
			body := "<?xml version=\"1.0\"?><Query><CmdType>Catalog</CmdType><SN>1</SN><DeviceID>" + DEVICEID + "</DeviceID></Query>"
			query += fmt.Sprint(len(body)) + "\r\n\r\n" + body
			respondRaw(pc, src, query)
			queried = true
		default:
			if strings.Contains(txt, "Keepalive") {
				t.Log("KEEPALIVE OK")
			}
			// NOTE: deliberately do NOT respond to the device's catalog response
		}
	}
}

func firstLineOf(s string) string {
	for i, r := range s {
		if r == '\n' || r == '\r' {
			return s[:i]
		}
	}
	return s
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			line := s[start:i]
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			out = append(out, line)
			start = i + 1
		}
	}
	return out
}

func coreHeads(txt string) string {
	var b []byte
	for _, line := range splitLines(txt) {
		for _, p := range []string{"Via:", "From:", "To:", "Call-ID:", "CSeq:"} {
			if len(line) > len(p) && line[:len(p)] == p {
				b = append(b, []byte(line+"\r\n")...)
			}
		}
	}
	return string(b)
}

func hasAuthorization(txt string) bool {
	for _, line := range splitLines(txt) {
		if len(line) > 14 && line[:14] == "Authorization:" {
			return true
		}
	}
	return false
}

func respondRaw(pc *net.UDPConn, src net.Addr, raw string) {
	_, _ = pc.WriteToUDP([]byte(raw), src.(*net.UDPAddr))
}
