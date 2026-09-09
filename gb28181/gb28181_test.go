package gb28181

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	sip "github.com/holihur/sip"
)

const (
	testDeviceID  = "34020000001320000001"
	testChannelID = "34020000001320000002"
	testServerID  = "34020000002000000001"
)

// ---------- XML layer ----------

func TestEnvelopeRoundTrip(t *testing.T) {
	e := &Envelope{
		CmdType:    CmdCatalog,
		SN:         42,
		DeviceID:   testDeviceID,
		SumNum:     2,
		DeviceList: &DeviceList{Num: "2", Items: []Item{{DeviceID: testChannelID, Name: "cam1", Status: "ON"}}},
	}
	body := BuildResponse(e)
	got, err := Parse(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.CmdType != CmdCatalog || got.SN != 42 || got.DeviceID != testDeviceID {
		t.Fatalf("envelope mismatch: %+v", got)
	}
	if got.DeviceList == nil || len(got.DeviceList.Items) != 1 || got.DeviceList.Items[0].DeviceID != testChannelID {
		t.Fatalf("device list mismatch: %+v", got.DeviceList)
	}
}

func TestParseGB2312Declaration(t *testing.T) {
	body := `<?xml version="1.0" encoding="GB2312"?>
<Notify>
  <CmdType>Keepalive</CmdType>
  <SN>7</SN>
  <DeviceID>` + testDeviceID + `</DeviceID>
</Notify>`
	e, err := Parse([]byte(body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.CmdType != CmdKeepalive || e.SN != 7 || e.DeviceID != testDeviceID {
		t.Fatalf("mismatch: %+v", e)
	}
}

func TestParseErrors(t *testing.T) {
	if _, err := Parse(nil); err == nil {
		t.Fatal("expected error for empty body")
	}
	if _, err := Parse([]byte("not xml at all")); err == nil {
		t.Fatal("expected error for non-xml")
	}
}

func TestRootBuilders(t *testing.T) {
	e := &Envelope{CmdType: CmdPTZCmd, SN: 1, DeviceID: testDeviceID, PTZCmd: "A50F"}
	for _, tc := range []struct {
		name string
		body []byte
		root string
	}{
		{"notify", BuildNotify(e), "Notify"},
		{"query", BuildQuery(e), "Query"},
		{"control", BuildControl(e), "Control"},
		{"response", BuildResponse(e), "Response"},
	} {
		if !strings.Contains(string(tc.body), "<"+tc.root+">") {
			t.Errorf("%s body missing root %s: %s", tc.name, tc.root, tc.body)
		}
	}
}

func TestParseSSRC(t *testing.T) {
	if v, err := ParseSSRC("01000001"); err != nil || v != 0x01000001 {
		t.Fatalf("hex ssrc: %v %v", v, err)
	}
	if v, err := ParseSSRC("0100000001"); err != nil || v != 100000001 {
		t.Fatalf("dec ssrc: %v %v", v, err)
	}
	if _, err := ParseSSRC("zzz"); err == nil {
		t.Fatal("expected error")
	}
}

// ---------- SDP layer ----------

func TestStreamSDPRoundTrip(t *testing.T) {
	s := &StreamSDP{
		Username:  testServerID,
		Address:   "192.168.1.100",
		SSRC:      0x01000001,
		RecvOnly:  true,
		VideoPort: 6000,
		AudioPort: 6002,
	}
	parsed, err := ParseSDP(s.Build())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.Username != testServerID || parsed.Address != "192.168.1.100" ||
		parsed.VideoPort != 6000 || parsed.AudioPort != 6002 ||
		!parsed.RecvOnly || parsed.SSRC != 0x01000001 {
		t.Fatalf("mismatch: %+v", parsed)
	}
	if parsed.SessionName != "Play" || parsed.SSRCOf() != "16777217" {
		t.Fatalf("session/ssrc mismatch: %+v", parsed)
	}
}

func TestParseSDPPlaybackRange(t *testing.T) {
	body := "v=0\r\no=x 0 0 IN IP4 10.0.0.1\r\ns=PlayBack\r\nc=IN IP4 10.0.0.1\r\nt=1000 2000\r\nm=video 6000 RTP/AVP 96\r\na=recvonly\r\ny=0100000001\r\n"
	parsed, err := ParseSDP([]byte(body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.SessionName != "PlayBack" || parsed.StartTime != "1000" || parsed.EndTime != "2000" {
		t.Fatalf("mismatch: %+v", parsed)
	}
}

func TestParseSDPErrors(t *testing.T) {
	if _, err := ParseSDP([]byte("garbage")); err == nil {
		t.Fatal("expected error")
	}
	badSSRC := []byte("v=0\r\ns=Play\r\ny=zzz\r\n")
	if _, err := ParseSDP(badSSRC); err == nil {
		t.Fatal("expected ssrc error")
	}
}

// ---------- Device <-> Platform integration over loopback UDP ----------

func waitUntil(t *testing.T, timeout time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

func TestDevicePlatformIntegration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	var catalogResp, infoResp, alarms, keeps int
	var controlCmds []string

	pcfg := PlatformConfig{
		ServerID:   testServerID,
		ServerHost: "127.0.0.1",
		ListenPort: 25060,
		Password:   func(string) (string, bool) { return "12345678", true },
	}
	p, err := NewPlatform(pcfg)
	if err != nil {
		t.Fatal(err)
	}
	p.OnDevice = func(ev DeviceEvent) {
		if ev.Envelope == nil {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		switch ev.Envelope.CmdType {
		case CmdCatalog:
			catalogResp++
		case CmdDeviceInfo:
			infoResp++
		case CmdKeepalive:
			keeps++
		case CmdAlarm:
			alarms++
		}
	}
	go func() {
		_ = p.Run(ctx)
	}()
	select {
	case <-p.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("platform not up")
	}

	d, err := NewDevice(DeviceConfig{
		DeviceID:          testDeviceID,
		Password:          "12345678",
		ServerID:          testServerID,
		ServerHost:        "127.0.0.1",
		ServerPort:        25060,
		LocalHost:         "127.0.0.1",
		LocalPort:         25061,
		KeepaliveInterval: 150 * time.Millisecond,
		Channels: []Item{
			{DeviceID: testChannelID, Name: "front-gate", Status: "ON"},
		},
		DeviceInfo: DeviceInfoT{Name: "testcam", Manufacturer: "go-sip", Model: "v1", Firmware: "1.0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var inviteSDPs int
	d.OnInvite = func(sdp *SDP, dlg *sip.Dialog) {
		mu.Lock()
		inviteSDPs++
		mu.Unlock()
	}
	d.OnControl = func(e *Envelope) {
		mu.Lock()
		controlCmds = append(controlCmds, e.CmdType)
		mu.Unlock()
	}
	go func() {
		_ = d.Start(ctx)
	}()
	if !waitUntil(t, 5*time.Second, func() bool { return d.Registered() && p.IsOnline(testDeviceID) }) {
		t.Fatal("device never registered")
	}

	// queries
	if err := p.QueryCatalog(testDeviceID); err != nil {
		t.Fatalf("catalog query: %v", err)
	}
	if err := p.QueryDeviceInfo(testDeviceID); err != nil {
		t.Fatalf("deviceinfo query: %v", err)
	}
	if err := p.PTZControl(testDeviceID, "A50F0104000000"); err != nil {
		t.Fatalf("ptz: %v", err)
	}

	// alarm report from device
	if err := d.SendMessage(BuildNotify(&Envelope{
		CmdType: CmdAlarm, SN: 99, DeviceID: testDeviceID,
		AlarmTime: "2026-01-01T00:00:00", AlarmType: "2", AlarmPriority: "1", AlarmMethod: "5",
	})); err != nil {
		t.Fatalf("alarm send: %v", err)
	}

	// point-playback INVITE
	sess, err := p.InviteLive(testChannelID, "127.0.0.1", 36000, 0x01000001)
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	resp, err := sess.WaitResponse(5 * time.Second)
	if err != nil {
		t.Fatalf("invite response: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	offer, err := ParseSDP(sess.Tx().Request().Body())
	if err != nil {
		t.Fatalf("offer sdp: %v", err)
	}
	if offer.SSRC != 0x01000001 || offer.VideoPort != 36000 {
		t.Fatalf("offer mismatch: %+v", offer)
	}
	answer, err := ParseSDP(resp.Body())
	if err != nil {
		t.Fatalf("answer sdp: %v", err)
	}
	if answer.RecvOnly || answer.SSRC != offer.SSRC {
		t.Fatalf("answer mismatch: %+v", answer)
	}
	if err := sess.Ack(); err != nil {
		t.Fatalf("ack: %v", err)
	}

	// playback invite (time range carried in s= / t=)
	if _, err := p.InvitePlayback(testChannelID, "127.0.0.1", 36000, 0x01000002, "20260101T000000", "20260102T000000"); err != nil {
		t.Fatalf("playback invite: %v", err)
	}

	// keepalives
	if !waitUntil(t, 2*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return keeps >= 2
	}) {
		t.Fatal("no keepalives observed")
	}
	if !waitUntil(t, 2*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return catalogResp >= 1 && infoResp >= 1 && alarms >= 1 && inviteSDPs >= 1 && len(controlCmds) >= 1
	}) {
		mu.Lock()
		t.Fatalf("responses incomplete: catalog=%d info=%d alarm=%d invites=%d ctl=%v",
			catalogResp, infoResp, alarms, inviteSDPs, controlCmds)
	}
}

func TestDeviceWrongPassword(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, err := NewPlatform(PlatformConfig{
		ServerID: testServerID, ServerHost: "127.0.0.1", ListenPort: 25062,
		Password: func(string) (string, bool) { return "right", true },
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = p.Run(ctx) }()
	select {
	case <-p.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("platform not up")
	}

	d, _ := NewDevice(DeviceConfig{
		DeviceID: testDeviceID, Password: "wrong", ServerID: testServerID,
		ServerHost: "127.0.0.1", ServerPort: 25062, LocalHost: "127.0.0.1", LocalPort: 25063,
	})
	go func() { _ = d.Start(ctx) }()
	time.Sleep(500 * time.Millisecond)
	if d.Registered() {
		t.Fatal("registered with wrong password")
	}
}

func TestPlatformUnknownDevice(t *testing.T) {
	p, err := NewPlatform(PlatformConfig{
		ServerID: testServerID, ServerHost: "127.0.0.1", ListenPort: 25064,
		Password: func(id string) (string, bool) { return "", false },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.sendMessage("nobody", []byte("x")); err == nil {
		t.Fatal("expected not-registered error")
	}
	if _, err := p.InviteLive("nobody", "127.0.0.1", 6000, 1); err == nil {
		t.Fatal("expected not-registered error")
	}
}

func TestNewPlatformValidation(t *testing.T) {
	if _, err := NewPlatform(PlatformConfig{}); err == nil {
		t.Fatal("expected error")
	}
}

// ---------- coverage helpers ----------

func TestAuthHeaderStringAllFields(t *testing.T) {
	a := &sip.Auth{
		Scheme: "Digest", Username: "u", Realm: "r", Nonce: "n", URI: "sip:x",
		Response: "abc", Cnonce: "c", Nc: "00000001", Qop: "auth",
		Algorithm: "MD5", Opaque: "o",
	}
	s := authHeaderString(a)
	for _, want := range []string{`username="u"`, `realm="r"`, `nonce="n"`, `uri="sip:x"`,
		`response="abc"`, `cnonce="c"`, `nc=00000001`, `qop=auth`, `algorithm="MD5"`, `opaque="o"`} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %s in %s", want, s)
		}
	}
	parsed, err := sip.ParseAuth(s)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if parsed.Username != "u" || parsed.Nonce != "n" || parsed.Response != "abc" {
		t.Fatalf("roundtrip mismatch: %+v", parsed)
	}
}

func TestNewDeviceDefaults(t *testing.T) {
	if _, err := NewDevice(DeviceConfig{}); err == nil {
		t.Fatal("expected validation error")
	}
	d, err := NewDevice(DeviceConfig{DeviceID: testDeviceID, ServerID: testServerID, ServerHost: "h"})
	if err != nil {
		t.Fatal(err)
	}
	if d.cfg.LocalPort != 5060 || d.cfg.KeepaliveInterval != 60*time.Second {
		t.Fatalf("defaults not applied: %+v", d.cfg)
	}
}

func TestDeviceRejectsMalformed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d, _ := NewDevice(DeviceConfig{
		DeviceID: testDeviceID, ServerID: testServerID, ServerHost: "127.0.0.1",
		ServerPort: 25066, LocalHost: "127.0.0.1", LocalPort: 25067,
	})
	go func() { _ = d.Start(ctx) }()
	select {
	case <-d.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("device not ready")
	}
	if d.Transport() == nil {
		t.Fatal("no transport")
	}
	send := func(msg string) int {
		conn, err := net.Dial("udp", "127.0.0.1:25067")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		lport := conn.LocalAddr().(*net.UDPAddr).Port
		msg = strings.Replace(msg, "25068", fmt.Sprint(lport), 1)
		_, _ = conn.Write([]byte(msg))
		buf := make([]byte, 4096)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			return 0
		}
		lines := strings.SplitN(string(buf[:n]), "\r\n", 2)
		var code int
		fmt.Sscanf(lines[0], "SIP/2.0 %d", &code)
		return code
	}
	goodXML := "MESSAGE sip:d@h SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:25068;branch=z9hG4bKa\r\nFrom: <sip:x@y>;tag=t\r\nTo: <sip:d@h>\r\nCall-ID: c1\r\nCSeq: 1 MESSAGE\r\nMax-Forwards: 70\r\nContent-Type: application/MANSCDP+xml\r\nContent-Length: 5\r\n\r\njunk!"
	t.Logf("resp to valid-ish: %d", send(goodXML))
	badSDP := "INVITE sip:d@h SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:25068;branch=z9hG4bKb\r\nFrom: <sip:x@y>;tag=t\r\nTo: <sip:d@h>\r\nCall-ID: c2\r\nCSeq: 1 INVITE\r\nMax-Forwards: 70\r\nContact: <sip:x@127.0.0.1:25068>\r\nContent-Type: application/sdp\r\nContent-Length: 6\r\n\r\nnotaSDP"
	if code := send(badSDP); code != 400 {
		t.Fatalf("expected 400 for bad sdp, got %d", code)
	}
}

func TestPlatformDevicesSnapshot(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, _ := NewPlatform(PlatformConfig{ServerID: testServerID, ServerHost: "127.0.0.1", ListenPort: 25069,
		Password: func(string) (string, bool) { return "12345678", true }})
	go func() { _ = p.Run(ctx) }()
	<-p.Ready()
	d, _ := NewDevice(DeviceConfig{DeviceID: testDeviceID, Password: "12345678", ServerID: testServerID,
		ServerHost: "127.0.0.1", ServerPort: 25069, LocalHost: "127.0.0.1", LocalPort: 25074,
		KeepaliveInterval: time.Hour})
	go func() { _ = d.Start(ctx) }()
	if !waitUntil(t, 5*time.Second, func() bool { return p.IsOnline(testDeviceID) }) {
		t.Fatal("device not online")
	}
	devs := p.Devices()
	if len(devs) != 1 || devs[0].ID != testDeviceID || !devs[0].Registered {
		t.Fatalf("devices snapshot: %+v", devs)
	}
}
