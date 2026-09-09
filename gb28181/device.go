package gb28181

import (
	"context"
	"fmt"
	"sync"
	"time"

	sip "github.com/holihur/sip"
)

// DeviceConfig configures a GB28181 device (IPC/NVR) endpoint.
type DeviceConfig struct {
	DeviceID          string // 20-digit national code, e.g. 34020000001320000001
	Password          string
	ServerID          string // platform SIP ID
	ServerHost        string
	ServerPort        int
	LocalHost         string        // advertised IP for Contact/SDP
	LocalPort         int           // listening port (5060 or e.g. 5090)
	KeepaliveInterval time.Duration // default 60s
	Channels          []Item        // channels reported in catalog responses
	DeviceInfo        DeviceInfoT
}

// DeviceInfoT is the static device info reported in DeviceInfo responses.
type DeviceInfoT struct {
	Name         string
	Manufacturer string
	Model        string
	Firmware     string
}

// Device is a GB28181 device-side endpoint: registers to a platform,
// sends keepalives, answers catalog/deviceinfo queries and accepts
// streaming INVITEs.
type Device struct {
	cfg DeviceConfig
	ua  *sip.UA
	tp  *sip.Transport

	mu        sync.Mutex
	sn        int
	nonce     string // last auth challenge from platform
	regOk     bool
	streams   map[string]*Stream // key: call-id
	ready     chan struct{}
	OnControl func(e *Envelope) // PTZ/TeleBoot/etc
	OnInvite  func(sdp *SDP, dlg *sip.Dialog)
	OnError   func(err error)
}

// Stream represents one accepted media session.
type Stream struct {
	Dialog *sip.Dialog
	SSRC   uint32
	SDP    *SDP
}

// NewDevice creates a device endpoint and binds its transport.
func NewDevice(cfg DeviceConfig) (*Device, error) {
	if cfg.DeviceID == "" || cfg.ServerID == "" || cfg.ServerHost == "" {
		return nil, fmt.Errorf("gb28181: device requires DeviceID/ServerID/ServerHost")
	}
	if cfg.LocalPort == 0 {
		cfg.LocalPort = 5060
	}
	if cfg.KeepaliveInterval == 0 {
		cfg.KeepaliveInterval = 60 * time.Second
	}
	d := &Device{cfg: cfg, streams: make(map[string]*Stream), ready: make(chan struct{})}
	return d, nil
}

// Ready is closed once the device transport is bound.
func (d *Device) Ready() <-chan struct{} { return d.ready }

// Start binds the transport and UA, then begins registration + keepalive.
func (d *Device) Start(ctx context.Context) error {
	tp, err := sip.NewTransport("0.0.0.0", d.cfg.LocalPort, d.cfg.LocalPort)
	if err != nil {
		return err
	}
	d.tp = tp
	d.ua = sip.NewUA(tp, d.cfg.LocalHost)
	d.ua.SetCallbacks(sip.UACallbacks{
		OnMessage: d.onMessage,
		OnInvite:  d.onInvite,
	})
	close(d.ready)
	return d.run(ctx)
}

// Transport exposes the underlying transport for tests/advanced use.
func (d *Device) Transport() *sip.Transport { return d.tp }

// Registered reports whether the last registration succeeded.
func (d *Device) Registered() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.regOk
}

func (d *Device) nextSN() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sn++
	return d.sn
}

func (d *Device) serverUri() *sip.Uri {
	return &sip.Uri{Scheme: "sip", User: d.cfg.ServerID, Host: d.cfg.ServerHost, Port: d.cfg.ServerPort}
}

func (d *Device) selfUri() *sip.Uri {
	return &sip.Uri{Scheme: "sip", User: d.cfg.DeviceID, Host: d.cfg.LocalHost, Port: d.cfg.LocalPort}
}

// run performs registration (with digest auth) and periodic keepalives
// until ctx is done.
func (d *Device) run(ctx context.Context) error {
	registered, err := d.register()
	if err != nil && d.OnError != nil {
		d.OnError(err)
	}
	if registered {
		d.mu.Lock()
		d.regOk = true
		d.mu.Unlock()
	}
	tick := time.NewTicker(d.cfg.KeepaliveInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
			if err := d.Keepalive(); err != nil && d.OnError != nil {
				d.OnError(err)
			}
		}
	}
}

// register performs up to two REGISTERs: the first triggers a 401
// challenge, the second carries the Digest response.
func (d *Device) register() (bool, error) {
	callID := sip.NewCallID()
	cseq := 1
	send := func(auth *sip.Auth) (int, *sip.Response, error) {
		req, err := d.newRegister(callID, cseq, auth)
		if err != nil {
			return 0, nil, err
		}
		ctx, err := d.ua.TxManager().Request(req, sip.Addr{
			Network: "udp", Host: d.cfg.ServerHost, Port: d.cfg.ServerPort,
		})
		if err != nil {
			return 0, nil, err
		}
		select {
		case ev := <-ctx.Events():
			if ev.Err != nil {
				return 0, nil, ev.Err
			}
			return ev.Response.StatusCode, ev.Response, nil
		case <-time.After(10 * time.Second):
			return 0, nil, sip.ErrTimeout
		}
	}
	code, resp, err := send(nil)
	if err != nil {
		return false, err
	}
	if code == 200 {
		return true, nil
	}
	if code != 401 {
		return false, fmt.Errorf("gb28181: register got %d", code)
	}
	if www := resp.Headers().Get("WWW-Authenticate"); www != nil {
		if a, perr := sip.ParseAuth(www.Value()); perr == nil && a.Nonce != "" {
			d.mu.Lock()
			d.nonce = a.Nonce
			d.mu.Unlock()
		}
	}
	// Second REGISTER with credentials (same Call-ID, CSeq+1).
	cseq++
	challenge := d.lastChallenge()
	if challenge == nil {
		return false, fmt.Errorf("gb28181: 401 without WWW-Authenticate")
	}
	uri := "sip:" + d.cfg.ServerID + "@" + d.cfg.ServerHost
	auth := sip.DigestResponse(challenge, sip.REGISTER, uri, d.cfg.DeviceID, d.cfg.Password, "", "")
	code, _, err = send(auth)
	if err != nil {
		return false, err
	}
	if code == 200 {
		return true, nil
	}
	return false, fmt.Errorf("gb28181: register auth failed: %d", code)
}

func (d *Device) lastChallenge() *sip.Auth {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.nonce == "" {
		return nil
	}
	return &sip.Auth{Scheme: "Digest", Realm: d.cfg.ServerID, Nonce: d.nonce}
}

func (d *Device) newRegister(callID string, cseq int, auth *sip.Auth) (*sip.Request, error) {
	to := d.serverUri()
	req := sip.NewRequest(sip.REGISTER, to.Clone())
	from := &sip.Address{Uri: &sip.Uri{Scheme: "sip", User: d.cfg.DeviceID, Host: d.cfg.ServerHost}}
	from.Params = sip.NewParams()
	from.Params.Set("tag", sip.NewTag())
	req.Headers().Set(sip.NewHeader("To", (&sip.Address{Uri: to}).String()))
	req.Headers().Set(sip.NewHeader("From", from.String()))
	req.Headers().Set(sip.NewHeader("Call-ID", callID))
	req.Headers().Set(&sip.CSeq{Seq: uint32(cseq), Method: sip.REGISTER})
	req.Headers().Set(sip.MaxForwards(70))
	contact := &sip.Uri{Scheme: "sip", User: d.cfg.DeviceID, Host: d.cfg.LocalHost, Port: d.cfg.LocalPort}
	req.Headers().Set(sip.NewHeader("Contact", contact.String()))
	req.Headers().Set(sip.NewHeader("Expires", "3600"))
	req.Headers().Set(sip.NewHeader("User-Agent", "go-sip-gb28181"))
	if auth != nil {
		req.Headers().Set(sip.NewHeader("Authorization", authHeaderString(auth)))
	}
	return req, nil
}

// Keepalive sends one Notify Keepalive MESSAGE.
func (d *Device) Keepalive() error {
	e := &Envelope{
		CmdType:  CmdKeepalive,
		SN:       d.nextSN(),
		DeviceID: d.cfg.DeviceID,
		SeqNum:   1,
	}
	return d.SendMessage(BuildNotify(e))
}

// SendMessage sends a MANSCDP body as a MESSAGE to the platform.
func (d *Device) SendMessage(body []byte) error {
	req := d.newMessage(d.serverUri(), body)
	_, err := d.ua.TxManager().Request(req, sip.Addr{
		Network: "udp", Host: d.cfg.ServerHost, Port: d.cfg.ServerPort,
	})
	return err
}

func (d *Device) newMessage(to *sip.Uri, body []byte) *sip.Request {
	req := sip.NewRequest(sip.MESSAGE, to.Clone())
	from := &sip.Address{Uri: &sip.Uri{Scheme: "sip", User: d.cfg.DeviceID, Host: d.cfg.ServerHost}}
	from.Params = sip.NewParams()
	from.Params.Set("tag", sip.NewTag())
	req.Headers().Set(sip.NewHeader("From", from.String()))
	req.Headers().Set(sip.NewHeader("To", to.String()))
	req.Headers().Set(sip.NewHeader("Call-ID", sip.NewCallID()))
	req.Headers().Set(&sip.CSeq{Seq: 1, Method: sip.MESSAGE})
	req.Headers().Set(sip.MaxForwards(70))
	req.SetBody("application/MANSCDP+xml", body)
	return req
}

// onMessage answers catalog/deviceinfo queries and forwards control
// commands to OnControl.
func (d *Device) onMessage(req *sip.Request, stx *sip.ServerTx) {
	e, err := Parse(req.Body())
	if err != nil {
		_ = d.ua.Respond(nil, stx, 400, "", nil)
		return
	}
	_ = d.ua.Respond(nil, stx, 200, "", nil)
	switch e.CmdType {
	case CmdCatalog:
		items := d.cfg.Channels
		list := &DeviceList{Num: fmt.Sprint(len(items)), Items: items}
		resp := &Envelope{
			CmdType:    CmdCatalog,
			SN:         e.SN,
			DeviceID:   d.cfg.DeviceID,
			SumNum:     len(items),
			DeviceList: list,
		}
		_ = d.SendMessage(BuildResponse(resp))
	case CmdDeviceInfo:
		info := d.cfg.DeviceInfo
		resp := &Envelope{
			CmdType:      CmdDeviceInfo,
			SN:           e.SN,
			DeviceID:     d.cfg.DeviceID,
			DeviceName:   info.Name,
			Manufacturer: info.Manufacturer,
			Model:        info.Model,
			Firmware:     info.Firmware,
			Result:       "OK",
		}
		_ = d.SendMessage(BuildResponse(resp))
	case CmdDeviceStatus:
		resp := &Envelope{CmdType: CmdDeviceStatus, SN: e.SN, DeviceID: d.cfg.DeviceID, Status: "ONLINE", Result: "OK"}
		_ = d.SendMessage(BuildResponse(resp))
	case CmdPTZCmd, CmdTeleBoot, CmdDeviceConfig, CmdConfigDownload, CmdPresetQuery:
		if d.OnControl != nil {
			d.OnControl(e)
		}
	}
}

// onInvite accepts a streaming INVITE and answers with our SDP.
func (d *Device) onInvite(req *sip.Request, stx *sip.ServerTx, dlg *sip.Dialog) {
	remote, err := ParseSDP(req.Body())
	if err != nil {
		_ = d.ua.Respond(nil, stx, 400, "", nil)
		return
	}
	answer := &StreamSDP{
		Username:    d.cfg.DeviceID,
		Address:     d.cfg.LocalHost,
		SSRC:        remote.SSRC,
		RecvOnly:    false,
		VideoPort:   remote.VideoPort,
		AudioPort:   remote.AudioPort,
		SessionName: remote.SessionName,
		StartTime:   remote.StartTime,
		EndTime:     remote.EndTime,
	}
	answerSDP := answer.Build()
	// Answer sendonly: we stream out to the receiver's address.
	resp := sip.NewResponse(200, "")
	if to := req.To(); to != nil {
		to = to.Clone()
		to.SetTag(sip.NewTag())
		resp.Headers().Add(sip.NewHeader("To", to.String()))
	}
	resp.Headers().Set(sip.NewHeader("Contact", (&sip.Address{Uri: d.selfUri()}).String()))
	resp.SetBody("application/sdp", answerSDP)
	if err := stx.Respond(resp); err != nil {
		return
	}
	s := &Stream{Dialog: dlg, SSRC: remote.SSRC, SDP: remote}
	callID := req.CallID()
	d.mu.Lock()
	d.streams[callID] = s
	d.mu.Unlock()
	if d.OnInvite != nil {
		d.OnInvite(remote, dlg)
	}
}

// authHeaderString serializes an Authorization header value with proper
// quoting of response/nonce/cnonce/realm.
func authHeaderString(a *sip.Auth) string {
	q := func(s string) string { return `"` + s + `"` }
	v := "Digest"
	v += fmt.Sprintf(` username=%s`, q(a.Username))
	v += fmt.Sprintf(` realm=%s`, q(a.Realm))
	v += fmt.Sprintf(` nonce=%s`, q(a.Nonce))
	v += fmt.Sprintf(` uri=%s`, q(a.URI))
	if a.Response != "" {
		v += fmt.Sprintf(` response=%s`, q(a.Response))
	}
	if a.Algorithm != "" {
		v += fmt.Sprintf(` algorithm=%s`, q(a.Algorithm))
	}
	if a.Cnonce != "" {
		v += fmt.Sprintf(` cnonce=%s nc=%s qop=%s`, q(a.Cnonce), a.Nc, a.Qop)
	}
	if a.Opaque != "" {
		v += fmt.Sprintf(` opaque=%s`, q(a.Opaque))
	}
	return v
}
