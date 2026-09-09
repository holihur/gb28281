package gb28181

import (
	"context"
	"fmt"
	"sync"
	"time"

	sip "github.com/holihur/sip"
)

// PlatformConfig configures a GB28181 SIP platform (server / media
// signaling gateway).
type PlatformConfig struct {
	ServerID   string // e.g. 34020000002000000001
	ServerHost string // advertised host in Via/Contact
	ListenPort int    // e.g. 5060
	Realm      string // digest realm; defaults to ServerID
	Password   func(deviceID string) (password string, ok bool)
	Expires    int // registration lifetime, default 3600
}

// DeviceStatus tracks one registered device.
type DeviceStatus struct {
	ID         string
	LastSeen   time.Time
	Registered bool
	Nonce      string

	lastReg *sip.Request
}

// DeviceEvent describes device lifecycle / keepalive events.
type DeviceEvent struct {
	DeviceID string
	Type     string // registered / expired / keepalive / alarm
	Envelope *Envelope
}

// Platform is the GB28181 server side: handles device REGISTER with
// digest auth, keepalives, catalog/deviceinfo query replies, alarms,
// and originates point-playback / record queries / PTZ control.
type Platform struct {
	cfg PlatformConfig
	ua  *sip.UA
	tp  *sip.Transport

	mu        sync.Mutex
	devices   map[string]*DeviceStatus
	sn        int
	ready     chan struct{}
	channelOf map[string]string // channelID -> parent deviceID
	OnDevice  func(ev DeviceEvent)
	OnInvite  func(req *sip.Request, stx *sip.ServerTx, dlg *sip.Dialog)
}

// NewPlatform creates the platform; call Run to start serving.
func NewPlatform(cfg PlatformConfig) (*Platform, error) {
	if cfg.ServerID == "" {
		return nil, fmt.Errorf("gb28181: platform requires ServerID")
	}
	if cfg.ListenPort == 0 {
		cfg.ListenPort = 5060
	}
	if cfg.Realm == "" {
		cfg.Realm = cfg.ServerID
	}
	if cfg.Expires == 0 {
		cfg.Expires = 3600
	}
	return &Platform{cfg: cfg, devices: make(map[string]*DeviceStatus), ready: make(chan struct{}), channelOf: make(map[string]string)}, nil
}

// Ready is closed once the platform transport is bound and serving.
func (p *Platform) Ready() <-chan struct{} { return p.ready }

// Run binds transport + UA and serves until ctx is done.
func (p *Platform) Run(ctx context.Context) error {
	tp, err := sip.NewTransport("0.0.0.0", p.cfg.ListenPort, p.cfg.ListenPort)
	if err != nil {
		return err
	}
	p.tp = tp
	p.ua = sip.NewUA(tp, p.cfg.ServerHost)
	p.ua.SetCallbacks(sip.UACallbacks{
		OnRegister: p.onRegister,
		OnMessage:  p.onMessage,
		OnInvite: func(req *sip.Request, stx *sip.ServerTx, dlg *sip.Dialog) {
			if p.OnInvite != nil {
				p.OnInvite(req, stx, dlg)
			}
		},
	})
	close(p.ready)
	<-ctx.Done()
	return ctx.Err()
}

func (p *Platform) device(deviceID string) *DeviceStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	d, ok := p.devices[deviceID]
	if !ok {
		d = &DeviceStatus{ID: deviceID}
		p.devices[deviceID] = d
	}
	return d
}

// Devices returns a snapshot of known devices.
func (p *Platform) Devices() []DeviceStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]DeviceStatus, 0, len(p.devices))
	for _, d := range p.devices {
		out = append(out, *d)
	}
	return out
}

// IsOnline reports whether deviceID registered recently.
func (p *Platform) IsOnline(deviceID string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	d, ok := p.devices[deviceID]
	return ok && d.Registered && time.Since(d.LastSeen) < time.Duration(p.cfg.Expires)*time.Second
}

func (p *Platform) nextSN() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sn++
	return p.sn
}

// onRegister implements the GB28181 digest-auth REGISTER flow:
// 401 challenge, then verification of the second REGISTER.
func (p *Platform) onRegister(req *sip.Request, stx *sip.ServerTx) {
	deviceID := req.From().Uri.User
	authHdr := req.Headers().Get("Authorization")
	auth, _ := sip.ParseAuth(authValue(authHdr))
	if auth == nil || auth.Scheme == "" || auth.Response == "" {
		// challenge
		nonce := sip.NewCallID()
		d := p.device(deviceID)
		p.mu.Lock()
		d.Nonce = nonce
		d.lastReg = req
		p.mu.Unlock()
		resp := sip.NewResponse(401, "")
		resp.Headers().Set(sip.NewHeader("WWW-Authenticate", fmt.Sprintf(
			`Digest realm=%q nonce=%q`, p.cfg.Realm, nonce)))
		_ = stx.Respond(resp)
		return
	}
	password, ok := "", false
	if p.cfg.Password != nil {
		password, ok = p.cfg.Password(deviceID)
	}
	if !ok {
		_ = stx.Respond(sip.NewResponse(403, ""))
		return
	}
	if auth.Realm == "" {
		auth.Realm = p.cfg.Realm
	}
	ha1 := sip.MD5Hex(auth.Username + ":" + auth.Realm + ":" + password)
	ha2 := sip.MD5Hex(string(sip.REGISTER) + ":" + auth.URI)
	expected := sip.MD5Hex(ha1 + ":" + auth.Nonce + ":" + ha2)
	if expected != auth.Response {
		_ = stx.Respond(sip.NewResponse(401, ""))
		return
	}
	d := p.device(deviceID)
	p.mu.Lock()
	d.Registered = true
	d.LastSeen = time.Now()
	p.mu.Unlock()
	_ = stx.Respond(sip.NewResponse(200, ""))
	if p.OnDevice != nil {
		p.OnDevice(DeviceEvent{DeviceID: deviceID, Type: "registered"})
	}
}

func authValue(h sip.Header) string {
	if h == nil {
		return ""
	}
	return h.Value()
}

// onMessage handles keepalives, alarm reports and query responses.
func (p *Platform) onMessage(req *sip.Request, stx *sip.ServerTx) {
	e, err := Parse(req.Body())
	if err != nil {
		_ = p.ua.Respond(nil, stx, 400, "", nil)
		return
	}
	_ = p.ua.Respond(nil, stx, 200, "", nil)
	deviceID := req.From().Uri.User
	d := p.device(deviceID)
	switch e.CmdType {
	case CmdKeepalive:
		p.mu.Lock()
		d.LastSeen = time.Now()
		p.mu.Unlock()
	case CmdCatalog:
		if e.DeviceList != nil {
			p.mu.Lock()
			for _, it := range e.DeviceList.Items {
				p.channelOf[it.DeviceID] = deviceID
			}
			p.mu.Unlock()
		}
	case CmdDeviceInfo, CmdDeviceStatus, CmdRecordInfo, CmdMediaStatus, CmdMobilePos:
		// query responses fall through to the event callback
	}
	if p.OnDevice != nil {
		p.OnDevice(DeviceEvent{DeviceID: deviceID, Type: "message", Envelope: e})
	}
}

// sendMessage sends a MANSCDP MESSAGE to a registered device and waits
// for the final response of the SIP transaction.
func (p *Platform) sendMessage(deviceID string, body []byte) error {
	dst, ok := p.deviceAddr(deviceID)
	if !ok {
		return fmt.Errorf("gb28181: device %s not registered", deviceID)
	}
	req := p.newMessage(deviceID, dst, body)
	ctx, err := p.ua.TxManager().Request(req, dst)
	if err != nil {
		return err
	}
	select {
	case ev := <-ctx.Events():
		if ev.Err != nil {
			return ev.Err
		}
		return nil
	case <-time.After(10 * time.Second):
		return sip.ErrTimeout
	}
}

// resolveDevice maps a SIP ID (device or channel) to the parent device ID.
// Channels reported via catalog queries are tracked; unknown channel IDs
// fall back to the single registered device if unambiguous.
func (p *Platform) resolveDevice(id string) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if d, ok := p.devices[id]; ok && d.Registered {
		return id, true
	}
	// channel known from catalog?
	if dev, ok := p.channelOf[id]; ok {
		if d, ok2 := p.devices[dev]; ok2 && d.Registered {
			return dev, true
		}
	}
	var regs []string
	for did, d := range p.devices {
		if d.Registered {
			regs = append(regs, did)
		}
	}
	if len(regs) == 1 {
		return regs[0], true
	}
	return "", false
}

func (p *Platform) deviceAddr(deviceID string) (sip.Addr, bool) {
	if parent, ok := p.resolveDevice(deviceID); ok {
		deviceID = parent
	}
	req := p.lastRegisterOf(deviceID)
	if req == nil {
		return sip.Addr{}, false
	}
	via := req.Via()
	if via == nil {
		return sip.Addr{}, false
	}
	host := via.Host
	port := via.Port
	if host == "" {
		return sip.Addr{}, false
	}
	if port == 0 {
		port = 5060
	}
	return sip.Addr{Network: "udp", Host: host, Port: port}, true
}

func (p *Platform) lastRegisterOf(deviceID string) *sip.Request {
	// Use the Contact/Via from the tracked device: we re-parse from the
	// stored last REGISTER kept in DeviceStatus via lastReg field.
	p.mu.Lock()
	d := p.devices[deviceID]
	p.mu.Unlock()
	if d == nil {
		return nil
	}
	return d.lastReg
}

func (p *Platform) newMessage(deviceID string, dst sip.Addr, body []byte) *sip.Request {
	to := &sip.Uri{Scheme: "sip", User: deviceID, Host: dst.Host, Port: dst.Port}
	req := sip.NewRequest(sip.MESSAGE, to)
	from := &sip.Address{Uri: &sip.Uri{Scheme: "sip", User: p.cfg.ServerID, Host: p.cfg.ServerHost}}
	from.Params = sip.NewParams()
	from.Params.Set("tag", sip.NewTag())
	req.Headers().Set(sip.NewHeader("From", from.String()))
	req.Headers().Set(sip.NewHeader("To", (&sip.Address{Uri: to}).String()))
	req.Headers().Set(sip.NewHeader("Call-ID", sip.NewCallID()))
	req.Headers().Set(&sip.CSeq{Seq: 1, Method: sip.MESSAGE})
	req.Headers().Set(sip.MaxForwards(70))
	req.SetBody("application/MANSCDP+xml", body)
	return req
}

// QueryCatalog sends a Catalog query to deviceID.
func (p *Platform) QueryCatalog(deviceID string) error {
	e := &Envelope{CmdType: CmdCatalog, SN: p.nextSN(), DeviceID: deviceID}
	return p.sendMessage(deviceID, BuildQuery(e))
}

// QueryDeviceInfo sends a DeviceInfo query to deviceID.
func (p *Platform) QueryDeviceInfo(deviceID string) error {
	e := &Envelope{CmdType: CmdDeviceInfo, SN: p.nextSN(), DeviceID: deviceID}
	return p.sendMessage(deviceID, BuildQuery(e))
}

// PTZControl sends a PTZCmd control to deviceID.
func (p *Platform) PTZControl(deviceID, ptzCmd string) error {
	e := &Envelope{CmdType: CmdPTZCmd, SN: p.nextSN(), DeviceID: deviceID, PTZCmd: ptzCmd}
	return p.sendMessage(deviceID, BuildControl(e))
}

// InviteLive starts a point-playback INVITE toward deviceID. mediaIP /
// mediaPort describe where the platform receives RTP; ssrc is the GB28181
// y= field (e.g. 0100000001). The returned session is a standard SIP
// INVITE client session.
func (p *Platform) InviteLive(deviceID, mediaIP string, mediaPort int, ssrc uint32) (*sip.ClientInviteSession, error) {
	return p.invite(deviceID, &StreamSDP{
		Username:  p.cfg.ServerID,
		Address:   mediaIP,
		SSRC:      ssrc,
		RecvOnly:  true,
		VideoPort: mediaPort,
	})
}

// InvitePlayback starts a playback INVITE over the given time range
// (Start/End as yyyyMMddTHHmmss strings).
func (p *Platform) InvitePlayback(deviceID, mediaIP string, mediaPort int, ssrc uint32, start, end string) (*sip.ClientInviteSession, error) {
	return p.invite(deviceID, &StreamSDP{
		Username:    p.cfg.ServerID,
		Address:     mediaIP,
		SSRC:        ssrc,
		RecvOnly:    true,
		VideoPort:   mediaPort,
		SessionName: "PlayBack",
		StartTime:   start,
		EndTime:     end,
	})
}

func (p *Platform) invite(deviceID string, s *StreamSDP) (*sip.ClientInviteSession, error) {
	dst, ok := p.deviceAddr(deviceID)
	if !ok {
		return nil, fmt.Errorf("gb28181: device %s not registered", deviceID)
	}
	target := &sip.Uri{Scheme: "sip", User: deviceID, Host: dst.Host, Port: dst.Port}
	from := &sip.Address{Uri: &sip.Uri{Scheme: "sip", User: p.cfg.ServerID, Host: p.cfg.ServerHost}}
	return p.ua.Invite(target, from, "application/sdp", s.Build())
}
