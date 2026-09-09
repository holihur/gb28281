package sip

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

type Credentials struct {
	Username string
	Password string
	Realm    string
}

type UA struct {
	tp        *Transport
	tm        *TxManager
	Host      string
	UserAgent string
	dialogs   *DialogManager

	mu          sync.Mutex
	OnInvite    func(req *Request, stx *ServerTx, dlg *Dialog)
	OnRegister  func(req *Request, stx *ServerTx)
	OnBye       func(req *Request, dlg *Dialog, stx *ServerTx)
	OnMessage   func(req *Request, stx *ServerTx)
	OnInfo      func(req *Request, stx *ServerTx, dlg *Dialog)
	OnNotify    func(req *Request, stx *ServerTx)
	OnSubscribe func(req *Request, stx *ServerTx)
}

func NewUA(tp *Transport, host string) *UA {
	ua := &UA{
		tp:        tp,
		Host:      host,
		UserAgent: "go-sip/1.0",
		dialogs:   NewDialogManager(),
	}
	ua.tm = NewTxManager(tp, host, tp.UDPPort())
	ua.tm.SetOnRequest(ua.handleRequest)
	ua.tm.Run()
	return ua
}

type UACallbacks struct {
	OnInvite    func(req *Request, stx *ServerTx, dlg *Dialog)
	OnRegister  func(req *Request, stx *ServerTx)
	OnBye       func(req *Request, dlg *Dialog, stx *ServerTx)
	OnMessage   func(req *Request, stx *ServerTx)
	OnInfo      func(req *Request, stx *ServerTx, dlg *Dialog)
	OnNotify    func(req *Request, stx *ServerTx)
	OnSubscribe func(req *Request, stx *ServerTx)
}

func (ua *UA) SetCallbacks(cb UACallbacks) {
	ua.mu.Lock()
	defer ua.mu.Unlock()
	if cb.OnInvite != nil {
		ua.OnInvite = cb.OnInvite
	}
	if cb.OnRegister != nil {
		ua.OnRegister = cb.OnRegister
	}
	if cb.OnBye != nil {
		ua.OnBye = cb.OnBye
	}
	if cb.OnMessage != nil {
		ua.OnMessage = cb.OnMessage
	}
	if cb.OnInfo != nil {
		ua.OnInfo = cb.OnInfo
	}
	if cb.OnNotify != nil {
		ua.OnNotify = cb.OnNotify
	}
	if cb.OnSubscribe != nil {
		ua.OnSubscribe = cb.OnSubscribe
	}
}

func (ua *UA) callbacks() UACallbacks {
	ua.mu.Lock()
	defer ua.mu.Unlock()
	return UACallbacks{
		OnInvite:    ua.OnInvite,
		OnRegister:  ua.OnRegister,
		OnBye:       ua.OnBye,
		OnMessage:   ua.OnMessage,
		OnInfo:      ua.OnInfo,
		OnNotify:    ua.OnNotify,
		OnSubscribe: ua.OnSubscribe,
	}
}

func (ua *UA) TxManager() *TxManager   { return ua.tm }
func (ua *UA) Transport() *Transport   { return ua.tp }
func (ua *UA) Dialogs() *DialogManager { return ua.dialogs }
func (ua *UA) Port() int               { return ua.tp.UDPPort() }

func (ua *UA) handleRequest(req *Request, src Addr, stx *ServerTx) {
	cb := ua.callbacks()
	switch req.Method {
	case ACK, CANCEL:
		return
	case BYE:
		ua.handleBye(req, src, stx)
		return
	case INVITE:
		ua.handleInvite(req, stx)
		return
	case MESSAGE:
		if cb.OnMessage != nil {
			cb.OnMessage(req, stx)
			return
		}
	case OPTIONS:
		if stx != nil {
			resp := NewResponse(200, "")
			allow := ParseTokenList("Allow", "INVITE, ACK, CANCEL, BYE, REGISTER, OPTIONS, MESSAGE, INFO, NOTIFY, SUBSCRIBE")
			resp.Headers().Set(allow)
			_ = stx.Respond(resp)
		}
		return
	case INFO:
		dlg := ua.findDialog(req)
		if cb.OnInfo != nil && dlg != nil {
			cb.OnInfo(req, stx, dlg)
			return
		}
	case NOTIFY:
		if cb.OnNotify != nil {
			cb.OnNotify(req, stx)
			return
		}
	case SUBSCRIBE:
		if cb.OnSubscribe != nil {
			cb.OnSubscribe(req, stx)
			return
		}
	case REGISTER:
		if cb.OnRegister != nil {
			cb.OnRegister(req, stx)
			return
		}
	}
	if stx != nil {
		resp := NewResponse(501, "")
		resp.Headers().Set(MaxForwards(70))
		_ = stx.Respond(resp)
	}
}

func (ua *UA) findDialog(req *Request) *Dialog {
	to := req.To()
	from := req.From()
	if to == nil || from == nil {
		return nil
	}
	d := ua.dialogs.Get(req.CallID(), to.Tag(), from.Tag())
	if d != nil {
		d.updateFromRequest(req)
	}
	return d
}

func (ua *UA) handleBye(req *Request, src Addr, stx *ServerTx) {
	dlg := ua.findDialog(req)
	resp := NewResponse(200, "")
	if dlg == nil {
		resp = NewResponse(481, "")
		_ = stx.Respond(resp)
		return
	}
	if !dialogSourceAllowed(dlg, src) {
		_ = stx.Respond(NewResponse(403, ""))
		return
	}
	if cseq := req.CSeq(); cseq != nil && cseq.Seq < dlg.getRemoteSeq() {
		_ = stx.Respond(NewResponse(500, ""))
		return
	}
	dlg.Terminate()
	ua.dialogs.Remove(dlg)
	_ = stx.Respond(resp)
	if cb := ua.callbacks(); cb.OnBye != nil {
		cb.OnBye(req, dlg, stx)
	}
}

// dialogSourceAllowed verifies an in-dialog request came from the dialog's
// remote endpoint, defending against spoofed BYE/CANCEL.
func dialogSourceAllowed(dlg *Dialog, src Addr) bool {
	if dlg == nil {
		return false
	}
	host := ""
	if dlg.RemoteTarget != nil {
		host = dlg.RemoteTarget.Host
	} else if dlg.Remote != nil && dlg.Remote.Uri != nil {
		host = dlg.Remote.Uri.Host
	}
	if host == "" {
		return true
	}
	return sameHost(src.Host, host)
}

func (ua *UA) handleInvite(req *Request, stx *ServerTx) {
	if ua.callbacks().OnInvite == nil {
		resp := NewResponse(501, "")
		_ = stx.Respond(resp)
		return
	}
	localTag := NewTag()
	dlg := NewServerDialog(req, localTag)
	ua.dialogs.Add(dlg)
	ua.callbacks().OnInvite(req, stx, dlg)
}

// Register sends a REGISTER for aor. contact may be nil to use a default.
func (ua *UA) Register(aor *Uri, contact *Uri, expires int, creds *Credentials) (*ClientTx, error) {
	if contact == nil {
		contact = &Uri{Scheme: aor.Scheme, User: aor.User, Host: ua.Host, Port: ua.Port()}
	}
	req := NewRequest(REGISTER, aor.Clone())
	from := &Address{Uri: aor.Clone(), Params: NewParams()}
	from.Params.Set("tag", NewTag())
	req.Headers().Set(fromHeader(from))
	to := &Address{Uri: aor.Clone()}
	req.Headers().Set(toHeader(to))
	req.Headers().Set(NewHeader("Call-ID", NewCallID()))
	req.Headers().Set(&CSeq{Seq: 1, Method: REGISTER})
	req.Headers().Set(MaxForwards(70))
	req.Headers().Set(NewHeader("Expires", fmt.Sprint(expires)))
	req.Headers().Set(NewHeader("Contact", contact.String()+";expires="+fmt.Sprint(expires)))
	req.Headers().Set(NewHeader("User-Agent", ua.UserAgent))
	if creds != nil {
		ua.authHeaders(req, creds)
	}
	dst := Addr{Network: "udp", Host: aor.Host, Port: aor.EffectivePort()}
	return ua.tm.Request(req, dst)
}

func (ua *UA) authHeaders(req *Request, creds *Credentials) {
	req.Headers().Set(NewHeader("Authorization", fmt.Sprintf(
		`Digest username="%s", realm="%s", uri="%s"`,
		escapeAuthValue(creds.Username), escapeAuthValue(creds.Realm), escapeAuthValue(req.Uri.String()))))
}

// escapeAuthValue escapes a value destined for a quoted auth parameter so
// it cannot break out of the quoting.
func escapeAuthValue(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, `"`, `\"`)
}

func MD5Hex(parts ...string) string {
	h := md5.New()
	for _, p := range parts {
		h.Write([]byte(p))
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// digestHashHex hashes s according to the Digest algorithm; falls back to MD5.
func digestHashHex(algorithm string, parts ...string) string {
	joined := strings.Join(parts, "")
	switch strings.ToLower(algorithm) {
	case "sha-256":
		sum := sha256.Sum256([]byte(joined))
		return hex.EncodeToString(sum[:])
	case "sha-512-256":
		sum := sha512.Sum512_256([]byte(joined))
		return hex.EncodeToString(sum[:])
	default:
		return MD5Hex(parts...)
	}
}

func DigestResponse(challenge *Auth, method Method, uri, username, password string, cnonce, nc string) *Auth {
	algorithm := strings.ToUpper(challenge.Algorithm)
	qop := challenge.Qop
	ha1 := digestHashHex(challenge.Algorithm, username+":"+challenge.Realm+":"+password)
	ha2 := digestHashHex(challenge.Algorithm, string(method)+":"+uri)
	var resp string
	if qop == "" {
		resp = digestHashHex(challenge.Algorithm, ha1+":"+challenge.Nonce+":"+ha2)
	} else {
		resp = digestHashHex(challenge.Algorithm, ha1+":"+challenge.Nonce+":"+nc+":"+cnonce+":"+qop+":"+ha2)
	}
	a := &Auth{
		Scheme:    "Digest",
		Username:  username,
		Realm:     challenge.Realm,
		Nonce:     challenge.Nonce,
		URI:       uri,
		Response:  resp,
		Qop:       qop,
		Cnonce:    cnonce,
		Nc:        nc,
		Algorithm: algorithm,
		Opaque:    challenge.Opaque,
	}
	return a
}

type ClientInviteSession struct {
	ua    *UA
	ctx   *ClientTx
	dlg   *Dialog
	mu    sync.Mutex
	Done  chan struct{}
	Final *Response
	Err   error
}

func (s *ClientInviteSession) Dialog() *Dialog { return s.dlg }
func (s *ClientInviteSession) Tx() *ClientTx   { return s.ctx }

// WaitResponse blocks until a final response or timeout.
func (s *ClientInviteSession) WaitResponse(timeout time.Duration) (*Response, error) {
	select {
	case <-s.Done:
		return s.Final, s.Err
	case <-time.After(timeout):
		return nil, ErrTimeout
	}
}

// Invite starts an outgoing INVITE with an early dialog.
func (ua *UA) Invite(target *Uri, from *Address, contentType string, body []byte) (*ClientInviteSession, error) {
	req := NewRequest(INVITE, target.Clone())
	localTag := NewTag()
	from = from.Clone()
	if from.Params == nil {
		from.Params = NewParams()
	}
	from.Params.Set("tag", localTag)
	req.Headers().Set(fromHeader(from))
	to := &Address{Uri: target.Clone()}
	req.Headers().Set(toHeader(to))
	req.Headers().Set(NewHeader("Call-ID", NewCallID()))
	req.Headers().Set(&CSeq{Seq: 1, Method: INVITE})
	req.Headers().Set(MaxForwards(70))
	req.Headers().Set(NewHeader("Contact", (&Address{Uri: &Uri{Scheme: target.Scheme, User: from.Uri.User, Host: ua.Host, Port: ua.Port()}}).String()))
	req.Headers().Set(NewHeader("User-Agent", ua.UserAgent))
	req.SetBody(contentType, body)
	dst := Addr{Network: "udp", Host: target.Host, Port: target.EffectivePort()}
	ctx, err := ua.tm.Request(req, dst)
	if err != nil {
		return nil, err
	}
	sess := &ClientInviteSession{
		ua:   ua,
		ctx:  ctx,
		dlg:  NewClientDialog(req.CallID(), localTag, "", from, to, 1),
		Done: make(chan struct{}),
	}
	ua.dialogs.Add(sess.dlg)
	go sess.pump()
	return sess, nil
}

func (s *ClientInviteSession) pump() {
	for {
		ev, ok := <-s.ctx.Events()
		if !ok {
			return
		}
		if ev.Err != nil {
			s.mu.Lock()
			s.Err = ev.Err
			s.mu.Unlock()
			close(s.Done)
			return
		}
		resp := ev.Response
		s.dlg.updateFromResponse(resp)
		if resp.StatusCode >= 300 {
			s.mu.Lock()
			s.Final = resp
			s.mu.Unlock()
			s.dlg.Terminate()
			s.ua.dialogs.Remove(s.dlg)
			close(s.Done)
			return
		}
		if resp.StatusCode >= 200 {
			s.mu.Lock()
			s.Final = resp
			s.mu.Unlock()
			s.dlg.SetState(DialogConfirmed)
			if s.dlg.RemoteTarget == nil {
				if cu := contactUri(resp); cu != nil {
					s.dlg.RemoteTarget = cu
				} else if s.dlg.Remote != nil {
					s.dlg.RemoteTarget = s.dlg.Remote.Uri.Clone()
				}
			}
			close(s.Done)
			return
		}
	}
}

func contactUri(resp *Response) *Uri {
	l := resp.Contact()
	if l == nil {
		return nil
	}
	c := l.First()
	if c == nil {
		return nil
	}
	return c.Uri.Clone()
}

// Ack sends the ACK for a confirmed 2xx response.
func (s *ClientInviteSession) Ack() error {
	resp := s.Final
	if resp == nil {
		return ErrInvalidResponse
	}
	orig := s.ctx.Request()
	ack := NewRequest(ACK, s.dlg.RemoteTarget.Clone())
	if via := orig.Via(); via != nil {
		ack.Headers().Add(via.Clone())
	}
	for _, h := range orig.Headers().All("Route") {
		ack.Headers().Add(h.Clone())
	}
	if f := orig.Headers().Get("From"); f != nil {
		ack.Headers().Add(f.Clone())
	}
	if to := resp.Headers().Get("To"); to != nil {
		ack.Headers().Add(to.Clone())
	}
	ack.Headers().Set(NewHeader("Call-ID", s.dlg.CallID))
	if cseq := orig.CSeq(); cseq != nil {
		ack.Headers().Set(&CSeq{Seq: cseq.Seq, Method: ACK})
	}
	ack.Headers().Set(MaxForwards(70))
	network, host, port := s.ua.tp.TransportFor(s.dlg.RemoteTarget)
	return s.ua.tp.Send(network, Addr{Network: network, Host: host, Port: port}, ack)
}

// Hangup sends BYE on a dialog and waits for the final response.
// A 491 (glare) response is retried with exponential backoff up to 2 times.
func (ua *UA) Hangup(dlg *Dialog, timeout time.Duration) (*Response, error) {
	backoff := 200 * time.Millisecond
	var lastResp *Response
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(backoff)
			backoff *= 2
		}
		req, err := dlg.CreateRequest(BYE, "", nil)
		if err != nil {
			return nil, err
		}
		resp, err := ua.sendAndWait(req, dlg.RemoteTarget, timeout)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == 491 {
			lastResp = resp
			continue
		}
		dlg.Terminate()
		return resp, nil
	}
	if lastResp != nil {
		return lastResp, nil
	}
	return nil, ErrTimeout
}

func (ua *UA) sendAndWait(req *Request, target *Uri, timeout time.Duration) (*Response, error) {
	network, host, port := ua.tp.TransportFor(target)
	dst := Addr{Network: network, Host: host, Port: port}
	ctx, err := ua.tm.Request(req, dst)
	if err != nil {
		return nil, err
	}
	deadline := time.After(timeout)
	for {
		select {
		case ev := <-ctx.Events():
			if ev.Err != nil {
				return nil, ev.Err
			}
			if ev.Response.StatusCode >= 200 {
				return ev.Response, nil
			}
		case <-deadline:
			return nil, ErrTimeout
		}
	}
}

// Respond sends a response for an incoming dialog-creating request via the server tx.
func (ua *UA) Respond(dlg *Dialog, stx *ServerTx, status int, contentType string, body []byte) error {
	resp := NewResponse(status, "")
	if dlg != nil {
		if resp.Headers().Get("To") == nil && dlg.Local != nil {
			resp.Headers().Set(toHeader(dlg.Local.Clone()))
		}
		if status >= 100 && dlg.LocalTag != "" {
			if to := resp.Headers().Get("To"); to != nil {
				if a := addressOf(to); a != nil && a.Tag() == "" {
					a.SetTag(dlg.LocalTag)
				}
			}
		}
	}
	if status >= 200 && status < 300 && dlg != nil {
		if dlg.RemoteTarget != nil {
			resp.Headers().Set(NewHeader("Contact", (&Address{Uri: dlg.RemoteTarget}).String()))
		}
	} else if status >= 200 && dlg == nil {
		if to := resp.Headers().Get("To"); to != nil {
			if a := addressOf(to); a != nil && a.Tag() == "" {
				a.SetTag(NewTag())
			}
		}
	}
	resp.SetBody(contentType, body)
	if stx == nil {
		return ErrUnsupported
	}
	return stx.Respond(resp)
}
