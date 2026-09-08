package sip

import (
	"sync"
	"time"
)

// MediaRelay abstracts media handling between the two legs of a B2BUA session.
type MediaRelay interface {
	Start(a, b *Uri) error
	Stop()
}

type noopRelay struct{}

func (noopRelay) Start(*Uri, *Uri) error { return nil }
func (noopRelay) Stop()                  {}

// B2BSession pairs the two dialog legs of a bridged call.
type B2BSession struct {
	ID       string
	ALeg     *Dialog
	BLeg     *Dialog
	ASession *ClientInviteSession // outgoing leg toward B is driven by this
	relay    MediaRelay
}

// B2BUA bridges incoming calls on one UA to outgoing calls on another UA.
type B2BUA struct {
	mu       sync.Mutex
	ingress  *UA
	egress   *UA
	relay    MediaRelay
	sessions map[string]*B2BSession

	routeTargetMu  sync.Mutex
	RouteTarget    func(req *Request) (*Uri, error)
	OnSessionStart func(s *B2BSession)
	OnSessionEnd   func(s *B2BSession)
}

// SetRouteTarget sets the egress routing callback (safe for concurrent use).
func (b *B2BUA) SetRouteTarget(f func(req *Request) (*Uri, error)) {
	b.routeTargetMu.Lock()
	b.RouteTarget = f
	b.routeTargetMu.Unlock()
}

func (b *B2BUA) routeTargetFn() func(req *Request) (*Uri, error) {
	b.routeTargetMu.Lock()
	defer b.routeTargetMu.Unlock()
	return b.RouteTarget
}

// SetSessionHooks sets optional lifecycle notifications.
func (b *B2BUA) SetSessionHooks(start, end func(s *B2BSession)) {
	b.routeTargetMu.Lock()
	b.OnSessionStart = start
	b.OnSessionEnd = end
	b.routeTargetMu.Unlock()
}

func NewB2BUA(ingress, egress *UA, relay MediaRelay) *B2BUA {
	if relay == nil {
		relay = noopRelay{}
	}
	b := &B2BUA{
		ingress:  ingress,
		egress:   egress,
		relay:    relay,
		sessions: make(map[string]*B2BSession),
	}
	ingress.SetCallbacks(UACallbacks{OnInvite: b.handleIngressInvite})
	egress.SetCallbacks(UACallbacks{OnBye: func(req *Request, dlg *Dialog, stx *ServerTx) {
		b.handleLegBye(dlg)
	}})
	ingress.SetCallbacks(mergeCallbacks(ingress.callbacks(), UACallbacks{OnBye: func(req *Request, dlg *Dialog, stx *ServerTx) {
		b.handleLegBye(dlg)
	}}))
	return b
}

func mergeCallbacks(a, b UACallbacks) UACallbacks {
	out := a
	out.OnBye = b.OnBye
	return out
}

func (b *B2BUA) handleIngressInvite(req *Request, stx *ServerTx, aDlg *Dialog) {
	if b.routeTargetFn() == nil {
		_ = b.ingress.Respond(aDlg, stx, 501, "", nil)
		return
	}
	target, err := b.routeTargetFn()(req)
	if err != nil {
		_ = b.ingress.Respond(aDlg, stx, 500, "", nil)
		return
	}
	sdp := string(req.Body())
	var ct string
	if h := req.Headers().Get("Content-Type"); h != nil {
		ct = h.Value()
	}
	from := &Address{Uri: req.From().Uri.Clone()}
	sess, err := b.egress.Invite(target, from, ct, []byte(sdp))
	if err != nil {
		_ = b.ingress.Respond(aDlg, stx, 503, "", nil)
		return
	}
	go func() {
		resp, err := sess.WaitResponse(60 * time.Second)
		if err != nil || resp.StatusCode >= 300 {
			code := 503
			if resp != nil {
				code = resp.StatusCode
			}
			_ = b.ingress.Respond(aDlg, stx, code, "", nil)
			return
		}
		if resp.StatusCode == 200 {
			_ = sess.Ack()
		}
		var body []byte
		if len(resp.Body()) > 0 {
			body = resp.Body()
		}
		if err := b.ingress.Respond(aDlg, stx, 200, ct, body); err != nil {
			return
		}
		session := &B2BSession{
			ID:       req.CallID(),
			ALeg:     aDlg,
			BLeg:     sess.Dialog(),
			ASession: sess,
			relay:    b.relay,
		}
		_ = b.relay.Start(aDlg.RemoteTarget, sess.Dialog().RemoteTarget)
		b.mu.Lock()
		b.sessions[session.ID] = session
		b.mu.Unlock()
		b.routeTargetMu.Lock()
		onStart := b.OnSessionStart
		b.routeTargetMu.Unlock()
		if onStart != nil {
			onStart(session)
		}
	}()
}

// handleLegBye tears down the peer leg when either side hangs up.
func (b *B2BUA) handleLegBye(dlg *Dialog) {
	if dlg == nil {
		return
	}
	b.mu.Lock()
	var found *B2BSession
	for _, s := range b.sessions {
		if s.ALeg == dlg || s.BLeg == dlg {
			found = s
		}
	}
	if found != nil {
		delete(b.sessions, found.ID)
	}
	b.mu.Unlock()
	if found == nil {
		return
	}
	peer := found.ALeg
	peerUA := b.ingress
	if dlg == found.ALeg {
		peer = found.BLeg
		peerUA = b.egress
	}
	b.relay.Stop()
	if peer != nil && peer.GetState() != DialogTerminated {
		_, _ = peerUA.Hangup(peer, 10*time.Second)
	}
	b.routeTargetMu.Lock()
	onEnd := b.OnSessionEnd
	b.routeTargetMu.Unlock()
	if onEnd != nil {
		onEnd(found)
	}
}

func (b *B2BUA) Sessions() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.sessions)
}
