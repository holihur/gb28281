package sip

import (
	"fmt"
	"sync"
	"time"
)

func (p *Proxy) SetRecordRoute(on bool) {
	p.cfgMu.Lock()
	p.cfg.RecordRoute = on
	p.cfgMu.Unlock()
}

func (p *Proxy) recordRouteEnabled() bool {
	p.cfgMu.Lock()
	defer p.cfgMu.Unlock()
	return p.cfg.RecordRoute
}

func (p *Proxy) setLogger(l Logger) {
	p.cfgMu.Lock()
	p.cfg.Logger = l
	p.cfgMu.Unlock()
}

// ProxyConfig tunes proxy behaviour.
type ProxyConfig struct {
	RecordRoute bool
	TimerC      time.Duration
	Logger      Logger
}

type branchState struct {
	ctx     *ClientTx
	target  *Uri
	final   *Response
	isFinal bool
}

type proxyDialog struct {
	callID      string
	remoteLeg   *Uri // chosen target for in-dialog requests toward the callee
	routeSet    []*Uri
	responseTag string
}

// Proxy is a stateful SIP proxy with parallel forking support.
type Proxy struct {
	Tp    *Transport
	Tm    *TxManager
	Host  string
	cfgMu sync.RWMutex
	cfg   ProxyConfig

	mu        sync.Mutex
	branches  map[string][]*branchState // stx key -> branches (fork groups)
	dialogs   map[string]*proxyDialog
	cancelled map[string]bool

	resolveMu      sync.Mutex
	ResolveTargets func(req *Request) ([]*Uri, error)
}

// SetResolveTargets sets the fork-target callback (safe for concurrent use).
func (p *Proxy) SetResolveTargets(f func(req *Request) ([]*Uri, error)) {
	p.resolveMu.Lock()
	p.ResolveTargets = f
	p.resolveMu.Unlock()
}

func (p *Proxy) resolveTargetsFn() func(req *Request) ([]*Uri, error) {
	p.resolveMu.Lock()
	defer p.resolveMu.Unlock()
	return p.ResolveTargets
}

func NewProxy(tp *Transport, tm *TxManager, host string, cfg ProxyConfig) *Proxy {
	if cfg.TimerC <= 0 {
		cfg.TimerC = 3 * time.Minute
	}
	p := &Proxy{
		Tp:        tp,
		Tm:        tm,
		Host:      host,
		cfg:       cfg,
		branches:  make(map[string][]*branchState),
		dialogs:   make(map[string]*proxyDialog),
		cancelled: make(map[string]bool),
	}
	tm.SetOnRequest(p.handleRequest)
	tm.SetOnError(func(err error, src Addr) {
		p.cfgMu.RLock()
		logger := p.cfg.Logger
		p.cfgMu.RUnlock()
		if logger != nil {
			logger.Warnf("proxy tx error: %v", err)
		}
	})
	return p
}

func (p *Proxy) dialogKey(req *Request) string {
	return req.CallID()
}

func (p *Proxy) handleRequest(req *Request, src Addr, stx *ServerTx) {
	p.cfgMu.RLock()
	logger := p.cfg.Logger
	p.cfgMu.RUnlock()
	if logger != nil {
		logger.Debugf("proxy <- %s %s", req.Method, req.Uri)
	}
	switch req.Method {
	case ACK:
		p.handleAck(req, src)
	case CANCEL:
		p.handleCancel(req, stx)
	case BYE:
		p.handleInDialog(req, stx)
	case INVITE, SUBSCRIBE, REFER:
		p.handleInitial(req, stx)
	case REGISTER, MESSAGE, OPTIONS, INFO, NOTIFY, UPDATE:
		p.handleInitial(req, stx)
	default:
		_ = stx.Respond(NewResponse(501, ""))
	}
}

// pushProxyHeaders adds our Via branch, decrements Max-Forwards and
// optionally inserts a Record-Route.
func (p *Proxy) prepareBranch(req *Request, target *Uri, newBranch bool) (*Request, error) {
	out := req.Clone().(*Request)
	out.Uri = target.Clone()
	if mf, ok := out.Headers().Get("Max-Forwards").(MaxForwards); ok {
		if mf <= 0 {
			return nil, ErrMaxForwards
		}
		out.Headers().Set(MaxForwards(int(mf) - 1))
	}
	if newBranch {
		via := &Via{
			Proto:  "SIP/2.0/UDP",
			Host:   p.Host,
			Port:   p.Tp.UDPPort(),
			Params: NewParams(),
		}
		via.SetBranch(NewBranch())
		out.Headers().Add(via)
	}
	if p.recordRouteEnabled() {
		rr := (&Address{Uri: &Uri{Scheme: "sip", Host: p.Host, Port: p.Tp.UDPPort(), Params: NewParams().Set("lr", "")}}).String()
		out.Headers().Add(NewHeader("Record-Route", rr))
	}
	return out, nil
}

func (p *Proxy) handleInitial(req *Request, stx *ServerTx) {
	resolve := p.resolveTargetsFn()
	if resolve == nil {
		_ = stx.Respond(NewResponse(500, ""))
		return
	}
	targets, err := resolve(req)
	if err != nil || len(targets) == 0 {
		_ = stx.Respond(NewResponse(500, ""))
		return
	}
	inDialog := false
	if to := req.To(); to != nil && to.Tag() != "" {
		inDialog = true
	}
	if inDialog {
		p.forwardInDialog(req, stx)
		return
	}
	p.fork(req, stx, targets)
}

func (p *Proxy) fork(req *Request, stx *ServerTx, targets []*Uri) {
	groupKey := stx.Key()
	p.mu.Lock()
	p.branches[groupKey] = nil
	p.cancelled[groupKey] = false
	p.mu.Unlock()

	for _, tgt := range targets {
		br, err := p.prepareBranch(req, tgt, true)
		if err == ErrMaxForwards {
			_ = stx.Respond(NewResponse(483, ""))
			return
		}
		if err != nil {
			continue
		}
		network, host, port := p.Tp.TransportFor(tgt)
		dst := Addr{Network: network, Host: host, Port: port}
		ctx, err := p.Tm.Request(br, dst)
		if err != nil {
			continue
		}
		bs := &branchState{ctx: ctx, target: tgt.Clone()}
		p.mu.Lock()
		p.branches[groupKey] = append(p.branches[groupKey], bs)
		p.mu.Unlock()
		go p.runBranch(groupKey, bs, stx)
	}
	// Timer C
	time.AfterFunc(p.cfg.TimerC, func() {
		p.mu.Lock()
		cancelled := p.cancelled[groupKey]
		branches := append([]*branchState(nil), p.branches[groupKey]...)
		p.mu.Unlock()
		if cancelled {
			return
		}
		stillPending := false
		for _, bs := range branches {
			if !bs.isFinal {
				stillPending = true
				_ = bs.ctx.Cancel()
			}
		}
		if stillPending {
			_ = stx.Respond(NewResponse(504, ""))
			p.cleanupGroup(groupKey)
		}
	})
}

func (p *Proxy) runBranch(groupKey string, bs *branchState, stx *ServerTx) {
	deadline := time.After(p.cfg.TimerC)
	for {
		select {
		case ev := <-bs.ctx.Events():
			if ev.Err != nil {
				bs.isFinal = true
				bs.final = NewResponse(504, "")
				p.checkGroupDone(groupKey, stx)
				return
			}
			resp := ev.Response
			if resp.StatusCode < 200 {
				continue
			}
			bs.isFinal = true
			bs.final = resp
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				p.deliverFinal(groupKey, bs, stx, resp)
				return
			}
			p.checkGroupDone(groupKey, stx)
			if bs.isFinal {
				return
			}
		case <-deadline:
			bs.isFinal = true
			bs.final = NewResponse(504, "")
			_ = bs.ctx.Cancel()
			p.checkGroupDone(groupKey, stx)
			return
		}
	}
}

// deliverFinal picks a winning 2xx, cancels sibling branches and replies upstream.
func (p *Proxy) deliverFinal(groupKey string, winner *branchState, stx *ServerTx, resp *Response) {
	p.mu.Lock()
	if p.cancelled[groupKey] {
		p.mu.Unlock()
		return
	}
	p.cancelled[groupKey] = true
	branches := append([]*branchState(nil), p.branches[groupKey]...)
	p.mu.Unlock()
	for _, bs := range branches {
		if bs != winner && !bs.isFinal {
			_ = bs.ctx.Cancel()
		}
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		contact := resp.Contact()
		var dlgContact *Uri
		if contact != nil && contact.First() != nil {
			dlgContact = contact.First().Uri.Clone()
		}
		key := stx.req.CallID()
		localTag := NewTag()
		p.mu.Lock()
		p.dialogs[key] = &proxyDialog{
			callID:      stx.req.CallID(),
			remoteLeg:   dlgContact,
			routeSet:    recordRouteSet(resp),
			responseTag: localTag,
		}
		p.mu.Unlock()
		if to := resp.Headers().Get("To"); to != nil {
			if a := addressOf(to); a != nil && a.Tag() == "" {
				a.SetTag(localTag)
			}
		}
	}

	forwarded := resp.Clone().(*Response)
	// pop our own top Via; stx.Respond re-adds the upstream Via
	forwarded.Headers().Del("Via")
	_ = stx.Respond(forwarded)
	p.cleanupGroup(groupKey)
}

func (p *Proxy) checkGroupDone(groupKey string, stx *ServerTx) {
	p.mu.Lock()
	branches := append([]*branchState(nil), p.branches[groupKey]...)
	cancelled := p.cancelled[groupKey]
	p.mu.Unlock()
	if cancelled {
		return
	}
	for _, bs := range branches {
		if !bs.isFinal {
			return
		}
	}
	// all final: pick the best non-2xx
	best := pickBestResponse(branches)
	if best == nil {
		best = NewResponse(500, "")
	}
	forwarded := best.Clone().(*Response)
	forwarded.Headers().Del("Via")
	_ = stx.Respond(forwarded)
	p.cleanupGroup(groupKey)
}

func pickBestResponse(branches []*branchState) *Response {
	var best *Response
	rank := func(code int) int {
		switch {
		case code >= 200 && code < 300:
			return 1000
		}
		prefs := []int{491, 600, 603, 486, 404, 403, 401, 407, 415, 503, 500, 502, 504}
		for i, c := range prefs {
			if c == code {
				return 900 - i
			}
		}
		return code
	}
	for _, bs := range branches {
		if bs.final == nil {
			continue
		}
		if best == nil || rank(bs.final.StatusCode) > rank(best.StatusCode) {
			best = bs.final
		}
	}
	return best
}

func (p *Proxy) cleanupGroup(groupKey string) {
	p.mu.Lock()
	delete(p.branches, groupKey)
	delete(p.cancelled, groupKey)
	p.mu.Unlock()
}

func (p *Proxy) handleCancel(req *Request, stx *ServerTx) {
	groupKey := "S|" + viaBranch(req) + "|INVITE"
	_ = groupKey
	p.mu.Lock()
	for key, branches := range p.branches {
		if key != "S|"+viaBranch(req)+"|INVITE" && key != "S|"+viaBranch(req)+"|"+string(req.Method) {
			continue
		}
		p.cancelled[key] = true
		for _, bs := range branches {
			if !bs.isFinal {
				_ = bs.ctx.Cancel()
			}
		}
	}
	p.mu.Unlock()
	_ = stx.Respond(NewResponse(200, ""))
}

func (p *Proxy) handleAck(req *Request, src Addr) {
	if dlg, ok := p.dialogs[p.dialogKey(req)]; ok && dlg.remoteLeg != nil {
		ack, err := p.prepareBranch(req, dlg.remoteLeg, false)
		if err == nil {
			_ = p.forwardRaw(ack, dlg.remoteLeg)
		}
	}
}

func (p *Proxy) handleInDialog(req *Request, stx *ServerTx) {
	dlg, ok := p.dialogs[p.dialogKey(req)]
	if !ok || dlg.remoteLeg == nil {
		_ = stx.Respond(NewResponse(481, ""))
		return
	}
	fwd, err := p.prepareBranch(req, dlg.remoteLeg, false)
	if err == ErrMaxForwards {
		_ = stx.Respond(NewResponse(483, ""))
		return
	}
	if err != nil {
		_ = stx.Respond(NewResponse(500, ""))
		return
	}
	if req.Method == BYE {
		key := p.dialogKey(req)
		p.mu.Lock()
		delete(p.dialogs, key)
		p.mu.Unlock()
	}
	go func() {
		resp, err := p.forwardAndCollect(fwd, dlg.remoteLeg)
		if err != nil {
			_ = stx.Respond(NewResponse(500, ""))
			return
		}
		_ = stx.Respond(resp)
	}()
}

func (p *Proxy) forwardInDialog(req *Request, stx *ServerTx) {
	p.handleInDialog(req, stx)
}

func (p *Proxy) forwardRaw(req *Request, target *Uri) error {
	network, host, port := p.Tp.TransportFor(target)
	return p.Tp.Send(network, Addr{Network: network, Host: host, Port: port}, req)
}

// forwardAndCollect sends a request and waits for its final response,
// retransmitting ACK for INVITE 2xx automatically.
func (p *Proxy) forwardAndCollect(req *Request, target *Uri) (*Response, error) {
	network, host, port := p.Tp.TransportFor(target)
	dst := Addr{Network: network, Host: host, Port: port}
	ctx, err := p.Tm.Request(req, dst)
	if err != nil {
		return nil, err
	}
	select {
	case ev := <-ctx.Events():
		if ev.Err != nil {
			return nil, ev.Err
		}
		return ev.Response, nil
	case <-time.After(60 * time.Second):
		return nil, ErrTimeout
	}
}

func tagOf(a *Address) string {
	if a == nil {
		return ""
	}
	return a.Tag()
}

// ErrMaxForwards signals Max-Forwards exhaustion.
var ErrMaxForwards = fmt.Errorf("sip: max forwards exhausted")
