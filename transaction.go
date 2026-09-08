package sip

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
	"sync"
	"time"
)

type TxConfig struct {
	T1     time.Duration
	T2     time.Duration
	TimerD time.Duration
	TimerF time.Duration
	TimerJ time.Duration
}

func DefaultTxConfig() TxConfig {
	return TxConfig{
		T1:     500 * time.Millisecond,
		T2:     4 * time.Second,
		TimerD: 32 * time.Second,
		TimerF: 32 * time.Second,
		TimerJ: 32 * time.Second,
	}
}

type TxState int

const (
	TxStateIdle TxState = iota
	TxStateCalling
	TxStateTrying
	TxStateProceeding
	TxStateCompleted
	TxStateConfirmed
	TxStateTerminated
)

func (s TxState) String() string {
	switch s {
	case TxStateIdle:
		return "idle"
	case TxStateCalling:
		return "calling"
	case TxStateTrying:
		return "trying"
	case TxStateProceeding:
		return "proceeding"
	case TxStateCompleted:
		return "completed"
	case TxStateConfirmed:
		return "confirmed"
	case TxStateTerminated:
		return "terminated"
	}
	return "unknown"
}

type Transaction interface {
	Key() string
	State() TxState
	Terminated() <-chan struct{}
}

type TxEvent struct {
	Response *Response
	Err      error
}

type ClientTx struct {
	mu         sync.Mutex
	m          *TxManager
	req        *Request
	key        string
	dst        Addr
	state      TxState
	events     chan TxEvent
	terminated chan struct{}
	stop       chan struct{}
	stopOnce   sync.Once
}

type ServerTx struct {
	mu         sync.Mutex
	m          *TxManager
	req        *Request
	key        string
	src        Addr
	state      TxState
	final      *Response
	terminated chan struct{}
	stop       chan struct{}
	stopOnce   sync.Once
}

type TxManager struct {
	tp      *Transport
	cfgMu   sync.RWMutex
	cfg     TxConfig
	viaHost string
	viaPort int

	mu   sync.Mutex
	cbMu sync.Mutex
	txs  map[string]Transaction

	Metrics *Metrics

	OnRequest  func(req *Request, src Addr, stx *ServerTx)
	OnResponse func(resp *Response, src Addr, ctx *ClientTx)
	OnError    func(err error, src Addr)
}

func (m *TxManager) SetOnRequest(f func(req *Request, src Addr, stx *ServerTx)) {
	m.cbMu.Lock()
	m.OnRequest = f
	m.cbMu.Unlock()
}

func (m *TxManager) SetOnResponse(f func(resp *Response, src Addr, ctx *ClientTx)) {
	m.cbMu.Lock()
	m.OnResponse = f
	m.cbMu.Unlock()
}

func (m *TxManager) SetOnError(f func(err error, src Addr)) {
	m.cbMu.Lock()
	m.OnError = f
	m.cbMu.Unlock()
}

func (m *TxManager) onRequestFn() func(req *Request, src Addr, stx *ServerTx) {
	m.cbMu.Lock()
	defer m.cbMu.Unlock()
	return m.OnRequest
}

func (m *TxManager) onResponseFn() func(resp *Response, src Addr, ctx *ClientTx) {
	m.cbMu.Lock()
	defer m.cbMu.Unlock()
	return m.OnResponse
}

func (m *TxManager) onErrorFn() func(err error, src Addr) {
	m.cbMu.Lock()
	defer m.cbMu.Unlock()
	return m.OnError
}

func NewTxManager(tp *Transport, viaHost string, viaPort int) *TxManager {
	return &TxManager{
		tp:      tp,
		cfg:     DefaultTxConfig(),
		viaHost: viaHost,
		viaPort: viaPort,
		txs:     make(map[string]Transaction),
	}
}

func (m *TxManager) SetConfig(cfg TxConfig) {
	m.cfgMu.Lock()
	m.cfg = cfg
	m.cfgMu.Unlock()
}

func (m *TxManager) Config() TxConfig {
	m.cfgMu.RLock()
	defer m.cfgMu.RUnlock()
	return m.cfg
}

func (m *TxManager) config() TxConfig {
	return m.Config()
}

func (m *TxManager) Run() {
	go func() {
		for pkt := range m.tp.Packets() {
			m.handlePacket(pkt)
		}
	}()
}

func NewBranch() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("z9hG4bK%d", time.Now().UnixNano())
	}
	return "z9hG4bK" + hex.EncodeToString(b)
}

func serverTxKey(req *Request) string {
	via := req.Via()
	branch := ""
	if via != nil {
		branch = via.Branch()
	}
	var method Method
	if cseq := req.CSeq(); cseq != nil {
		method = cseq.Method
	}
	return "S|" + branch + "|" + string(method)
}

func clientTxKey(req *Request) string {
	via := req.Via()
	branch := ""
	if via != nil {
		branch = via.Branch()
	}
	var method Method
	if cseq := req.CSeq(); cseq != nil {
		method = cseq.Method
	}
	return "C|" + branch + "|" + string(method)
}

func (m *TxManager) handlePacket(pkt *Packet) {
	if m.Metrics != nil {
		m.Metrics.Inc("packets_received")
	}
	switch msg := pkt.Msg.(type) {
	case *Request:
		m.handleRequest(msg, pkt.Src)
	case *Response:
		m.handleResponse(msg, pkt.Src)
	}
}

func (m *TxManager) handleRequest(req *Request, src Addr) {
	cseq := req.CSeq()
	method := Method("")
	if cseq != nil {
		method = cseq.Method
	}
	if method == ACK {
		key := "S|" + viaBranch(req) + "|INVITE"
		m.mu.Lock()
		stx, ok := m.txs[key].(*ServerTx)
		m.mu.Unlock()
		if ok {
			stx.receiveACK(req)
			return
		}
		if m.onRequestFn() != nil {
			m.onRequestFn()(req, src, nil)
		}
		return
	}
	key := serverTxKey(req)
	m.mu.Lock()
	stx, ok := m.txs[key].(*ServerTx)
	if ok {
		m.mu.Unlock()
		stx.receiveRetransmission(req)
		return
	}
	if key == "" {
		m.mu.Unlock()
		return
	}
	stx = &ServerTx{
		m:          m,
		req:        req,
		key:        key,
		src:        src,
		state:      TxStateProceeding,
		terminated: make(chan struct{}),
		stop:       make(chan struct{}),
	}
	m.txs[key] = stx
	m.mu.Unlock()
	handler := m.onRequestFn()
	if handler != nil {
		handler(req, src, stx)
	}
}

func (m *TxManager) handleResponse(resp *Response, src Addr) {
	key := clientTxKeyOf(resp)
	if key == "" {
		return
	}
	m.mu.Lock()
	ctx, ok := m.txs[key].(*ClientTx)
	m.mu.Unlock()
	if ok {
		ctx.receive(resp)
		if onResponse := m.onResponseFn(); onResponse != nil {
			onResponse(resp, src, ctx)
		}
		return
	}
	if onError := m.onErrorFn(); onError != nil {
		onError(fmt.Errorf("%w: %s", ErrTxNotFound, key), src)
	}
}

func viaBranch(req *Request) string {
	via := req.Via()
	if via == nil {
		return ""
	}
	return via.Branch()
}

func clientTxKeyOf(resp *Response) string {
	via := resp.Via()
	if via == nil {
		return ""
	}
	branch := via.Branch()
	method := ""
	if cseq := resp.CSeq(); cseq != nil {
		method = string(cseq.Method)
	}
	return "C|" + branch + "|" + method
}

func (m *TxManager) Request(req *Request, dst Addr) (*ClientTx, error) {
	if req.Via() == nil {
		if req.Headers().Get("Via") == nil {
			via := &Via{Proto: "SIP/2.0/" + m.defaultTransport(), Host: m.viaHost, Port: m.viaPort, Params: NewParams()}
			via.SetBranch(NewBranch())
			req.Headers().Add(via)
		}
	}
	if req.Headers().Get("Max-Forwards") == nil {
		req.Headers().Set(MaxForwards(70))
	}
	if req.Headers().Get("Call-ID") == nil {
		req.Headers().Set(NewHeader("Call-ID", NewCallID()))
	}
	if req.Headers().Get("CSeq") == nil {
		req.Headers().Set(&CSeq{Seq: 1, Method: req.Method})
	}
	key := clientTxKey(req)
	m.mu.Lock()
	if _, exists := m.txs[key]; exists {
		m.mu.Unlock()
		return nil, ErrTxExists
	}
	ctx := &ClientTx{
		m:          m,
		req:        req,
		key:        key,
		dst:        dst,
		state:      TxStateIdle,
		events:     make(chan TxEvent, 64),
		terminated: make(chan struct{}),
		stop:       make(chan struct{}),
	}
	m.txs[key] = ctx
	m.mu.Unlock()
	if err := m.send(ctx.req, dst); err != nil {
		m.remove(key)
		return nil, err
	}
	ctx.mu.Lock()
	if req.Method == INVITE {
		ctx.state = TxStateCalling
	} else {
		ctx.state = TxStateTrying
	}
	ctx.mu.Unlock()
	ctx.startRetransmit()
	return ctx, nil
}

func (m *TxManager) defaultTransport() string {
	if m.tp != nil {
		if m.tp.udpConn != nil {
			return "UDP"
		}
		if m.tp.tcpListener != nil {
			return "TCP"
		}
	}
	return "UDP"
}

func (m *TxManager) send(msg Message, dst Addr) error {
	if m.tp == nil {
		return ErrTransportClosed
	}
	network := dst.Network
	if network == "" {
		if req, ok := msg.(*Request); ok && req.Uri != nil {
			network, _, _ = m.tp.TransportFor(req.Uri)
		} else {
			network = "udp"
		}
	}
	host, port := dst.Host, dst.Port
	if port == 0 {
		if req, ok := msg.(*Request); ok && req.Uri != nil {
			_, host, port = m.tp.TransportFor(req.Uri)
		}
	}
	return m.tp.Send(network, Addr{Network: network, Host: host, Port: port}, msg)
}

func (m *TxManager) remove(key string) {
	m.mu.Lock()
	delete(m.txs, key)
	m.mu.Unlock()
}

func NewCallID() string {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d@%s", time.Now().UnixNano(), "localhost")
	}
	return hex.EncodeToString(b) + "@localhost"
}

// ClientTx

func (t *ClientTx) Key() string                 { return t.key }
func (t *ClientTx) State() TxState              { t.mu.Lock(); defer t.mu.Unlock(); return t.state }
func (t *ClientTx) Terminated() <-chan struct{} { return t.terminated }
func (t *ClientTx) Request() *Request           { return t.req }
func (t *ClientTx) Events() <-chan TxEvent      { return t.events }

func (t *ClientTx) setState(s TxState) {
	t.state = s
}

func (t *ClientTx) startRetransmit() {
	t1 := t.m.config().T1
	capInterval := t.m.config().T2
	if t.req.Method == INVITE {
		capInterval = t1 * 2
	}
	retransmit := func() {
		if t.m.send(t.req, t.dst) == nil && t.m.OnError != nil {
			_ = 0
		}
	}
	var elapsed time.Duration
	interval := t1
	go func() {
		for {
			select {
			case <-t.stop:
				return
			case <-time.After(interval):
			}
			t.mu.Lock()
			if t.state == TxStateCompleted || t.state == TxStateTerminated {
				t.mu.Unlock()
				return
			}
			if t.req.Method == INVITE && t.state == TxStateProceeding {
				t.mu.Unlock()
				return
			}
			t.mu.Unlock()
			retransmit()
			elapsed += interval
			if t.req.Method == INVITE {
				if elapsed >= t.m.config().TimerF {
					t.timeout()
					return
				}
			} else if elapsed >= t.m.config().TimerF {
				t.timeout()
				return
			}
			interval *= 2
			if interval > capInterval {
				interval = capInterval
			}
		}
	}()
}

func (t *ClientTx) timeout() {
	t.mu.Lock()
	if t.state == TxStateCompleted || t.state == TxStateTerminated {
		t.mu.Unlock()
		return
	}
	t.mu.Unlock()
	select {
	case t.events <- TxEvent{Err: ErrTimeout}:
	default:
	}
	t.finish()
}

func (t *ClientTx) receive(resp *Response) {
	t.mu.Lock()
	switch {
	case resp.StatusCode < 200:
		if t.state == TxStateCompleted || t.state == TxStateTerminated {
			t.mu.Unlock()
			return
		}
		t.setState(TxStateProceeding)
		t.mu.Unlock()
		t.deliver(TxEvent{Response: resp})
	case resp.StatusCode < 300:
		if t.req.Method == INVITE {
			wasCompleted := t.state == TxStateCompleted
			t.setState(TxStateCompleted)
			t.mu.Unlock()
			if !wasCompleted {
				t.deliver(TxEvent{Response: resp})
				t.m.schedule(t.m.config().TimerD, t.finish)
			}
			t.sendACK(resp)
			return
		}
		t.mu.Unlock()
		t.deliver(TxEvent{Response: resp})
		t.finish()
	default:
		if t.state == TxStateCompleted || t.state == TxStateTerminated {
			t.mu.Unlock()
			return
		}
		t.setState(TxStateCompleted)
		t.mu.Unlock()
		t.deliver(TxEvent{Response: resp})
		t.sendACK(resp)
		t.m.schedule(t.m.config().TimerD, t.finish)
	}
}

func (t *ClientTx) deliver(e TxEvent) {
	select {
	case t.events <- e:
	default:
	}
}

func (t *ClientTx) sendACK(resp *Response) {
	via := t.req.Via()
	ack := NewRequest(ACK, t.req.Uri)
	ack.Headers().Add(via.Clone())
	for _, h := range t.req.Headers().All("Route") {
		ack.Headers().Add(h.Clone())
	}
	if f := t.req.Headers().Get("From"); f != nil {
		ack.Headers().Add(f.Clone())
	}
	if to := resp.Headers().Get("To"); to != nil {
		ack.Headers().Add(to.Clone())
	}
	ack.Headers().Set(NewHeader("Call-ID", t.req.CallID()))
	if cseq := t.req.CSeq(); cseq != nil {
		ack.Headers().Set(&CSeq{Seq: cseq.Seq, Method: ACK})
	}
	ack.Headers().Set(MaxForwards(70))
	_ = t.m.send(ack, t.dst)
}

func (t *ClientTx) Cancel() error {
	t.mu.Lock()
	switch t.state {
	case TxStateProceeding:
		t.mu.Unlock()
	case TxStateCalling:
		t.mu.Unlock()
	default:
		t.mu.Unlock()
		return ErrUnsupported
	}
	cancel := NewRequest(CANCEL, t.req.Uri)
	via := t.req.Via()
	if via != nil {
		cancel.Headers().Add(via.Clone())
	}
	if f := t.req.Headers().Get("From"); f != nil {
		cancel.Headers().Add(f.Clone())
	}
	if to := t.req.Headers().Get("To"); to != nil {
		cancel.Headers().Add(to.Clone())
	}
	cancel.Headers().Set(NewHeader("Call-ID", t.req.CallID()))
	if cseq := t.req.CSeq(); cseq != nil {
		cancel.Headers().Set(&CSeq{Seq: cseq.Seq, Method: CANCEL})
	}
	cancel.Headers().Set(MaxForwards(70))
	return t.m.send(cancel, t.dst)
}

func (t *ClientTx) finish() {
	t.stopOnce.Do(func() {
		close(t.stop)
	})
	t.m.remove(t.key)
	select {
	case <-t.terminated:
	default:
		close(t.terminated)
	}
}

// ServerTx

func (t *ServerTx) Key() string                 { return t.key }
func (t *ServerTx) State() TxState              { t.mu.Lock(); defer t.mu.Unlock(); return t.state }
func (t *ServerTx) Terminated() <-chan struct{} { return t.terminated }
func (t *ServerTx) Request() *Request           { return t.req }

func (t *ServerTx) isInvite() bool { return t.req.Method == INVITE }

func (t *ServerTx) receiveRetransmission(req *Request) {
	t.mu.Lock()
	final := t.final
	state := t.state
	t.mu.Unlock()
	if final != nil && (state == TxStateCompleted || state == TxStateConfirmed) {
		_ = t.m.send(final, t.src)
	}
}

func (t *ServerTx) setState(s TxState) {
	t.state = s
}

func (t *ServerTx) receiveACK(ack *Request) {
	t.mu.Lock()
	state := t.state
	t.mu.Unlock()
	_ = state
	if !t.isInvite() {
		return
	}
	t.mu.Lock()
	if t.state == TxStateCompleted {
		t.setState(TxStateConfirmed)
		t.mu.Unlock()
		t.m.schedule(t.m.config().T1*4, t.finish)
		return
	}
	t.mu.Unlock()
}

func (t *ServerTx) Respond(resp *Response) error {
	if resp.StatusCode < 100 || resp.StatusCode > 699 {
		return ErrInvalidResponse
	}
	cseq := t.req.CSeq()
	if cseq != nil {
		resp.Headers().Set(&CSeq{Seq: cseq.Seq, Method: cseq.Method})
	}
	if via := t.req.Via(); via != nil {
		resp.Headers().Add(via.Clone())
	}
	if f := t.req.Headers().Get("From"); f != nil && resp.Headers().Get("From") == nil {
		resp.Headers().Add(f.Clone())
	}
	if to := t.req.Headers().Get("To"); to != nil && resp.Headers().Get("To") == nil {
		resp.Headers().Add(to.Clone())
	}
	if resp.Headers().Get("Call-ID") == nil {
		resp.Headers().Set(NewHeader("Call-ID", t.req.CallID()))
	}
	if len(resp.Headers().All("Record-Route")) == 0 {
		for _, rr := range t.req.Headers().All("Record-Route") {
			resp.Headers().Add(rr.Clone())
		}
	}
	t.mu.Lock()
	switch {
	case resp.StatusCode < 200:
		if t.state == TxStateCompleted || t.state == TxStateConfirmed || t.state == TxStateTerminated {
			t.mu.Unlock()
			return ErrTxTerminated
		}
		t.setState(TxStateProceeding)
		t.mu.Unlock()
		return t.m.send(resp, t.src)
	case t.final != nil:
		t.mu.Unlock()
		return nil
	}
	t.final = resp
	if t.isInvite() {
		t.setState(TxStateCompleted)
		t.mu.Unlock()
		if err := t.m.send(resp, t.src); err != nil {
			return err
		}
		t.startFinalRetransmit()
		t.m.schedule(t.m.config().TimerJ, t.finish)
		return nil
	}
	t.setState(TxStateCompleted)
	t.mu.Unlock()
	err := t.m.send(resp, t.src)
	t.m.schedule(t.m.config().TimerJ, t.finish)
	return err
}

func (t *ServerTx) startFinalRetransmit() {
	interval := t.m.config().T1
	go func() {
		for {
			select {
			case <-t.stop:
				return
			case <-time.After(interval):
			}
			t.mu.Lock()
			if t.state != TxStateCompleted {
				t.mu.Unlock()
				return
			}
			final := t.final
			t.mu.Unlock()
			if final == nil {
				return
			}
			_ = t.m.send(final, t.src)
			interval *= 2
			if interval > t.m.config().T2 {
				interval = t.m.config().T2
			}
		}
	}()
}

func (t *ServerTx) finish() {
	t.stopOnce.Do(func() { close(t.stop) })
	t.m.remove(t.key)
	select {
	case <-t.terminated:
	default:
		close(t.terminated)
	}
}

func (m *TxManager) schedule(d time.Duration, fn func()) {
	if d <= 0 {
		go fn()
		return
	}
	time.AfterFunc(d, fn)
}

func FormatPort(p int) string { return strconv.Itoa(p) }
