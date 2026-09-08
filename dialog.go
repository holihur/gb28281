package sip

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

type DialogState int

const (
	DialogEarly DialogState = iota
	DialogConfirmed
	DialogTerminated
)

func (s DialogState) String() string {
	switch s {
	case DialogEarly:
		return "early"
	case DialogConfirmed:
		return "confirmed"
	case DialogTerminated:
		return "terminated"
	}
	return "unknown"
}

type Dialog struct {
	mu           sync.Mutex
	CallID       string
	LocalTag     string
	RemoteTag    string
	Local        *Address
	Remote       *Address
	RemoteTarget *Uri
	RouteSet     []*Uri
	State        DialogState
	LocalSeq     uint32
	RemoteSeq    uint32
	Secure       bool
}

func NewTag() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func (d *Dialog) ID() string {
	return d.CallID + ";" + d.LocalTag + ";" + d.RemoteTag
}

func (d *Dialog) GetState() DialogState {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.State
}

func (d *Dialog) SetState(s DialogState) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.State = s
}

func (d *Dialog) NextLocalSeq() uint32 {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.LocalSeq++
	return d.LocalSeq
}

func (d *Dialog) CreateRequest(method Method, contentType string, body []byte) (*Request, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.State == DialogTerminated {
		return nil, ErrDialogNotFound
	}
	uri := d.RemoteTarget
	if uri == nil {
		if d.Remote != nil {
			uri = d.Remote.Uri
		} else {
			return nil, ErrDialogNotFound
		}
	}
	req := NewRequest(method, uri.Clone())
	req.Headers().Set(NewHeader("Call-ID", d.CallID))
	from := d.Local.Clone()
	if from.Params == nil {
		from.Params = NewParams()
	}
	from.Params.Del("tag")
	from.Params.Set("tag", d.LocalTag)
	req.Headers().Set(fromHeader(from))
	to := d.Remote.Clone()
	if to.Params == nil {
		to.Params = NewParams()
	}
	if d.RemoteTag != "" {
		to.Params.Set("tag", d.RemoteTag)
	}
	req.Headers().Set(toHeader(to))
	d.LocalSeq++
	req.Headers().Set(&CSeq{Seq: d.LocalSeq, Method: method})
	req.Headers().Set(MaxForwards(70))
	for i := len(d.RouteSet) - 1; i >= 0; i-- {
		req.Headers().Add(NewHeader("Route", d.RouteSet[i].String()))
	}
	req.SetBody(contentType, body)
	return req, nil
}

func fromHeader(a *Address) Header { return &AddrHeader{A: a, K: "From"} }
func toHeader(a *Address) Header   { return &AddrHeader{A: a, K: "To"} }

type AddrHeader struct {
	A *Address
	K string
}

func (h *AddrHeader) Name() string  { return h.K }
func (h *AddrHeader) Value() string { return h.A.String() }
func (h *AddrHeader) Clone() Header { return &AddrHeader{A: h.A.Clone(), K: h.K} }

// updateFromResponse mutates a UAC dialog per an in-dialog response.
func (d *Dialog) updateFromResponse(resp *Response) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if to := resp.Headers().Get("To"); to != nil {
		if a := addressOf(to); a != nil && a.Tag() != "" {
			d.RemoteTag = a.Tag()
		}
	}
	if contact := resp.Contact(); contact != nil {
		if c := contact.First(); c != nil {
			d.RemoteTarget = c.Uri.Clone()
		}
	}
	d.RouteSet = recordRouteSet(resp)
}

func recordRouteSet(m Message) []*Uri {
	var set []*Uri
	for _, h := range m.Headers().All("Record-Route") {
		l := nameAddrListOf(h)
		if l == nil {
			continue
		}
		for _, a := range l.Addresses {
			set = append(set, a.Uri.Clone())
		}
	}
	return set
}

func (d *Dialog) getRemoteSeq() uint32 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.RemoteSeq
}

func (d *Dialog) updateFromRequest(req *Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if cseq := req.CSeq(); cseq != nil {
		if cseq.Seq > d.RemoteSeq {
			d.RemoteSeq = cseq.Seq
		}
	}
}

func (d *Dialog) Terminate() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.State = DialogTerminated
}

type DialogManager struct {
	mu      sync.Mutex
	dialogs map[string]*Dialog
}

func NewDialogManager() *DialogManager {
	return &DialogManager{dialogs: make(map[string]*Dialog)}
}

func (dm *DialogManager) Add(d *Dialog) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	dm.dialogs[d.ID()] = d
}

func (dm *DialogManager) Get(callID, localTag, remoteTag string) *Dialog {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	if d, ok := dm.dialogs[callID+";"+localTag+";"+remoteTag]; ok {
		return d
	}
	return nil
}

func (dm *DialogManager) Remove(d *Dialog) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	delete(dm.dialogs, d.ID())
}

func (dm *DialogManager) Len() int {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	return len(dm.dialogs)
}

// NewClientDialog builds the UAC side of a dialog for an outgoing initial request.
func NewClientDialog(callID, localTag, remoteTag string, from, to *Address, seq uint32) *Dialog {
	return &Dialog{
		CallID:    callID,
		LocalTag:  localTag,
		RemoteTag: remoteTag,
		Local:     from.Clone(),
		Remote:    to.Clone(),
		LocalSeq:  seq,
		State:     DialogEarly,
	}
}

// NewServerDialog builds the UAS side of a dialog from an incoming request and
// the locally chosen to-tag.
func NewServerDialog(req *Request, localTag string) *Dialog {
	from := req.From()
	to := req.To()
	d := &Dialog{
		CallID:    req.CallID(),
		LocalTag:  localTag,
		Local:     to.Clone(),
		Remote:    from.Clone(),
		RemoteTag: from.Tag(),
		State:     DialogEarly,
	}
	if cseq := req.CSeq(); cseq != nil {
		d.RemoteSeq = cseq.Seq
	}
	d.RemoteTarget = req.Uri.Clone()
	d.RouteSet = recordRouteSet(req)
	return d
}
