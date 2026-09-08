package sip

import (
	"testing"
)

func makeDialog() *Dialog {
	from, _ := ParseAddress(`"Alice" <sip:alice@atlanta.com>;tag=abc`)
	to, _ := ParseAddress(`<sip:bob@biloxi.com>`)
	return &Dialog{
		CallID:       "cid",
		LocalTag:     "abc",
		RemoteTag:    "xyz",
		Local:        from,
		Remote:       to,
		RemoteTarget: to.Uri.Clone(),
		LocalSeq:     100,
		State:        DialogConfirmed,
	}
}

func TestDialogID(t *testing.T) {
	d := makeDialog()
	if d.ID() != "cid;abc;xyz" {
		t.Fatal(d.ID())
	}
	if d.GetState() != DialogConfirmed {
		t.Fatal(d.GetState())
	}
	d.SetState(DialogTerminated)
	if d.GetState() != DialogTerminated {
		t.Fatal("set state")
	}
}

func TestDialogCreateRequest(t *testing.T) {
	d := makeDialog()
	req, err := d.CreateRequest(BYE, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if req.CallID() != "cid" {
		t.Fatal(req.CallID())
	}
	if req.From().Tag() != "abc" || req.To().Tag() != "xyz" {
		t.Fatal("tags")
	}
	cseq := req.CSeq()
	if cseq == nil || cseq.Seq != 101 {
		t.Fatal(cseq)
	}
	d.NextLocalSeq()
	req2, _ := d.CreateRequest(INFO, "text/plain", []byte("hello"))
	if req2.CSeq().Seq != 103 {
		t.Fatal(req2.CSeq().Seq)
	}
	if req2.Headers().Get("Content-Length") == nil {
		t.Fatal("body length")
	}
}

func TestDialogCreateRequestRouteSet(t *testing.T) {
	d := makeDialog()
	r1, _ := ParseUri("sip:proxy1.atlanta.com;lr")
	r2, _ := ParseUri("sip:proxy2.biloxi.com;lr")
	d.RouteSet = []*Uri{r1, r2}
	req, err := d.CreateRequest(BYE, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	routes := req.Headers().Values("Route")
	if len(routes) != 2 || routes[0] != "sip:proxy2.biloxi.com;lr" {
		t.Fatal(routes)
	}
}

func TestDialogTerminated(t *testing.T) {
	d := makeDialog()
	d.Terminate()
	if _, err := d.CreateRequest(BYE, "", nil); err != ErrDialogNotFound {
		t.Fatal(err)
	}
}

func TestDialogNoRemote(t *testing.T) {
	d := &Dialog{CallID: "x", LocalTag: "l", State: DialogEarly, Local: &Address{Uri: &Uri{Host: "a"}}}
	if _, err := d.CreateRequest(BYE, "", nil); err != ErrDialogNotFound {
		t.Fatal(err)
	}
}

func TestDialogUpdateFromResponse(t *testing.T) {
	d := makeDialog()
	d.RemoteTag = ""
	resp := NewResponse(200, "")
	resp.Headers().Set(NewHeader("To", `<sip:bob@biloxi.com>;tag=rrr`))
	resp.Headers().Set(NewHeader("Contact", "<sip:bob@client.biloxi.com>"))
	resp.Headers().Set(NewHeader("Record-Route", "<sip:p1.com;lr>, <sip:p2.com;lr>"))
	d.updateFromResponse(resp)
	if d.RemoteTag != "rrr" {
		t.Fatal(d.RemoteTag)
	}
	if d.RemoteTarget.Host != "client.biloxi.com" {
		t.Fatal(d.RemoteTarget)
	}
	if len(d.RouteSet) != 2 || d.RouteSet[0].Host != "p1.com" {
		t.Fatal(d.RouteSet)
	}
}

func TestDialogUpdateFromRequest(t *testing.T) {
	d := makeDialog()
	d.RemoteSeq = 5
	req := NewRequest(BYE, d.RemoteTarget)
	req.Headers().Set(NewHeader("CSeq", "10 BYE"))
	d.updateFromRequest(req)
	if d.RemoteSeq != 10 {
		t.Fatal(d.RemoteSeq)
	}
	d.updateFromRequest(NewRequest(INFO, d.RemoteTarget))
	if d.RemoteSeq != 10 {
		t.Fatal("seq should not decrease")
	}
}

func TestDialogManager(t *testing.T) {
	dm := NewDialogManager()
	if dm.Len() != 0 {
		t.Fatal("not empty")
	}
	d := makeDialog()
	dm.Add(d)
	if dm.Len() != 1 {
		t.Fatal("len")
	}
	if dm.Get(d.CallID, d.LocalTag, d.RemoteTag) != d {
		t.Fatal("get")
	}
	if dm.Get("nope", "", "") != nil {
		t.Fatal("bogus get")
	}
	dm.Remove(d)
	if dm.Len() != 0 {
		t.Fatal("remove")
	}
}

func TestDialogStates(t *testing.T) {
	if DialogEarly.String() != "early" || DialogConfirmed.String() != "confirmed" || DialogTerminated.String() != "terminated" || DialogState(9).String() != "unknown" {
		t.Fatal("state strings")
	}
}

func TestNewServerDialog(t *testing.T) {
	req := NewRequest(INVITE, &Uri{Scheme: "sip", User: "bob", Host: "biloxi.com"})
	req.Headers().Set(NewHeader("From", `<sip:alice@atlanta.com>;tag=fromtag`))
	req.Headers().Set(NewHeader("To", `<sip:bob@biloxi.com>`))
	req.Headers().Set(NewHeader("Call-ID", "sid"))
	req.Headers().Set(&CSeq{Seq: 7, Method: INVITE})
	req.Headers().Set(NewHeader("Record-Route", "<sip:rr.com;lr>"))
	d := NewServerDialog(req, "localtag")
	if d.LocalTag != "localtag" || d.RemoteTag != "fromtag" || d.RemoteSeq != 7 {
		t.Fatalf("%+v", d)
	}
	if d.RemoteTarget.Host != "biloxi.com" || len(d.RouteSet) != 1 {
		t.Fatal(d)
	}
	if d.Local.Tag() != "" || d.Remote.Uri.User != "alice" {
		t.Fatal("sides swapped")
	}
}

func TestNewTag(t *testing.T) {
	a, b := NewTag(), NewTag()
	if a == "" || a == b {
		t.Fatal("tags")
	}
}
