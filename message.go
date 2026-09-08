package sip

import (
	"fmt"
	"strconv"
)

const SipVersion = "SIP/2.0"

type Method string

const (
	INVITE    Method = "INVITE"
	ACK       Method = "ACK"
	BYE       Method = "BYE"
	CANCEL    Method = "CANCEL"
	OPTIONS   Method = "OPTIONS"
	REGISTER  Method = "REGISTER"
	INFO      Method = "INFO"
	UPDATE    Method = "UPDATE"
	PRACK     Method = "PRACK"
	REFER     Method = "REFER"
	NOTIFY    Method = "NOTIFY"
	SUBSCRIBE Method = "SUBSCRIBE"
	MESSAGE   Method = "MESSAGE"
	PUBLISH   Method = "PUBLISH"
)

type Message interface {
	IsRequest() bool
	StartLine() string
	Headers() *Headers
	Body() []byte
	SetBody(contentType string, body []byte)
	Clone() Message
	String() string
}

type Request struct {
	Method  Method
	Uri     *Uri
	Proto   string
	headers Headers
	body    []byte
}

type Response struct {
	StatusCode int
	Reason     string
	Proto      string
	headers    Headers
	body       []byte
}

func NewRequest(method Method, uri *Uri) *Request {
	return &Request{Method: method, Uri: uri, Proto: SipVersion}
}

func NewResponse(status int, reason string) *Response {
	if reason == "" {
		reason = DefaultReason(status)
	}
	return &Response{StatusCode: status, Reason: reason, Proto: SipVersion}
}

func DefaultReason(code int) string {
	switch code {
	case 100:
		return "Trying"
	case 180:
		return "Ringing"
	case 183:
		return "Session Progress"
	case 200:
		return "OK"
	case 202:
		return "Accepted"
	case 301:
		return "Moved Permanently"
	case 302:
		return "Moved Temporarily"
	case 400:
		return "Bad Request"
	case 401:
		return "Unauthorized"
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	case 407:
		return "Proxy Authentication Required"
	case 408:
		return "Request Timeout"
	case 415:
		return "Unsupported Media Type"
	case 420:
		return "Bad Extension"
	case 421:
		return "Extension Required"
	case 423:
		return "Interval Too Brief"
	case 480:
		return "Temporarily Unavailable"
	case 481:
		return "Call/Transaction Does Not Exist"
	case 483:
		return "Too Many Hops"
	case 486:
		return "Busy Here"
	case 487:
		return "Request Terminated"
	case 488:
		return "Not Acceptable Here"
	case 500:
		return "Server Internal Error"
	case 501:
		return "Not Implemented"
	case 502:
		return "Bad Gateway"
	case 503:
		return "Service Unavailable"
	case 504:
		return "Server Time-out"
	case 600:
		return "Busy Everywhere"
	case 603:
		return "Decline"
	case 604:
		return "Does Not Exist Anywhere"
	}
	switch {
	case code < 200:
		return "Provisional"
	case code < 300:
		return "Success"
	case code < 400:
		return "Redirection"
	case code < 500:
		return "Client Error"
	case code < 600:
		return "Server Error"
	default:
		return "Global Failure"
	}
}

func (r *Request) IsRequest() bool  { return true }
func (r *Response) IsRequest() bool { return false }

func (r *Request) StartLine() string {
	return string(r.Method) + " " + r.Uri.String() + " " + r.Proto
}

func (r *Response) StartLine() string {
	return r.Proto + " " + strconv.Itoa(r.StatusCode) + " " + r.Reason
}

func (r *Request) Headers() *Headers  { return &r.headers }
func (r *Response) Headers() *Headers { return &r.headers }

func (r *Request) Body() []byte  { return r.body }
func (r *Response) Body() []byte { return r.body }

func (r *Request) SetBody(contentType string, body []byte) {
	r.body = body
	if body == nil {
		r.headers.Del("Content-Length")
		r.headers.Del("Content-Type")
		return
	}
	r.headers.Set(ContentLength(len(body)))
	if contentType != "" {
		r.headers.Set(NewHeader("Content-Type", contentType))
	}
}

func (r *Response) SetBody(contentType string, body []byte) {
	r.body = body
	if body == nil {
		r.headers.Del("Content-Length")
		r.headers.Del("Content-Type")
		return
	}
	r.headers.Set(ContentLength(len(body)))
	if contentType != "" {
		r.headers.Set(NewHeader("Content-Type", contentType))
	}
}

func (r *Request) Clone() Message {
	n := *r
	n.Uri = r.Uri.Clone()
	n.headers = *r.headers.Clone()
	n.body = append([]byte(nil), r.body...)
	return &n
}

func (r *Response) Clone() Message {
	n := *r
	n.headers = *r.headers.Clone()
	n.body = append([]byte(nil), r.body...)
	return &n
}

func (r *Request) String() string  { return render(r) }
func (r *Response) String() string { return render(r) }

func render(m Message) string {
	var b []byte
	b = append(b, m.StartLine()...)
	b = append(b, '\r', '\n')
	for _, h := range m.Headers().list {
		b = append(b, h.Name()...)
		b = append(b, ':', ' ')
		b = append(b, h.Value()...)
		b = append(b, '\r', '\n')
	}
	if len(m.Body()) > 0 {
		if m.Headers().Get("Content-Length") == nil {
			b = append(b, "Content-Length: "...)
			b = append(b, strconv.Itoa(len(m.Body()))...)
			b = append(b, '\r', '\n')
		}
		b = append(b, '\r', '\n')
		b = append(b, m.Body()...)
	} else {
		b = append(b, '\r', '\n')
	}
	return string(b)
}

func (r *Request) Via() *Via {
	h := r.headers.Get("Via")
	if v, ok := h.(*Via); ok {
		return v
	}
	if h != nil {
		if v, err := ParseVia(h.Value()); err == nil {
			return v
		}
	}
	return nil
}

func (r *Request) From() *Address {
	return addressOf(r.headers.Get("From"))
}

func (r *Request) To() *Address {
	return addressOf(r.headers.Get("To"))
}

func (r *Request) Contact() *NameAddrList {
	return nameAddrListOf(r.headers.Get("Contact"))
}

func (r *Response) Via() *Via {
	h := r.headers.Get("Via")
	if v, ok := h.(*Via); ok {
		return v
	}
	if h != nil {
		if v, err := ParseVia(h.Value()); err == nil {
			return v
		}
	}
	return nil
}

func (r *Response) From() *Address {
	return addressOf(r.headers.Get("From"))
}

func (r *Response) To() *Address {
	return addressOf(r.headers.Get("To"))
}

func (r *Response) Contact() *NameAddrList {
	return nameAddrListOf(r.headers.Get("Contact"))
}

func addressOf(h Header) *Address {
	switch v := h.(type) {
	case *AddrHeader:
		return v.A
	case *NameAddrList:
		return v.First()
	case *GenericHeader:
		a, err := ParseAddress(v.V)
		if err != nil {
			return nil
		}
		return a
	}
	return nil
}

func nameAddrListOf(h Header) *NameAddrList {
	switch v := h.(type) {
	case *NameAddrList:
		return v
	case *AddrHeader:
		return &NameAddrList{Addresses: []*Address{v.A}}
	case *GenericHeader:
		l, err := ParseNameAddrList(v.V)
		if err != nil {
			return nil
		}
		return l
	}
	return nil
}

func (r *Request) CallID() string {
	return headerValue(r.headers.Get("Call-ID"))
}

func (r *Request) CSeq() *CSeq {
	return cseqOf(r.headers.Get("CSeq"))
}

func (r *Response) CallID() string {
	return headerValue(r.headers.Get("Call-ID"))
}

func (r *Response) CSeq() *CSeq {
	return cseqOf(r.headers.Get("CSeq"))
}

func headerValue(h Header) string {
	if h == nil {
		return ""
	}
	return h.Value()
}

func cseqOf(h Header) *CSeq {
	switch v := h.(type) {
	case *CSeq:
		return v
	case *GenericHeader:
		c, err := ParseCSeq(v.V)
		if err != nil {
			return nil
		}
		return c
	}
	return nil
}

// Required headers validation (RFC 3261 8.1.1)

func (r *Request) Validate() error {
	if r.Method == "" {
		return fmt.Errorf("%w: empty method", ErrParse)
	}
	if r.Uri == nil || r.Uri.Host == "" {
		return fmt.Errorf("%w: bad request uri", ErrParse)
	}
	for _, e := range []struct {
		h Header
		d error
	}{
		{r.headers.Get("Via"), ErrNoVia},
		{r.headers.Get("From"), ErrNoFrom},
		{r.headers.Get("To"), ErrNoTo},
		{r.headers.Get("Call-ID"), ErrNoCallID},
		{r.headers.Get("CSeq"), ErrNoCSeq},
	} {
		if e.h == nil {
			return e.d
		}
	}
	return nil
}

func (r *Response) Validate() error {
	if r.StatusCode < 100 || r.StatusCode > 699 {
		return fmt.Errorf("%w: bad status code %d", ErrParse, r.StatusCode)
	}
	for _, e := range []struct {
		h Header
		d error
	}{
		{r.headers.Get("Via"), ErrNoVia},
		{r.headers.Get("From"), ErrNoFrom},
		{r.headers.Get("To"), ErrNoTo},
		{r.headers.Get("Call-ID"), ErrNoCallID},
		{r.headers.Get("CSeq"), ErrNoCSeq},
	} {
		if e.h == nil {
			return e.d
		}
	}
	return nil
}
