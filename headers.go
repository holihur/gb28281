package sip

import (
	"fmt"
	"strconv"
	"strings"
)

type Header interface {
	Name() string
	Value() string
	Clone() Header
}

type GenericHeader struct {
	K string
	V string
}

func NewHeader(name, value string) *GenericHeader {
	return &GenericHeader{K: name, V: value}
}

func (h *GenericHeader) Name() string  { return h.K }
func (h *GenericHeader) Value() string { return h.V }
func (h *GenericHeader) Clone() Header { return &GenericHeader{K: h.K, V: h.V} }

var shortToLong = map[string]string{
	"i":                   "Call-ID",
	"f":                   "From",
	"t":                   "To",
	"v":                   "Via",
	"m":                   "Contact",
	"c":                   "Content-Type",
	"l":                   "Content-Length",
	"k":                   "Supported",
	"s":                   "Subject",
	"r":                   "Refer-To",
	"u":                   "Allow-Events",
	"e":                   "Content-Encoding",
	"j":                   "Reject-Contact",
	"d":                   "Request-Disposition",
	"a":                   "Accept-Contact",
	"x":                   "Session-Expires",
	"y":                   "Identity",
	"n":                   "Identity-Info",
	"o":                   "Event",
	"b":                   "Referred-By",
	"q":                   "Target-Dialog",
	"cseq":                "CSeq",
	"call-id":             "Call-ID",
	"www-authenticate":    "WWW-Authenticate",
	"proxy-authenticate":  "Proxy-Authenticate",
	"proxy-authorization": "Proxy-Authorization",
	"p-asserted-identity": "P-Asserted-Identity",
	"refer-to":            "Refer-To",
	"referred-by":         "Referred-By",
	"accept-contact":      "Accept-Contact",
	"session-expires":     "Session-Expires",
	"min-se":              "Min-SE",
	"allow-events":        "Allow-Events",
	"content-length":      "Content-Length",
	"content-type":        "Content-Type",
	"max-forwards":        "Max-Forwards",
	"record-route":        "Record-Route",
	"accept-encoding":     "Accept-Encoding",
	"accept-language":     "Accept-Language",
	"retry-after":         "Retry-After",
	"in-reply-to":         "In-Reply-To",
	"user-agent":          "User-Agent",
	"reject-contact":      "Reject-Contact",
	"request-disposition": "Request-Disposition",
	"identity-info":       "Identity-Info",
	"target-dialog":       "Target-Dialog",
}

func CanonicalName(name string) string {
	name = strings.TrimSpace(name)
	if long, ok := shortToLong[strings.ToLower(name)]; ok {
		return long
	}
	parts := strings.Split(name, "-")
	for i, p := range parts {
		if p != "" {
			parts[i] = strings.ToUpper(p[:1]) + strings.ToLower(p[1:])
		}
	}
	return strings.Join(parts, "-")
}

// Via

type Via struct {
	Proto     string
	Transport string
	Host      string
	Port      int
	Params    *Params
}

func ParseVia(s string) (*Via, error) {
	s = strings.TrimSpace(s)
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c == 0x7f {
			return nil, fmt.Errorf("%w: control character in via", ErrParse)
		}
	}
	parts := strings.SplitN(s, " ", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("%w: bad via %q", ErrParse, s)
	}
	proto := strings.TrimSpace(parts[0])
	rest := strings.TrimSpace(parts[1])
	if i := strings.IndexByte(rest, ';'); i >= 0 {
		params, err := ParseParams(rest[i:])
		if err != nil {
			return nil, err
		}
		rest = rest[:i]
		v := &Via{Proto: proto, Params: params}
		if err := v.parseHostPort(strings.TrimSpace(rest)); err != nil {
			return nil, err
		}
		return v, nil
	}
	v := &Via{Proto: proto}
	if err := v.parseHostPort(rest); err != nil {
		return nil, err
	}
	return v, nil
}

func (v *Via) parseHostPort(s string) error {
	if strings.HasPrefix(s, "[") {
		end := strings.IndexByte(s, ']')
		if end < 0 {
			return fmt.Errorf("%w: bad via host %q", ErrParse, s)
		}
		v.Host = s[:end+1]
		if len(s) > end+1 && s[end+1] == ':' {
			p, err := strconv.Atoi(s[end+2:])
			if err != nil {
				return fmt.Errorf("%w: bad via port %q", ErrParse, s)
			}
			v.Port = p
		}
	} else if i := strings.LastIndexByte(s, ':'); i >= 0 {
		p, err := strconv.Atoi(s[i+1:])
		if err != nil {
			return fmt.Errorf("%w: bad via port %q", ErrParse, s)
		}
		v.Port = p
		v.Host = s[:i]
	} else {
		v.Host = s
	}
	if i := strings.LastIndex(v.Proto, "/"); i >= 0 {
		v.Transport = v.Proto[i+1:]
	} else {
		v.Transport = v.Proto
	}
	return nil
}

func (v *Via) Branch() string {
	if v.Params == nil {
		return ""
	}
	b, _ := v.Params.Get("branch")
	return b
}

func (v *Via) SetBranch(branch string) {
	if v.Params == nil {
		v.Params = NewParams()
	}
	v.Params.Set("branch", branch)
}

func (v *Via) Name() string { return "Via" }
func (v *Via) Value() string {
	var b strings.Builder
	b.WriteString(v.Proto)
	b.WriteByte(' ')
	b.WriteString(v.Host)
	if v.Port > 0 {
		b.WriteByte(':')
		b.WriteString(strconv.Itoa(v.Port))
	}
	b.WriteString(v.Params.String())
	return b.String()
}
func (v *Via) Clone() Header {
	n := *v
	n.Params = v.Params.Clone()
	return &n
}

// Address (From/To/Contact/Route display form)

type Address struct {
	DisplayName string
	Quoted      bool
	Uri         *Uri
	Params      *Params
}

func ParseAddress(s string) (*Address, error) {
	s = strings.TrimSpace(s)
	a := &Address{}
	uriStart := strings.IndexByte(s, '<')
	if uriStart >= 0 {
		raw := strings.TrimSpace(s[:uriStart])
		a.DisplayName = unquote(raw)
		a.Quoted = raw != a.DisplayName
		end := strings.LastIndexByte(s, '>')
		if end < 0 || end <= uriStart {
			return nil, fmt.Errorf("%w: unterminated < in %q", ErrBadAddress, s)
		}
		uri := s[uriStart+1 : end]
		var err error
		if a.Uri, err = ParseUri(uri); err != nil {
			return nil, err
		}
		if rest := strings.TrimSpace(s[end+1:]); rest != "" {
			if a.Params, err = ParseParams(rest); err != nil {
				return nil, err
			}
		}
		return a, nil
	}
	u, err := ParseUri(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadAddress, err)
	}
	a.Uri = u
	return a, nil
}

func (a *Address) Tag() string {
	if a == nil || a.Params == nil {
		return ""
	}
	t, _ := a.Params.Get("tag")
	return t
}

func (a *Address) SetTag(tag string) {
	if a.Params == nil {
		a.Params = NewParams()
	}
	a.Params.Set("tag", tag)
}

func (a *Address) Clone() *Address {
	if a == nil {
		return nil
	}
	n := *a
	n.Uri = a.Uri.Clone()
	n.Params = a.Params.Clone()
	return &n
}

func (a *Address) String() string {
	var b strings.Builder
	if a.DisplayName != "" {
		if a.Quoted || strings.ContainsAny(a.DisplayName, ",;\" ") {
			b.WriteString(`"` + strings.ReplaceAll(a.DisplayName, `"`, `\"`) + `"`)
		} else {
			b.WriteString(a.DisplayName)
		}
		b.WriteByte(' ')
	}
	b.WriteByte('<')
	b.WriteString(a.Uri.String())
	b.WriteByte('>')
	b.WriteString(a.Params.String())
	return b.String()
}

func ParseFrom(s string) (*Address, error)    { return ParseAddress(s) }
func ParseTo(s string) (*Address, error)      { return ParseAddress(s) }
func ParseContact(s string) (*Address, error) { return ParseAddress(s) }

// CSeq

type CSeq struct {
	Seq    uint32
	Method Method
}

func ParseCSeq(s string) (*CSeq, error) {
	fields := strings.Fields(s)
	if len(fields) != 2 {
		return nil, fmt.Errorf("%w: bad cseq %q", ErrParse, s)
	}
	seq, err := strconv.ParseUint(fields[0], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("%w: bad cseq %q", ErrParse, s)
	}
	return &CSeq{Seq: uint32(seq), Method: Method(strings.ToUpper(fields[1]))}, nil
}

func (c *CSeq) Name() string  { return "CSeq" }
func (c *CSeq) Value() string { return strconv.FormatUint(uint64(c.Seq), 10) + " " + string(c.Method) }
func (c *CSeq) Clone() Header { n := *c; return &n }

// ContentLength

type ContentLength uint32

func (c ContentLength) Name() string  { return "Content-Length" }
func (c ContentLength) Value() string { return strconv.FormatUint(uint64(c), 10) }
func (c ContentLength) Clone() Header { return c }

func ParseContentLength(s string) (ContentLength, error) {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%w: bad content-length %q", ErrParse, s)
	}
	return ContentLength(n), nil
}

// MaxForwards

type MaxForwards int

func (m MaxForwards) Name() string  { return "Max-Forwards" }
func (m MaxForwards) Value() string { return strconv.Itoa(int(m)) }
func (m MaxForwards) Clone() Header { return m }

// NameAddrList (Contact/Route sets)

type NameAddrList struct {
	HName     string
	Addresses []*Address
	All       bool // "*" for wildcard contact
}

func ParseNameAddrList(s string) (*NameAddrList, error) {
	s = strings.TrimSpace(s)
	if s == "*" {
		return &NameAddrList{All: true}, nil
	}
	l := &NameAddrList{}
	for _, part := range splitAddrList(s) {
		a, err := ParseAddress(part)
		if err != nil {
			return nil, err
		}
		l.Addresses = append(l.Addresses, a)
	}
	if len(l.Addresses) == 0 {
		return nil, fmt.Errorf("%w: empty address list", ErrBadAddress)
	}
	return l, nil
}

func splitAddrList(s string) []string {
	var out []string
	depth := 0
	inQuote := false
	escaped := false
	start := 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case escaped:
			escaped = false
		case c == '\\' && inQuote:
			escaped = true
		case c == '"':
			inQuote = !inQuote
		case !inQuote && c == '<':
			depth++
		case !inQuote && c == '>':
			depth--
		case !inQuote && depth == 0 && c == ',':
			out = append(out, strings.TrimSpace(s[start:i]))
			start = i + 1
		}
	}
	out = append(out, strings.TrimSpace(s[start:]))
	return out
}

func (l *NameAddrList) Name() string { return l.HName }
func (l *NameAddrList) Value() string {
	parts := make([]string, len(l.Addresses))
	for i, a := range l.Addresses {
		parts[i] = a.String()
	}
	return strings.Join(parts, ", ")
}
func (l *NameAddrList) Clone() Header {
	n := &NameAddrList{All: l.All, HName: l.HName}
	for _, a := range l.Addresses {
		n.Addresses = append(n.Addresses, a.Clone())
	}
	return n
}

func (l *NameAddrList) First() *Address {
	if l == nil || len(l.Addresses) == 0 {
		return nil
	}
	return l.Addresses[0]
}

// TokenList: Route, Record-Route are lists of addresses; Allow, Supported are token lists

type TokenList struct {
	HName  string
	Tokens []string
}

func ParseTokenList(name, s string) *TokenList {
	t := &TokenList{HName: name}
	for _, tok := range strings.Split(s, ",") {
		tok = strings.TrimSpace(tok)
		if tok != "" {
			t.Tokens = append(t.Tokens, tok)
		}
	}
	return t
}

func (t *TokenList) Name() string  { return t.HName }
func (t *TokenList) Value() string { return strings.Join(t.Tokens, ", ") }
func (t *TokenList) Has(tok string) bool {
	for _, x := range t.Tokens {
		if strings.EqualFold(x, tok) {
			return true
		}
	}
	return false
}
func (t *TokenList) Clone() Header {
	n := *t
	n.Tokens = append([]string(nil), t.Tokens...)
	return &n
}

// Auth challenge/response

type Auth struct {
	Scheme    string
	Username  string
	Realm     string
	Nonce     string
	URI       string
	Response  string
	Cnonce    string
	Nc        string
	Qop       string
	Algorithm string
	Opaque    string
	Other     *Params
}

func ParseAuth(s string) (*Auth, error) {
	s = strings.TrimSpace(s)
	i := strings.IndexAny(s, " \t,")
	if i < 0 {
		return &Auth{Scheme: s}, nil
	}
	a := &Auth{Scheme: s[:i], Other: NewParams()}
	for _, part := range splitAuthParams(s[i+1:]) {
		k, v, found := strings.Cut(part, "=")
		if !found {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = unquote(strings.TrimSpace(v))
		switch k {
		case "username":
			a.Username = v
		case "realm":
			a.Realm = v
		case "nonce":
			a.Nonce = v
		case "uri":
			a.URI = v
		case "response":
			a.Response = v
		case "cnonce":
			a.Cnonce = v
		case "nc":
			a.Nc = v
		case "qop":
			a.Qop = v
		case "algorithm":
			a.Algorithm = v
		case "opaque":
			a.Opaque = v
		default:
			a.Other.Set(k, v)
		}
	}
	return a, nil
}

func splitAuthParams(s string) []string {
	var out []string
	inQuote := false
	escaped := false
	start := 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case escaped:
			escaped = false
		case c == '\\' && inQuote:
			escaped = true
		case c == '"':
			inQuote = !inQuote
		case (c == ',' || c == ' ' || c == '\t') && !inQuote:
			if i > start {
				out = append(out, strings.TrimSpace(s[start:i]))
			}
			start = i + 1
		}
	}
	out = append(out, strings.TrimSpace(s[start:]))
	return out
}

func (a *Auth) Name() string { return "" }
func (a *Auth) Value() string {
	var b strings.Builder
	b.WriteString(a.Scheme)
	writeAuth := func(k, v string) {
		if v == "" {
			return
		}
		b.WriteString(", ")
		b.WriteString(k)
		b.WriteString(`="`)
		b.WriteString(v)
		b.WriteString(`"`)
	}
	writeAuth("username", a.Username)
	writeAuth("realm", a.Realm)
	writeAuth("nonce", a.Nonce)
	if a.URI != "" {
		b.WriteString(", uri=")
		b.WriteString(a.URI)
	}
	writeAuth("response", a.Response)
	writeAuth("cnonce", a.Cnonce)
	if a.Nc != "" {
		b.WriteString(", nc=" + a.Nc)
	}
	if a.Qop != "" {
		b.WriteString(", qop=" + a.Qop)
	}
	if a.Algorithm != "" {
		b.WriteString(", algorithm=" + a.Algorithm)
	}
	writeAuth("opaque", a.Opaque)
	return b.String()
}
func (a *Auth) Clone() Header {
	n := *a
	n.Other = a.Other.Clone()
	return &n
}
