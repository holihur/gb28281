package sip

import (
	"fmt"
	"strconv"
	"strings"
)

type Uri struct {
	Scheme   string
	User     string
	Password string
	Host     string
	Port     int
	Params   *Params
	Headers  *Params
}

const (
	SchemeSIP  = "sip"
	SchemeSIPS = "sips"
	SchemeTel  = "tel"
)

func ParseUri(s string) (*Uri, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("%w: empty uri", ErrBadUri)
	}
	scheme, rest, found := strings.Cut(s, ":")
	if !found {
		return nil, fmt.Errorf("%w: missing scheme in %q", ErrBadUri, s)
	}
	switch strings.ToLower(scheme) {
	case SchemeSIP, SchemeSIPS, SchemeTel:
	default:
		return nil, fmt.Errorf("%w: unknown scheme %q", ErrBadUri, scheme)
	}
	u := &Uri{Scheme: strings.ToLower(scheme)}

	hostPart := rest
	params := ""
	headers := ""
	if i := strings.IndexAny(rest, ";?"); i >= 0 {
		hostPart = rest[:i]
		rest = rest[i:]
		if rest[0] == ';' {
			pi := strings.IndexByte(rest, '?')
			if pi >= 0 {
				params = rest[:pi]
				headers = rest[pi+1:]
			} else {
				params = rest
			}
		} else {
			headers = rest[1:]
		}
	}

	userinfo := ""
	if at := strings.LastIndex(hostPart, "@"); at >= 0 {
		userinfo = hostPart[:at]
		hostPart = hostPart[at+1:]
		if up := strings.IndexByte(userinfo, ':'); up >= 0 {
			u.User = userinfo[:up]
			u.Password = userinfo[up+1:]
		} else {
			u.User = userinfo
		}
	}
	if hostPart == "" {
		return nil, fmt.Errorf("%w: missing host in %q", ErrBadUri, s)
	}

	host := hostPart
	if strings.HasPrefix(host, "[") {
		end := strings.IndexByte(host, ']')
		if end < 0 {
			return nil, fmt.Errorf("%w: unterminated ipv6 in %q", ErrBadUri, s)
		}
		if len(host) > end+1 {
			if host[end+1] != ':' {
				return nil, fmt.Errorf("%w: bad port in %q", ErrBadUri, s)
			}
			port, err := strconv.Atoi(host[end+2:])
			if err != nil {
				return nil, fmt.Errorf("%w: bad port in %q", ErrBadUri, s)
			}
			u.Port = port
		}
		u.Host = host[:end+1]
	} else if i := strings.LastIndexByte(host, ':'); i >= 0 {
		port, err := strconv.Atoi(host[i+1:])
		if err != nil {
			return nil, fmt.Errorf("%w: bad port in %q", ErrBadUri, s)
		}
		u.Port = port
		u.Host = host[:i]
	} else {
		u.Host = host
	}
	if u.Host == "" {
		return nil, fmt.Errorf("%w: missing host in %q", ErrBadUri, s)
	}

	var err error
	if params != "" {
		if u.Params, err = ParseParams(params); err != nil {
			return nil, err
		}
	}
	if headers != "" {
		u.Headers = NewParams()
		for _, part := range strings.Split(headers, "&") {
			k, v, _ := strings.Cut(part, "=")
			if k != "" {
				u.Headers.Set(k, v)
			}
		}
	}
	return u, nil
}

func (u *Uri) IsEncrypted() bool {
	return u != nil && u.Scheme == SchemeSIPS
}

func (u *Uri) HostPort() string {
	if u == nil {
		return ""
	}
	if u.Port > 0 {
		return u.Host + ":" + strconv.Itoa(u.Port)
	}
	return u.Host
}

func (u *Uri) EffectivePort() int {
	if u == nil {
		return 0
	}
	if u.Port > 0 {
		return u.Port
	}
	if u.Scheme == SchemeSIPS {
		return 5061
	}
	return 5060
}

func (u *Uri) Clone() *Uri {
	if u == nil {
		return nil
	}
	n := *u
	n.Params = u.Params.Clone()
	n.Headers = u.Headers.Clone()
	return &n
}

func (u *Uri) Equal(o *Uri) bool {
	if u == nil || o == nil {
		return u == o
	}
	if u.Scheme != o.Scheme || !strings.EqualFold(u.User, o.User) ||
		!strings.EqualFold(u.Host, o.Host) || u.Port != o.Port {
		return false
	}
	return u.paramsEqual(o)
}

func (u *Uri) paramsEqual(o *Uri) bool {
	for _, k := range []string{"user", "transport", "lr", "method", "ttl", "maddr"} {
		a, aok := u.Params.Get(k)
		b, bok := o.Params.Get(k)
		if aok != bok || a != b {
			return false
		}
	}
	return true
}

func (u *Uri) String() string {
	if u == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString(u.Scheme)
	b.WriteByte(':')
	if u.User != "" {
		b.WriteString(u.User)
		if u.Password != "" {
			b.WriteByte(':')
			b.WriteString(u.Password)
		}
		b.WriteByte('@')
	}
	b.WriteString(u.Host)
	if u.Port > 0 {
		b.WriteByte(':')
		b.WriteString(strconv.Itoa(u.Port))
	}
	b.WriteString(u.Params.String())
	if u.Headers != nil && u.Headers.Len() > 0 {
		b.WriteByte('?')
		for i, it := range u.Headers.Items() {
			if i > 0 {
				b.WriteByte('&')
			}
			b.WriteString(it.Key)
			if it.HasValue {
				b.WriteByte('=')
				b.WriteString(it.Value)
			}
		}
	}
	return b.String()
}
