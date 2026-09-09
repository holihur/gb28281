package sip

import (
	"fmt"
	"strings"
)

type Param struct {
	Key      string
	Value    string
	HasValue bool
}

type Params struct {
	items []Param
}

func NewParams() *Params {
	return &Params{}
}

func (p *Params) Len() int {
	if p == nil {
		return 0
	}
	return len(p.items)
}

func (p *Params) Set(key, value string) *Params {
	p.set(Param{Key: key, Value: value, HasValue: true})
	return p
}

func (p *Params) SetFlag(key string) *Params {
	p.set(Param{Key: key})
	return p
}

func (p *Params) set(param Param) {
	for i := range p.items {
		if strings.EqualFold(p.items[i].Key, param.Key) {
			p.items[i] = param
			return
		}
	}
	p.items = append(p.items, param)
}

func (p *Params) Get(key string) (string, bool) {
	if p == nil {
		return "", false
	}
	for _, it := range p.items {
		if strings.EqualFold(it.Key, key) {
			return it.Value, it.HasValue
		}
	}
	return "", false
}

func (p *Params) Has(key string) bool {
	if p == nil {
		return false
	}
	for _, it := range p.items {
		if strings.EqualFold(it.Key, key) {
			return true
		}
	}
	return false
}

func (p *Params) Del(key string) {
	if p == nil {
		return
	}
	for i := range p.items {
		if strings.EqualFold(p.items[i].Key, key) {
			p.items = append(p.items[:i], p.items[i+1:]...)
			return
		}
	}
}

func (p *Params) Keys() []string {
	if p == nil {
		return nil
	}
	keys := make([]string, 0, len(p.items))
	for _, it := range p.items {
		keys = append(keys, it.Key)
	}
	return keys
}

func (p *Params) Items() []Param {
	if p == nil {
		return nil
	}
	return p.items
}

func (p *Params) Clone() *Params {
	if p == nil {
		return nil
	}
	n := &Params{items: make([]Param, len(p.items))}
	copy(n.items, p.items)
	return n
}

func escapeParam(v string) string {
	if !strings.ContainsAny(v, "\";?,") {
		return sanitizeField(v)
	}
	q := strings.ReplaceAll(v, `"`, `\"`)
	return `"` + sanitizeField(q) + `"`
}

func (p *Params) String() string {
	if p == nil {
		return ""
	}
	var b strings.Builder
	for _, it := range p.items {
		b.WriteByte(';')
		b.WriteString(escapeParam(it.Key))
		if it.HasValue {
			b.WriteByte('=')
			b.WriteString(escapeParam(it.Value))
		}
	}
	return b.String()
}

func splitParamList(s string) []string {
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
		case c == ';' && !inQuote:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
		s = strings.ReplaceAll(s, `\"`, `"`)
	}
	return s
}

func ParseParams(s string) (*Params, error) {
	p := NewParams()
	s = strings.TrimPrefix(s, ";")
	if s == "" {
		return p, nil
	}
	for _, part := range splitParamList(s) {
		if part == "" {
			continue
		}
		k, v, found := strings.Cut(part, "=")
		k = strings.TrimSpace(k)
		if k == "" {
			return nil, fmt.Errorf("%w: empty param key in %q", ErrParse, s)
		}
		if strings.ContainsAny(k, "\";,?<>()@:\\[]") {
			return nil, fmt.Errorf("%w: invalid characters in param key %q", ErrParse, k)
		}
		if found {
			p.Set(strings.ToLower(k), unquote(strings.TrimSpace(v)))
		} else {
			p.SetFlag(strings.ToLower(k))
		}
	}
	return p, nil
}
