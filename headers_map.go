package sip

import (
	"strings"
)

type Headers struct {
	list []Header
}

func (h *Headers) Add(hdr Header) {
	h.list = append(h.list, hdr)
}

func (h *Headers) Set(hdr Header) {
	name := CanonicalName(hdr.Name())
	for i := range h.list {
		if CanonicalName(h.list[i].Name()) == name {
			h.list[i] = hdr
			for j := i + 1; j < len(h.list); j++ {
				if CanonicalName(h.list[j].Name()) == name {
					h.list = append(h.list[:j], h.list[j+1:]...)
					j--
				}
			}
			return
		}
	}
	h.list = append(h.list, hdr)
}

func (h *Headers) Get(name string) Header {
	cn := CanonicalName(name)
	for _, hdr := range h.list {
		if CanonicalName(hdr.Name()) == cn {
			return hdr
		}
	}
	return nil
}

func (h *Headers) All(name string) []Header {
	cn := CanonicalName(name)
	var out []Header
	for _, hdr := range h.list {
		if CanonicalName(hdr.Name()) == cn {
			out = append(out, hdr)
		}
	}
	return out
}

func (h *Headers) Del(name string) {
	cn := CanonicalName(name)
	out := h.list[:0]
	for _, hdr := range h.list {
		if CanonicalName(hdr.Name()) != cn {
			out = append(out, hdr)
		}
	}
	h.list = out
}

func (h *Headers) Len() int {
	return len(h.list)
}

func (h *Headers) Clone() *Headers {
	n := &Headers{list: make([]Header, len(h.list))}
	for i, hdr := range h.list {
		n.list[i] = hdr.Clone()
	}
	return n
}

func (h *Headers) String() string {
	var b strings.Builder
	for _, hdr := range h.list {
		b.WriteString(hdr.Name())
		b.WriteString(": ")
		b.WriteString(hdr.Value())
		b.WriteString("\r\n")
	}
	return b.String()
}

func (h *Headers) Values(name string) []string {
	cn := CanonicalName(name)
	var out []string
	for _, hdr := range h.list {
		if CanonicalName(hdr.Name()) == cn {
			out = append(out, hdr.Value())
		}
	}
	return out
}
