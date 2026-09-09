package sip

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Message size limits to prevent memory-exhaustion attacks.
const (
	MaxMessageSize   = 1 << 20 // 1 MiB: total message cap
	maxHeaderLines   = 128
	maxHeaderLineLen = 8192
	MaxBodySize      = 65536 // 64 KiB body cap
)

func ParseMessage(data []byte) (Message, error) {
	if len(data) < 8 {
		return nil, ErrShortMessage
	}
	if len(data) > MaxMessageSize {
		return nil, fmt.Errorf("%w: message too large: %d bytes", ErrParse, len(data))
	}
	reader := bufio.NewReader(bytes.NewReader(data))
	line, err := reader.ReadString('\n')
	if err != nil && line == "" {
		return nil, fmt.Errorf("%w: %v", ErrBadStartLine, err)
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return nil, ErrBadStartLine
	}
	if strings.HasPrefix(line, "SIP/") {
		return parseResponse(line, reader)
	}
	return parseRequest(line, reader)
}

func parseRequest(startLine string, reader *bufio.Reader) (Message, error) {
	fields := strings.Fields(startLine)
	if len(fields) != 3 {
		return nil, fmt.Errorf("%w: bad request line %q", ErrBadStartLine, startLine)
	}
	uri, err := ParseUri(fields[1])
	if err != nil {
		return nil, fmt.Errorf("%w: bad request uri: %v", ErrBadStartLine, err)
	}
	r := NewRequest(Method(strings.ToUpper(fields[0])), uri)
	r.Proto = fields[2]
	if err := parseHeaderBlock(reader, &r.headers, &r.body); err != nil {
		return nil, err
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

func parseResponse(startLine string, reader *bufio.Reader) (Message, error) {
	fields := strings.SplitN(startLine, " ", 3)
	if len(fields) < 2 {
		return nil, fmt.Errorf("%w: bad status line %q", ErrBadStartLine, startLine)
	}
	code, err := strconv.Atoi(fields[1])
	if err != nil {
		return nil, fmt.Errorf("%w: bad status code in %q", ErrBadStartLine, startLine)
	}
	reason := ""
	if len(fields) == 3 {
		reason = fields[2]
	}
	r := NewResponse(code, reason)
	r.Proto = fields[0]
	if err := parseHeaderBlock(reader, &r.headers, &r.body); err != nil {
		return nil, err
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

func parseHeaderBlock(reader *bufio.Reader, h *Headers, body *[]byte) error {
	var prev Header
	contentLength := -1
	headerCount := 0
	for {
		line, err := reader.ReadString('\n')
		if err != nil && line == "" {
			return fmt.Errorf("%w: unexpected end of headers: %v", ErrParse, err)
		}
		line = strings.TrimRight(line, "\r\n")
		if len(line) > maxHeaderLineLen {
			return fmt.Errorf("%w: header line too long", ErrBadHeader)
		}
		if line == "" {
			break
		}
		headerCount++
		if headerCount > maxHeaderLines {
			return fmt.Errorf("%w: too many headers", ErrBadHeader)
		}
		if line[0] == ' ' || line[0] == '\t' {
			if prev == nil {
				return fmt.Errorf("%w: continuation without header", ErrBadHeader)
			}
			setHeaderValue(prev, strings.TrimSpace(line))
			continue
		}
		name, value, found := strings.Cut(line, ":")
		if !found {
			return fmt.Errorf("%w: no colon in header %q", ErrBadHeader, line)
		}
		hdr := newTypedHeader(CanonicalName(strings.TrimSpace(name)), strings.TrimSpace(value))
		h.Add(hdr)
		prev = hdr
		if cl, ok := hdr.(ContentLength); ok {
			contentLength = int(cl)
		}
	}
	if contentLength < 0 {
		contentLength = 0
	}
	if contentLength > MaxBodySize {
		return fmt.Errorf("%w: content-length %d exceeds limit %d", ErrParse, contentLength, MaxBodySize)
	}
	if contentLength > 0 {
		buf := make([]byte, contentLength)
		n, err := io.ReadFull(reader, buf)
		if err != nil {
			return fmt.Errorf("%w: short body: got %d want %d: %v", ErrParse, n, contentLength, err)
		}
		*body = buf[:n]
	}
	return nil
}

func setHeaderValue(h Header, extra string) {
	if g, ok := h.(*GenericHeader); ok {
		g.V += " " + extra
	}
}

func newTypedHeader(name, value string) Header {
	switch name {
	case "Via":
		if v, err := ParseVia(value); err == nil {
			return v
		}
	case "From", "To", "Contact", "Route", "Record-Route", "Refer-To", "Accept-Contact", "Referred-By", "Reply-To", "Alert-Info", "Call-Info", "Error-Info", "P-Asserted-Identity", "Path", "Service-Route":
		if l, err := ParseNameAddrList(value); err == nil {
			l.HName = name
			return l
		}
	case "CSeq":
		if c, err := ParseCSeq(value); err == nil {
			return c
		}
	case "Content-Length":
		if c, err := ParseContentLength(value); err == nil {
			return c
		}
	case "Max-Forwards":
		if n, err := strconv.Atoi(value); err == nil {
			return MaxForwards(n)
		}
	case "Authorization", "WWW-Authenticate", "Proxy-Authorization", "Proxy-Authenticate":
		if a, err := ParseAuth(value); err == nil {
			return &TypedAuthHeader{Auth: a, K: name}
		}
	case "Allow", "Supported", "Require", "Proxy-Require", "Unsupported", "Allow-Events", "Event", "Accept", "Accept-Encoding", "Accept-Language", "Warning", "In-Reply-To", "Priority", "Retry-After", "Server", "User-Agent", "Organization", "Subject", "Timestamp", "Session-Expires", "Min-SE":
		return &GenericHeader{K: name, V: value}
	}
	return &GenericHeader{K: name, V: value}
}

type TypedAuthHeader struct {
	*Auth
	K string
}

func (t *TypedAuthHeader) Name() string  { return t.K }
func (t *TypedAuthHeader) Value() string { return t.Auth.Value() }
func (t *TypedAuthHeader) Clone() Header {
	return &TypedAuthHeader{Auth: t.Auth.Clone().(*Auth), K: t.K}
}

// StreamSplitter reassembles TCP streams into complete SIP messages.

type StreamSplitter struct {
	buf []byte
}

func (s *StreamSplitter) Feed(data []byte) ([][]byte, error) {
	if len(s.buf)+len(data) > MaxMessageSize {
		s.buf = nil
		return nil, fmt.Errorf("%w: buffered message exceeds %d bytes", ErrParse, MaxMessageSize)
	}
	s.buf = append(s.buf, data...)
	var out [][]byte
	for {
		msg, rest, ok, err := splitOne(s.buf)
		if err != nil {
			s.buf = rest
			return out, err
		}
		if !ok {
			return out, nil
		}
		s.buf = rest
		out = append(out, msg)
	}
}

func splitOne(data []byte) (msg, rest []byte, ok bool, err error) {
	i := bytes.Index(data, []byte("\r\n\r\n"))
	if i < 0 {
		return nil, data, false, nil
	}
	head := data[:i+4]
	cl := 0
	for _, line := range strings.Split(string(head), "\r\n") {
		name, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		if CanonicalName(name) == "Content-Length" {
			n, e := strconv.Atoi(strings.TrimSpace(value))
			if e != nil {
				return nil, data, false, fmt.Errorf("%w: bad content-length: %v", ErrParse, e)
			}
			cl = n
		}
	}
	total := i + 4 + cl
	if cl > MaxBodySize {
		return nil, data, false, fmt.Errorf("%w: content-length %d exceeds limit %d", ErrParse, cl, MaxBodySize)
	}
	if len(data) < total {
		return nil, data, false, nil
	}
	return data[:total], data[total:], true, nil
}
