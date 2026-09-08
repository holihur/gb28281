package sip

import "errors"

var (
	ErrParse           = errors.New("sip: parse error")
	ErrShortMessage    = errors.New("sip: message too short")
	ErrBadStartLine    = errors.New("sip: bad start line")
	ErrBadHeader       = errors.New("sip: bad header")
	ErrBadUri          = errors.New("sip: bad uri")
	ErrBadAddress      = errors.New("sip: bad address")
	ErrNoVia           = errors.New("sip: missing Via header")
	ErrNoFrom          = errors.New("sip: missing From header")
	ErrNoTo            = errors.New("sip: missing To header")
	ErrNoCallID        = errors.New("sip: missing Call-ID header")
	ErrNoCSeq          = errors.New("sip: missing CSeq header")
	ErrNoContact       = errors.New("sip: missing Contact header")
	ErrDialogNotFound  = errors.New("sip: dialog not found")
	ErrTxNotFound      = errors.New("sip: transaction not found")
	ErrTxExists        = errors.New("sip: transaction already exists")
	ErrTxTerminated    = errors.New("sip: transaction terminated")
	ErrTransportClosed = errors.New("sip: transport closed")
	ErrInvalidResponse = errors.New("sip: invalid response")
	ErrUnsupported     = errors.New("sip: unsupported operation")
	ErrTimeout         = errors.New("sip: timeout")
)
