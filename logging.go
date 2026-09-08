package sip

import (
	"fmt"
	"log/slog"
	"os"
	"sync"
)

// Logger is the pluggable logging interface used across the stack.
type Logger interface {
	Debugf(format string, args ...any)
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
}

type slogLogger struct{ l *slog.Logger }

func NewSlogLogger(l *slog.Logger) Logger {
	if l == nil {
		l = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	return &slogLogger{l: l}
}

func (s *slogLogger) Debugf(format string, args ...any) { s.l.Debug(fmt.Sprintf(format, args...)) }
func (s *slogLogger) Infof(format string, args ...any)  { s.l.Info(fmt.Sprintf(format, args...)) }
func (s *slogLogger) Warnf(format string, args ...any)  { s.l.Warn(fmt.Sprintf(format, args...)) }
func (s *slogLogger) Errorf(format string, args ...any) { s.l.Error(fmt.Sprintf(format, args...)) }

type discardLogger struct{}

func (discardLogger) Debugf(string, ...any) {}
func (discardLogger) Infof(string, ...any)  {}
func (discardLogger) Warnf(string, ...any)  {}
func (discardLogger) Errorf(string, ...any) {}

// Metrics accumulates protocol counters with an optional callback.
type Metrics struct {
	mu       sync.Mutex
	counters map[string]uint64
	OnEvent  func(name string, value uint64)
}

func NewMetrics() *Metrics {
	return &Metrics{counters: make(map[string]uint64)}
}

func (m *Metrics) Inc(name string) {
	m.mu.Lock()
	m.counters[name]++
	v := m.counters[name]
	cb := m.OnEvent
	m.mu.Unlock()
	if cb != nil {
		cb(name, v)
	}
}

func (m *Metrics) Get(name string) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.counters[name]
}

func (m *Metrics) Snapshot() map[string]uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]uint64, len(m.counters))
	for k, v := range m.counters {
		out[k] = v
	}
	return out
}
