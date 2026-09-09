package sip

import (
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Addr struct {
	Network string
	Host    string
	Port    int
}

func (a Addr) String() string {
	return a.Network + ":" + net.JoinHostPort(a.Host, strconv.Itoa(a.Port))
}

func AddrFromUDP(u *net.UDPAddr) Addr {
	return Addr{Network: "udp", Host: u.IP.String(), Port: u.Port}
}

func AddrFromTCP(t *net.TCPAddr) Addr {
	return Addr{Network: "tcp", Host: t.IP.String(), Port: t.Port}
}

type Packet struct {
	Msg Message
	Src Addr
}

type Transport struct {
	udpConn     *net.UDPConn
	tcpListener *net.TCPListener
	tlsListener net.Listener
	tlsCfg      *tls.Config

	dropHookMu     sync.Mutex
	DropHook       func(msg Message, dst Addr) bool
	TCPIdleTimeout time.Duration
	MaxTCPConns    int

	mu          sync.Mutex
	tcpConns    map[string]net.Conn
	connLastUse map[string]time.Time
	inflight    map[string]*dialCall
	packets     chan *Packet
	done        chan struct{}
	closeOnce   sync.Once
}

// dialCall tracks a single in-flight outbound dial so concurrent Send calls
// to the same target share one connection instead of dialing in parallel.
type dialCall struct {
	wg  sync.WaitGroup
	c   net.Conn
	err error
}

const (
	defaultIdleTimeout = 5 * time.Minute
	defaultMaxTCPConns = 1024
	writeTimeout       = 10 * time.Second
)

func (t *Transport) dropHook() func(msg Message, dst Addr) bool {
	t.dropHookMu.Lock()
	defer t.dropHookMu.Unlock()
	return t.DropHook
}

func (t *Transport) SetDropHook(f func(msg Message, dst Addr) bool) {
	t.dropHookMu.Lock()
	t.DropHook = f
	t.dropHookMu.Unlock()
}

func (t *Transport) idleTimeout() time.Duration {
	t.dropHookMu.Lock()
	defer t.dropHookMu.Unlock()
	if t.TCPIdleTimeout > 0 {
		return t.TCPIdleTimeout
	}
	return defaultIdleTimeout
}

func (t *Transport) maxTCPConns() int {
	t.dropHookMu.Lock()
	defer t.dropHookMu.Unlock()
	if t.MaxTCPConns > 0 {
		return t.MaxTCPConns
	}
	return defaultMaxTCPConns
}

func (t *Transport) touchConn(key string) {
	t.mu.Lock()
	if t.connLastUse != nil {
		t.connLastUse[key] = time.Now()
	}
	t.mu.Unlock()
}

func (t *Transport) dropConn(key string) {
	t.mu.Lock()
	if c, ok := t.tcpConns[key]; ok {
		_ = c.Close()
		delete(t.tcpConns, key)
		delete(t.connLastUse, key)
	}
	t.mu.Unlock()
}

func NewTLSTransport(host string, udpPort, tcpPort, tlsPort int, cfg *tls.Config) (*Transport, error) {
	t, err := NewTransport(host, udpPort, tcpPort)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, fmt.Errorf("sip: tls requires a config")
	}
	t.tlsCfg = cfg
	if tlsPort >= 0 {
		addr := &net.TCPAddr{IP: net.ParseIP(host), Port: tlsPort}
		if addr.IP == nil {
			addr = &net.TCPAddr{Port: tlsPort}
		}
		l, err := net.ListenTCP("tcp", addr)
		if err != nil {
			_ = t.Close()
			return nil, fmt.Errorf("sip: tls listen: %w", err)
		}
		t.tlsListener = tls.NewListener(l, cfg)
		go t.acceptStream(t.tlsListener, "tls")
	}
	go t.janitor()
	return t, nil
}

func (t *Transport) janitor() {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-t.done:
			return
		case <-ticker.C:
			t.mu.Lock()
			now := time.Now()
			for key, last := range t.connLastUse {
				if now.Sub(last) > t.idleTimeout() {
					if c, ok := t.tcpConns[key]; ok {
						_ = c.Close()
					}
					delete(t.tcpConns, key)
					delete(t.connLastUse, key)
				}
			}
			t.mu.Unlock()
		}
	}
}

func NewTransport(host string, udpPort, tcpPort int) (*Transport, error) {
	t := &Transport{
		tcpConns:    make(map[string]net.Conn),
		connLastUse: make(map[string]time.Time),
		inflight:    make(map[string]*dialCall),
		packets:     make(chan *Packet, 256),
		done:        make(chan struct{}),
	}
	go t.janitor()
	if udpPort >= 0 {
		addr := &net.UDPAddr{IP: net.ParseIP(host), Port: udpPort}
		if addr.IP == nil {
			addr = &net.UDPAddr{Port: udpPort}
		}
		c, err := net.ListenUDP("udp", addr)
		if err != nil {
			return nil, fmt.Errorf("sip: udp listen: %w", err)
		}
		t.udpConn = c
		go t.readUDP()
	}
	if tcpPort >= 0 {
		addr := &net.TCPAddr{IP: net.ParseIP(host), Port: tcpPort}
		if addr.IP == nil {
			addr = &net.TCPAddr{Port: tcpPort}
		}
		l, err := net.ListenTCP("tcp", addr)
		if err != nil {
			_ = t.Close()
			return nil, fmt.Errorf("sip: tcp listen: %w", err)
		}
		t.tcpListener = l
		go t.acceptStream(l, "tcp")
	}
	return t, nil
}

func (t *Transport) Packets() <-chan *Packet { return t.packets }

func (t *Transport) UDPPort() int {
	if t.udpConn == nil {
		return 0
	}
	return t.udpConn.LocalAddr().(*net.UDPAddr).Port
}

func (t *Transport) TCPPort() int {
	if t.tcpListener == nil {
		return 0
	}
	return t.tcpListener.Addr().(*net.TCPAddr).Port
}

func (t *Transport) readUDP() {
	buf := make([]byte, 65535)
	for {
		n, src, err := t.udpConn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-t.done:
				return
			default:
				time.Sleep(10 * time.Millisecond)
				continue
			}
		}
		t.dispatch(buf[:n], AddrFromUDP(src))
	}
}

func (t *Transport) acceptStream(l net.Listener, network string) {
	for {
		c, err := l.Accept()
		if err != nil {
			select {
			case <-t.done:
				return
			default:
				time.Sleep(10 * time.Millisecond)
				continue
			}
		}
		t.mu.Lock()
		n := len(t.tcpConns)
		t.mu.Unlock()
		if n > t.maxTCPConns() {
			_ = c.Close()
			continue
		}
		go t.readTCP(c)
	}
}

func (t *Transport) readTCP(c net.Conn) {
	defer func() {
		t.dropConn(t.connKey(c))
		_ = c.Close()
	}()
	t.mu.Lock()
	t.tcpConns[t.connKey(c)] = c
	if t.connLastUse != nil {
		t.connLastUse[t.connKey(c)] = time.Now()
	}
	t.mu.Unlock()
	splitter := &StreamSplitter{}
	buf := make([]byte, 65535)
	network := "tcp"
	if _, ok := c.(*tls.Conn); ok {
		network = "tls"
	}
	src := AddrFromTCP(c.RemoteAddr().(*net.TCPAddr))
	src.Network = network
	for {
		n, err := c.Read(buf)
		if n > 0 {
			msgs, perr := splitter.Feed(buf[:n])
			if perr != nil {
				return
			}
			for _, raw := range msgs {
				if !t.dispatch(raw, src) {
					return
				}
			}
		}
		if err != nil {
			return
		}
	}
}

func (t *Transport) dispatch(raw []byte, src Addr) bool {
	msg, err := ParseMessage(raw)
	if err != nil {
		return true
	}
	select {
	case t.packets <- &Packet{Msg: msg, Src: src}:
	case <-t.done:
		return false
	}
	return true
}

func (t *Transport) Send(network string, dst Addr, msg Message) error {
	data := []byte(msg.String())
	switch strings.ToLower(network) {
	case "udp":
		if t.udpConn == nil {
			return fmt.Errorf("%w: udp not enabled", ErrTransportClosed)
		}
		if hook := t.dropHook(); hook != nil && hook(msg, dst) {
			return nil
		}
		addr := &net.UDPAddr{IP: pickAddrFamily(t.udpConn, net.ParseIP(dst.Host)), Port: dst.Port}
		if addr.IP == nil {
			ips, err := net.LookupIP(dst.Host)
			if err != nil || len(ips) == 0 {
				return fmt.Errorf("sip: resolve %s: %w", dst.Host, err)
			}
			addr.IP = pickAddrFamily(t.udpConn, ips[0])
		}
		_ = t.udpConn.SetWriteDeadline(time.Now().Add(writeTimeout))
		_, err := t.udpConn.WriteToUDP(data, addr)
		return err
	case "tcp", "tls":
		conn, err := t.getStreamConn(network, dst)
		if err != nil {
			return err
		}
		_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		t.touchConn(t.connKey(conn))
		_, err = conn.Write(data)
		return err
	default:
		return fmt.Errorf("sip: unsupported network %q", network)
	}
}

// pickAddrFamily selects an address matching the local socket family,
// preferring IPv4 for IPv4-bound connections. For dual-stack (IPv6)
// sockets a v4 destination is converted to its 4-byte form so the kernel
// maps it onto the v4 address family instead of dropping it.
func pickAddrFamily(conn *net.UDPConn, ip net.IP) net.IP {
	if conn == nil || ip == nil {
		return ip
	}
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || local.IP == nil {
		return ip
	}
	local4 := local.IP.To4()
	wants4 := local4 != nil
	if (wants4 && ip.To4() != nil) || (!wants4 && ip.To4() == nil) {
		return ip
	}
	// Dual-stack socket (Go binds "::" with IPV6_V6ONLY=0 by default): a
	// literal IPv4 destination can still be written using its 4-byte form.
	if !wants4 && ip.To4() != nil && local.IP.IsUnspecified() {
		return ip.To4()
	}
	return nil
}

func (t *Transport) connKey(c net.Conn) string {
	network := "tcp"
	if _, ok := c.(*tls.Conn); ok {
		network = "tls"
	}
	return Addr{Network: network, Host: c.RemoteAddr().(*net.TCPAddr).IP.String(), Port: c.RemoteAddr().(*net.TCPAddr).Port}.String()
}

func (t *Transport) getStreamConn(network string, dst Addr) (net.Conn, error) {
	key := dst.String()
	t.mu.Lock()
	if c, ok := t.tcpConns[key]; ok {
		t.mu.Unlock()
		return c, nil
	}
	if d, ok := t.inflight[key]; ok {
		t.mu.Unlock()
		d.wg.Wait()
		t.mu.Lock()
		c, ok := t.tcpConns[key]
		t.mu.Unlock()
		if ok {
			return c, nil
		}
		return d.c, d.err
	}
	if len(t.tcpConns) >= t.maxTCPConns() {
		t.mu.Unlock()
		return nil, fmt.Errorf("%w: too many connections", ErrTransportClosed)
	}
	dc := &dialCall{}
	dc.wg.Add(1)
	t.inflight[key] = dc
	t.mu.Unlock()

	c, err := t.dial(network, dst)

	t.mu.Lock()
	delete(t.inflight, key)
	if err == nil && c != nil {
		t.tcpConns[key] = c
		if t.connLastUse != nil {
			t.connLastUse[key] = time.Now()
		}
	}
	t.mu.Unlock()
	dc.c = c
	dc.err = err
	dc.wg.Done()
	if err != nil {
		return nil, err
	}
	go t.readTCP(c)
	return c, nil
}

func (t *Transport) dial(network string, dst Addr) (net.Conn, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	if network == "tls" {
		cfg := t.tlsCfg.Clone()
		if cfg.MinVersion == 0 {
			cfg.MinVersion = tls.VersionTLS12
		}
		if cfg.ServerName == "" {
			cfg.ServerName = dst.Host
		}
		return tls.DialWithDialer(&d, "tcp", formatHostPort(HostPort{dst.Host, dst.Port}), cfg)
	}
	return d.Dial("tcp", net.JoinHostPort(dst.Host, strconv.Itoa(dst.Port)))
}

func (t *Transport) TLSPort() int {
	if t.tlsListener == nil {
		return 0
	}
	return t.tlsListener.Addr().(*net.TCPAddr).Port
}

func (t *Transport) Close() error {
	var err error
	t.closeOnce.Do(func() {
		close(t.done)
		if t.udpConn != nil {
			_ = t.udpConn.Close()
		}
		if t.tcpListener != nil {
			_ = t.tcpListener.Close()
		}
		if t.tlsListener != nil {
			_ = t.tlsListener.Close()
		}
		t.mu.Lock()
		for _, c := range t.tcpConns {
			_ = c.Close()
		}
		t.tcpConns = make(map[string]net.Conn)
		t.mu.Unlock()
	})
	return err
}

// TransportFor returns the network to use for reaching a target uri.
func (t *Transport) TransportFor(uri *Uri) (network string, host string, port int) {
	network = "udp"
	if uri.IsEncrypted() {
		network = "tls"
	}
	if tp, ok := uri.Params.Get("transport"); ok {
		switch strings.ToLower(tp) {
		case "tcp":
			network = "tcp"
		case "tls":
			network = "tls"
		case "udp":
			network = "udp"
		}
	}
	host = uri.Host
	port = uri.EffectivePort()
	return network, host, port
}
