package sip

import (
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
	mu          sync.Mutex
	tcpConns    map[string]net.Conn
	packets     chan *Packet
	done        chan struct{}
	closeOnce   sync.Once
}

func NewTransport(host string, udpPort, tcpPort int) (*Transport, error) {
	t := &Transport{
		tcpConns: make(map[string]net.Conn),
		packets:  make(chan *Packet, 256),
		done:     make(chan struct{}),
	}
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
		go t.acceptTCP()
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
				continue
			}
		}
		t.dispatch(buf[:n], AddrFromUDP(src))
	}
}

func (t *Transport) acceptTCP() {
	for {
		c, err := t.tcpListener.Accept()
		if err != nil {
			select {
			case <-t.done:
				return
			default:
				continue
			}
		}
		go t.readTCP(c)
	}
}

func (t *Transport) readTCP(c net.Conn) {
	defer func() { _ = c.Close() }()
	t.mu.Lock()
	t.tcpConns[AddrFromTCP(c.RemoteAddr().(*net.TCPAddr)).String()] = c
	t.mu.Unlock()
	splitter := &StreamSplitter{}
	buf := make([]byte, 65535)
	src := AddrFromTCP(c.RemoteAddr().(*net.TCPAddr))
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
		addr := &net.UDPAddr{IP: net.ParseIP(dst.Host), Port: dst.Port}
		if addr.IP == nil {
			ips, err := net.LookupIP(dst.Host)
			if err != nil || len(ips) == 0 {
				return fmt.Errorf("sip: resolve %s: %w", dst.Host, err)
			}
			addr.IP = ips[0]
		}
		_, err := t.udpConn.WriteToUDP(data, addr)
		return err
	case "tcp":
		conn, err := t.getTCPConn(dst)
		if err != nil {
			return err
		}
		_, err = conn.Write(data)
		return err
	default:
		return fmt.Errorf("sip: unsupported network %q", network)
	}
}

func (t *Transport) getTCPConn(dst Addr) (net.Conn, error) {
	key := dst.String()
	t.mu.Lock()
	if c, ok := t.tcpConns[key]; ok {
		t.mu.Unlock()
		return c, nil
	}
	t.mu.Unlock()
	d := net.Dialer{Timeout: 5 * time.Second}
	c, err := d.Dial("tcp", net.JoinHostPort(dst.Host, strconv.Itoa(dst.Port)))
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	t.tcpConns[key] = c
	t.mu.Unlock()
	go t.readTCP(c)
	return c, nil
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
		network = "tcp"
	}
	if tp, ok := uri.Params.Get("transport"); ok {
		switch strings.ToLower(tp) {
		case "tcp":
			network = "tcp"
		case "tls":
			network = "tcp"
		case "udp":
			network = "udp"
		}
	}
	host = uri.Host
	port = uri.EffectivePort()
	return network, host, port
}
