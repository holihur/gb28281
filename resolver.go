package sip

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

// HostPort is a resolved transport target.
type HostPort struct {
	Host string
	Port int
}

// Resolver abstracts DNS lookups (RFC 3263) so it can be injected in tests.
type Resolver interface {
	LookupSRV(service, proto, name string) ([]*net.SRV, error)
	LookupHost(name string) ([]string, error)
}

type NetResolver struct {
	R *net.Resolver
}

func NewNetResolver() *NetResolver {
	return &NetResolver{R: net.DefaultResolver}
}

func (n *NetResolver) LookupSRV(service, proto, name string) ([]*net.SRV, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, addrs, err := n.R.LookupSRV(ctx, service, proto, name)
	return addrs, err
}

func (n *NetResolver) LookupHost(name string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return n.R.LookupHost(ctx, name)
}

// ResolveTarget resolves a SIP URI to a list of transport targets (RFC 3263).
// Returns targets in preference order.
func ResolveTarget(r Resolver, uri *Uri) ([]HostPort, string, error) {
	network := "udp"
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
	// Explicit port: plain A lookup only.
	if uri.Port > 0 {
		ips, err := r.LookupHost(uri.Host)
		if err != nil {
			return nil, network, err
		}
		out := make([]HostPort, 0, len(ips))
		for _, ip := range ips {
			out = append(out, HostPort{Host: ip, Port: uri.Port})
		}
		if len(out) == 0 {
			out = append(out, HostPort{Host: uri.Host, Port: uri.Port})
		}
		return out, network, nil
	}
	service := "sip"
	proto := "udp"
	if uri.IsEncrypted() {
		service = "sips"
		proto = "tcp"
	} else if tp, ok := uri.Params.Get("transport"); ok {
		switch strings.ToLower(tp) {
		case "tcp", "tls":
			proto = "tcp"
		}
	}
	srvs, err := r.LookupSRV(service, proto, uri.Host)
	if err != nil || len(srvs) == 0 {
		ips, aerr := r.LookupHost(uri.Host)
		if aerr != nil {
			return nil, network, fmt.Errorf("srv: %v; a: %w", err, aerr)
		}
		port := uri.EffectivePort()
		out := make([]HostPort, 0, len(ips))
		for _, ip := range ips {
			out = append(out, HostPort{Host: ip, Port: port})
		}
		if len(out) == 0 {
			out = append(out, HostPort{Host: uri.Host, Port: port})
		}
		return out, network, nil
	}
	return shuffleSRV(srvs), network, nil
}

// shuffleSRV orders SRV records by priority with random weighting (RFC 2782).
func shuffleSRV(srvs []*net.SRV) []HostPort {
	sorted := append([]*net.SRV(nil), srvs...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Priority < sorted[j].Priority })
	out := make([]HostPort, 0, len(sorted))
	for i := 0; i < len(sorted); {
		j := i
		for j < len(sorted) && sorted[j].Priority == sorted[i].Priority {
			j++
		}
		group := sorted[i:j]
		for len(group) > 0 {
			total := 0
			for _, s := range group {
				total += int(s.Weight)
			}
			var pick int
			if total == 0 {
				pick = rand.Intn(len(group))
			} else {
				n := rand.Intn(total) + 1
				acc := 0
				for k, s := range group {
					acc += int(s.Weight)
					if acc >= n {
						pick = k
						break
					}
				}
			}
			s := group[pick]
			out = append(out, HostPort{Host: s.Target, Port: int(s.Port)})
			group = append(group[:pick], group[pick+1:]...)
		}
		i = j
	}
	return out
}

func formatHostPort(hp HostPort) string {
	return net.JoinHostPort(hp.Host, strconv.Itoa(hp.Port))
}
