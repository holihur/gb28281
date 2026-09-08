package sip

import (
	"fmt"
	"net"
	"testing"
)

type fakeResolver struct {
	srv   map[string][]*net.SRV
	hosts map[string][]string
}

func (f *fakeResolver) LookupSRV(service, proto, name string) ([]*net.SRV, error) {
	key := "_" + service + "._" + proto + "." + name
	if recs, ok := f.srv[key]; ok {
		return recs, nil
	}
	return nil, fmt.Errorf("no such srv")
}

func (f *fakeResolver) LookupHost(name string) ([]string, error) {
	if h, ok := f.hosts[name]; ok {
		return h, nil
	}
	return nil, fmt.Errorf("no such host")
}

func TestResolveTargetExplicitPort(t *testing.T) {
	r := &fakeResolver{hosts: map[string][]string{"h.com": {"1.1.1.1", "2.2.2.2"}}}
	targets, network, err := ResolveTarget(r, &Uri{Scheme: "sip", User: "a", Host: "h.com", Port: 5080})
	if err != nil {
		t.Fatal(err)
	}
	if network != "udp" || len(targets) != 2 || targets[0].Port != 5080 {
		t.Fatal(targets, network)
	}
}

func TestResolveTargetSRV(t *testing.T) {
	r := &fakeResolver{
		srv: map[string][]*net.SRV{
			"_sip._udp.h.com": {
				{Target: "a.h.com.", Port: 5060, Priority: 1, Weight: 50},
				{Target: "b.h.com.", Port: 5070, Priority: 2, Weight: 0},
			},
		},
		hosts: map[string][]string{
			"a.h.com.": {"10.0.0.1"},
			"b.h.com.": {"10.0.0.2"},
		},
	}
	targets, network, err := ResolveTarget(r, &Uri{Scheme: "sip", User: "a", Host: "h.com"})
	if err != nil {
		t.Fatal(err)
	}
	if network != "udp" || len(targets) != 2 {
		t.Fatal(targets, network)
	}
	if targets[0].Host != "a.h.com." || targets[0].Port != 5060 {
		t.Fatalf("priority order broken: %+v", targets)
	}
}

func TestResolveTargetSipsUsesSipsTCP(t *testing.T) {
	r := &fakeResolver{
		srv: map[string][]*net.SRV{
			"_sips._tcp.h.com": {{Target: "s.h.com.", Port: 5061, Priority: 1, Weight: 0}},
		},
	}
	targets, network, err := ResolveTarget(r, &Uri{Scheme: "sips", User: "a", Host: "h.com"})
	if err != nil {
		t.Fatal(err)
	}
	if network != "tls" || targets[0].Port != 5061 {
		t.Fatal(targets, network)
	}
}

func TestResolveTargetFallbackToA(t *testing.T) {
	r := &fakeResolver{hosts: map[string][]string{"h.com": {"3.3.3.3"}}}
	targets, _, err := ResolveTarget(r, &Uri{Scheme: "sip", User: "a", Host: "h.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0].Host != "3.3.3.3" || targets[0].Port != 5060 {
		t.Fatal(targets)
	}
}

func TestResolveTargetTransportParam(t *testing.T) {
	r := &fakeResolver{hosts: map[string][]string{"h.com": {"1.1.1.1"}}}
	_, network, err := ResolveTarget(r, &Uri{Scheme: "sip", Host: "h.com", Params: NewParams().Set("transport", "tcp")})
	if err != nil {
		t.Fatal(err)
	}
	if network != "tcp" {
		t.Fatal(network)
	}
}

func TestShuffleSRVPriorities(t *testing.T) {
	srvs := []*net.SRV{
		{Target: "low.", Port: 1, Priority: 10, Weight: 0},
		{Target: "high.", Port: 2, Priority: 1, Weight: 0},
	}
	out := shuffleSRV(srvs)
	if out[0].Host != "high." {
		t.Fatal(out)
	}
}

func TestFormatHostPort(t *testing.T) {
	if formatHostPort(HostPort{"h.com", 5060}) != "h.com:5060" {
		t.Fatal("format")
	}
}

func TestNetResolverConstructs(t *testing.T) {
	if NewNetResolver() == nil {
		t.Fatal("nil")
	}
}
