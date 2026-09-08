# go-sip

A complete SIP (RFC 3261) protocol stack implemented in pure Go, with an
independent Python black-box test suite and full CI (golangci-lint + Codecov).

## Features

- **Message layer**: full SIP URI parsing (incl. IPv6, params, headers), all
  common headers with compact-form support (`v`, `f`, `t`, `i`, `m`, `c`, `l`,
  `k`...), wire-format parser with line folding and `Content-Length` framing
- **Transport**: UDP, TCP and **TLS (SIPS)** with connection pooling, idle
  reaping, write deadlines, and connection limits; RFC 3263 **DNS SRV/NAPTR**
  resolution with priority/weight ordering and A-record fallback
- **Transaction layer**: full client/server transaction state machines
  (ICT/NICT/IST/NIST) with RFC 3261 timers (A, B, D, F, G, H, I, J), retransmissions,
  ACK for non-2xx, ACK retransmit on duplicate 200, CANCEL
- **Dialog layer**: early/confirmed/terminated dialog state, route sets,
  record-routing, remote target updates, CSeq tracking, glare (491) retry
- **UA layer**: REGISTER (with Digest auth helpers), INVITE sessions with
  early dialog, BYE, MESSAGE/INFO/NOTIFY/SUBSCRIBE handling, pluggable callbacks
- **Stateful proxy**: parallel forking, best-final response selection, CANCEL
  fan-out, Record-Route insertion, Max-Forwards/loop protection (483), Timer C
- **B2BUA**: two-leg session bridging with pluggable media relay interface
- **Observability**: `slog`-based pluggable logging, metrics counters
- **Tooling**: `cmd/sipserv` demo server, Python black-box tests, chaos tests
  (packet loss), GitHub Actions CI

## Install

```bash
go get github.com/holihur/sip
```

## Usage

### Simple request/response

```go
tp, err := sip.NewTransport("0.0.0.0", 5060, 5060)
ua := sip.NewUA(tp, "myhost.example.com")

ua.SetCallbacks(sip.UACallbacks{
    OnMessage: func(req *sip.Request, stx *sip.ServerTx) {
        _ = ua.Respond(nil, stx, 200, "", nil)
    },
})
```

### REGISTER

```go
aor := &sip.Uri{Scheme: "sip", User: "alice", Host: "registrar.example.com"}
tx, err := ua.Register(aor, nil, 3600, nil)
ev := <-tx.Events() // ev.Response.StatusCode == 200
```

### Outgoing call

```go
sess, _ := ua.Invite(target, from, "application/sdp", sdp)
resp, err := sess.WaitResponse(30 * time.Second)
_ = sess.Ack()
final, err := ua.Hangup(sess.Dialog(), 30*time.Second)
```

## Tests

```bash
go test -race -cover ./...
```

Coverage target: **>= 90%**.

### Python black-box tests

Wire-level tests that treat the stack purely as a black box over UDP/TCP:

```bash
pip install -r pytests/requirements.txt
pytest pytests/ -v
```

## CI

`.github/workflows/ci.yml` runs:

- `go test -race -coverprofile` on Go 1.22 / 1.23, uploads results to Codecov
- `golangci-lint` (config in `.golangci.yml`)
- Python black-box suite against a real server over the wire

## License

MIT

### Stateful proxy

```go
tm := sip.NewTxManager(tp, host, tp.UDPPort())
tm.Run()
px := sip.NewProxy(tp, tm, host, sip.ProxyConfig{RecordRoute: true})
px.SetResolveTargets(func(req *sip.Request) ([]*sip.Uri, error) {
    return lookupTargets(req) // parallel forking across returned targets
})
```

### B2BUA

```go
b := sip.NewB2BUA(uaIngress, uaEgress, myMediaRelay)
b.SetRouteTarget(func(req *sip.Request) (*sip.Uri, error) { return dialPlan(req) })
```
