package main

import (
	"flag"
	"log"
	"os"
	"os/signal"

	"github.com/jingdor/sip"
)

func main() {
	port := flag.Int("port", 5060, "listen port (udp+tcp)")
	host := flag.String("host", "127.0.0.1", "listen host")
	flag.Parse()

	tp, err := sip.NewTransport(*host, *port, *port)
	if err != nil {
		log.Fatal(err)
	}
	ua := sip.NewUA(tp, *host)

	ua.SetCallbacks(sip.UACallbacks{
		OnRegister: func(req *sip.Request, stx *sip.ServerTx) {
			_ = ua.Respond(nil, stx, 200, "", nil)
		},
		OnMessage: func(req *sip.Request, stx *sip.ServerTx) {
			_ = ua.Respond(nil, stx, 200, "", nil)
		},
		OnNotify: func(req *sip.Request, stx *sip.ServerTx) {
			_ = ua.Respond(nil, stx, 200, "", nil)
		},
		OnSubscribe: func(req *sip.Request, stx *sip.ServerTx) {
			_ = ua.Respond(nil, stx, 200, "", nil)
		},
		OnInfo: func(req *sip.Request, stx *sip.ServerTx, dlg *sip.Dialog) {
			_ = ua.Respond(dlg, stx, 200, "", nil)
		},
		OnInvite: func(req *sip.Request, stx *sip.ServerTx, dlg *sip.Dialog) {
			go func() {
				_ = ua.Respond(dlg, stx, 180, "", nil)
				sdp := "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=sip\r\nt=0 0\r\n"
				_ = ua.Respond(dlg, stx, 200, "application/sdp", []byte(sdp))
			}()
		},
		OnBye: func(req *sip.Request, dlg *sip.Dialog, stx *sip.ServerTx) {
		},
	})

	log.Printf("sipserv listening on %s:%d (udp+tcp)", *host, *port)
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
	_ = tp.Close()
}
