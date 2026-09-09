// Command gb28181serv is a demo GB28181 endpoint used by the Python
// black-box suite: platform mode (SIP server) or device mode (IPC/NVR
// simulator that registers to a platform).
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/holihur/sip"
	"github.com/holihur/sip/gb28181"
)

func main() {
	mode := flag.String("mode", "platform", "platform | device")
	serverID := flag.String("server-id", "34020000002000000001", "platform SIP ID")
	serverHost := flag.String("server-host", "127.0.0.1", "platform host")
	serverPort := flag.Int("server-port", 5060, "platform port")
	deviceID := flag.String("device-id", "34020000001320000001", "device SIP ID")
	password := flag.String("password", "12345678", "digest password")
	port := flag.Int("port", 5060, "listen port (platform) or local port (device)")
	channels := flag.Int("channels", 1, "number of simulated channels (device mode)")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	switch *mode {
	case "platform":
		p, err := gb28181.NewPlatform(gb28181.PlatformConfig{
			ServerID:   *serverID,
			ServerHost: "127.0.0.1",
			ListenPort: *port,
			Password:   func(string) (string, bool) { return *password, true },
		})
		if err != nil {
			log.Fatal(err)
		}
		p.OnDevice = func(ev gb28181.DeviceEvent) {
			if ev.Envelope != nil {
				fmt.Printf("EVENT type=%s device=%s cmd=%s sn=%d\n", ev.Type, ev.DeviceID, ev.Envelope.CmdType, ev.Envelope.SN)
			} else {
				fmt.Printf("EVENT type=%s device=%s\n", ev.Type, ev.DeviceID)
			}
			if ev.Type == "registered" {
				go func(id string) {
					time.Sleep(200 * time.Millisecond)
					_ = p.QueryCatalog(id)
					_ = p.QueryDeviceInfo(id)
				}(ev.DeviceID)
			}
		}
		go func() { _ = p.Run(ctx) }()
		fmt.Printf("platform %s listening on udp/tcp %d\n", *serverID, *port)
		select {}
	case "device":
		chs := make([]gb28181.Item, 0, *channels)
		for i := 1; i <= *channels; i++ {
			chs = append(chs, gb28181.Item{
				DeviceID: fmt.Sprintf("%s%02d", (*deviceID)[:len(*deviceID)-2], i),
				Name:     fmt.Sprintf("cam%d", i),
				Status:   "ON",
			})
		}
		d, err := gb28181.NewDevice(gb28181.DeviceConfig{
			DeviceID:          *deviceID,
			Password:          *password,
			ServerID:          *serverID,
			ServerHost:        *serverHost,
			ServerPort:        *serverPort,
			LocalHost:         "127.0.0.1",
			LocalPort:         *port,
			KeepaliveInterval: 5 * time.Second,
			Channels:          chs,
			DeviceInfo:        gb28181.DeviceInfoT{Name: "pytest-device", Manufacturer: "go-sip", Model: "sim", Firmware: "1.0"},
		})
		if err != nil {
			log.Fatal(err)
		}
		d.OnError = func(err error) { fmt.Println("DEVICE-ERROR:", err) }
		d.OnInvite = func(sdp *gb28181.SDP, dlg *sip.Dialog) {
			fmt.Printf("INVITE ssrc=%d videoPort=%d session=%s\n", sdp.SSRC, sdp.VideoPort, sdp.SessionName)
		}
		go func() { _ = d.Start(ctx) }()
		fmt.Printf("device %s -> %s@%s:%d, local %d\n", *deviceID, *serverID, *serverHost, *serverPort, *port)
		select {}
	}
}
