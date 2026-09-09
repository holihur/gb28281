package gb28181

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// SDP helpers implementing GB/T 28181 media description extensions:
// y=<ssrc> (stream SSRC) and f=<v>/<a>/<s>/<y> (media format profile).

// StreamSDP describes one GB28181 media session.
type StreamSDP struct {
	Username  string // 20-digit national code of the media source
	Address   string // media IP
	SSRC      uint32
	RecvOnly  bool // true for platform (media receiver), false for device (sender)
	VideoPort int
	AudioPort int
	// Playback (INVITE with s=Play back) time range, RFC3339-ish strings
	SessionName string // Play / PlayBack / Broadcast / Download
	StartTime   string
	EndTime     string
}

// Build renders the SDP text.
func (s *StreamSDP) Build() []byte {
	dir := "sendonly"
	if s.RecvOnly {
		dir = "recvonly"
	}
	if s.SessionName == "" {
		s.SessionName = "Play"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "v=0\r\n")
	fmt.Fprintf(&b, "o=%s 0 0 IN IP4 %s\r\n", s.Username, s.Address)
	fmt.Fprintf(&b, "s=%s\r\n", s.SessionName)
	fmt.Fprintf(&b, "c=IN IP4 %s\r\n", s.Address)
	if s.StartTime != "" || s.EndTime != "" {
		fmt.Fprintf(&b, "t=%s %s\r\n", s.StartTime, s.EndTime)
	} else {
		b.WriteString("t=0 0\r\n")
	}
	if s.VideoPort > 0 {
		fmt.Fprintf(&b, "m=video %d RTP/AVP 96 98 97\r\n", s.VideoPort)
		fmt.Fprintf(&b, "a=%s\r\na=rtpmap:96 PS/90000\r\na=rtpmap:98 H264/90000\r\na=rtpmap:97 MPEG4/90000\r\ny=%08x\r\n", dir, s.SSRC)
	}
	if s.AudioPort > 0 {
		fmt.Fprintf(&b, "m=audio %d RTP/AVP 8 0\r\n", s.AudioPort)
		fmt.Fprintf(&b, "a=rtpmap:8 PCMA/8000\r\na=rtpmap:0 PCMU/8000\r\na=%s\r\ny=%08x\r\n", dir, s.SSRC)
	}
	return []byte(b.String())
}

// SDP is a loosely parsed GB28181 SDP offering/answer.
type SDP struct {
	Username    string
	Address     string
	SessionName string
	VideoPort   int
	AudioPort   int
	SSRC        uint32
	RecvOnly    bool
	StartTime   string
	EndTime     string
}

// ParseSDP parses GB28181 SDP, extracting the y= SSRC and f= fields.
func ParseSDP(body []byte) (*SDP, error) {
	s := &SDP{}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimRight(line, "\r")
		line = strings.TrimLeft(line, " \t")
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "o":
			fields := strings.Fields(v)
			if len(fields) > 0 {
				s.Username = fields[0]
			}
			if len(fields) >= 6 {
				s.Address = fields[len(fields)-1]
			}
		case "s":
			s.SessionName = strings.TrimSpace(v)
		case "c":
			fields := strings.Fields(v)
			if len(fields) == 3 && net.ParseIP(fields[2]) != nil {
				s.Address = fields[2]
			}
		case "t":
			fields := strings.Fields(v)
			if len(fields) >= 1 {
				s.StartTime = fields[0]
			}
			if len(fields) >= 2 {
				s.EndTime = fields[1]
			}
		case "m":
			fields := strings.Fields(v)
			if len(fields) >= 2 {
				port, _ := strconv.Atoi(fields[1])
				if strings.HasPrefix(fields[0], "video") {
					s.VideoPort = port
				} else if strings.HasPrefix(fields[0], "audio") {
					s.AudioPort = port
				}
			}
		case "a":
			a := strings.TrimSpace(v)
			if a == "recvonly" {
				s.RecvOnly = true
			}
		case "y":
			ssrc, err := ParseSSRC(v)
			if err != nil {
				return nil, err
			}
			s.SSRC = ssrc
		}
	}
	if s.SessionName == "" {
		return nil, fmt.Errorf("gb28181: invalid sdp: missing s= line")
	}
	return s, nil
}

// SSRCOf returns the SDP y= value as a decimal string used in RTP headers.
func (s *SDP) SSRCOf() string {
	return fmt.Sprintf("%d", s.SSRC)
}
