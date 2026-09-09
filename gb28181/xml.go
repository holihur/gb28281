// Package gb28181 implements GB/T 28181 national standard signaling on top of
// the sip stack: registration with digest auth, keepalive, catalog/deviceinfo
// queries (MANSCDP+xml) and live/playback INVITE with GB28181 SDP (y=/f=).
package gb28181

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// CmdType values defined by GB/T 28181.
const (
	CmdKeepalive      = "Keepalive"
	CmdCatalog        = "Catalog"
	CmdDeviceInfo     = "DeviceInfo"
	CmdDeviceStatus   = "DeviceStatus"
	CmdDeviceConfig   = "DeviceConfig"
	CmdConfigDownload = "ConfigDownload"
	CmdAlarm          = "Alarm"
	CmdMobilePos      = "MobilePosition"
	CmdPosition       = "Position"
	CmdPresetQuery    = "PresetQuery"
	CmdPTZCmd         = "PTZCmd"
	CmdTeleBoot       = "TeleBoot"
	CmdRecordInfo     = "RecordInfo"
	CmdDownload       = "Download"
	CmdBroadcast      = "Broadcast"
	CmdInvite         = "INVITE"
	CmdMediaStatus    = "MediaStatus"
	CmdHomePosition   = "HomePosition"
)

// Envelope is the MANSCDP+xml message root (Notify / Control / Query / Response).
type Envelope struct {
	XMLName  xml.Name
	CmdType  string `xml:"CmdType"`
	SN       int    `xml:"SN"`
	DeviceID string `xml:"DeviceID"`
	// Notify
	SeqNum int `xml:"SeqNum,omitempty"`
	// Control
	PTZCmd    string `xml:"PTZCmd,omitempty"`
	TeleBoot  string `xml:"TeleBoot,omitempty"`
	RecordCmd string `xml:"RecordCmd,omitempty"`
	GuardCmd  string `xml:"GuardCmd,omitempty"`
	AlarmCmd  string `xml:"AlarmCmd,omitempty"`
	// Alarm / keepalive
	AlarmTime        string `xml:"AlarmTime,omitempty"`
	AlarmType        string `xml:"AlarmType,omitempty"`
	AlarmPriority    string `xml:"AlarmPriority,omitempty"`
	AlarmMethod      string `xml:"AlarmMethod,omitempty"`
	AlarmDescription string `xml:"AlarmDescription,omitempty"`
	Longitude        string `xml:"Longitude,omitempty"`
	Latitude         string `xml:"Latitude,omitempty"`
	// Catalog / device info responses
	DeviceList   *DeviceList `xml:"DeviceList,omitempty"`
	DeviceName   string      `xml:"DeviceName,omitempty"`
	Manufacturer string      `xml:"Manufacturer,omitempty"`
	Model        string      `xml:"Model,omitempty"`
	Firmware     string      `xml:"Firmware,omitempty"`
	Result       string      `xml:"Result,omitempty"`
	Status       string      `xml:"Status,omitempty"`
	Reason       string      `xml:"Reason,omitempty"`
	Online       string      `xml:"Online,omitempty"`
	SumNum       int         `xml:"SumNum,omitempty"`
}

// Item is one channel entry of a catalog response.
type Item struct {
	DeviceID     string `xml:"DeviceID"`
	Name         string `xml:"Name,omitempty"`
	Manufacturer string `xml:"Manufacturer,omitempty"`
	Model        string `xml:"Model,omitempty"`
	Owner        string `xml:"Owner,omitempty"`
	CivilCode    string `xml:"CivilCode,omitempty"`
	Address      string `xml:"Address,omitempty"`
	Parental     string `xml:"Parental,omitempty"`
	ParentID     string `xml:"ParentID,omitempty"`
	SafetyWay    string `xml:"SafetyWay,omitempty"`
	RegisterWay  string `xml:"RegisterWay,omitempty"`
	Secrecy      string `xml:"Secrecy,omitempty"`
	IPAddress    string `xml:"IPAddress,omitempty"`
	Port         string `xml:"Port,omitempty"`
	Password     string `xml:"Password,omitempty"`
	Status       string `xml:"Status,omitempty"`
	Longitude    string `xml:"Longitude,omitempty"`
	Latitude     string `xml:"Latitude,omitempty"`
}

// DeviceList wraps catalog items.
type DeviceList struct {
	Num   string `xml:"Num,attr"`
	Items []Item `xml:"Item"`
}

// Marshal builds a MANSCDP+xml body with an explicit XML declaration, as
// required by the standard (encoding is commonly GB2312/UTF-8; we always
// emit UTF-8 which is a valid subset for the transport layer).
func Marshal(e *Envelope) []byte {
	var b bytes.Buffer
	b.WriteString(xml.Header)
	enc := xml.NewEncoder(&b)
	_ = enc.Encode(e)
	_ = enc.Flush()
	return b.Bytes()
}

// MarshalRoot is Marshal with a custom root element name
// (Notify / Control / Query / Response).
func MarshalRoot(root string, e *Envelope) []byte {
	e.XMLName = xml.Name{Local: root}
	return Marshal(e)
}

// Parse decodes a MANSCDP+xml body. Tolerates declarations like
// <?xml version="1.0" encoding="GB2312"?> with any root element name.
func Parse(body []byte) (*Envelope, error) {
	if i := bytes.IndexByte(body, '<'); i > 0 {
		body = body[i:]
	} else if i == -1 {
		return nil, fmt.Errorf("gb28181: empty xml body")
	}
	dec := xml.NewDecoder(bytes.NewReader(body))
	dec.Strict = false
	// The declared encoding (often GB2312) is ignored: bodies on the wire
	// are decoded as raw bytes and republished as UTF-8.
	dec.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
		return input, nil
	}
	e := &Envelope{}
	if err := dec.Decode(e); err != nil {
		return nil, fmt.Errorf("gb28181: decode xml: %w", err)
	}
	return e, nil
}

// BuildNotify wraps e in a Notify root and marshals it.
func BuildNotify(e *Envelope) []byte { return MarshalRoot("Notify", e) }

// BuildQuery wraps e in a Query root and marshals it.
func BuildQuery(e *Envelope) []byte { return MarshalRoot("Query", e) }

// BuildControl wraps e in a Control root and marshals it.
func BuildControl(e *Envelope) []byte { return MarshalRoot("Control", e) }

// BuildResponse wraps e in a Response root and marshals it.
func BuildResponse(e *Envelope) []byte { return MarshalRoot("Response", e) }

// ParseSSRC parses an SSRC hex string used in the y= SDP line.
func ParseSSRC(s string) (uint32, error) {
	s = strings.TrimSpace(s)
	if v, err := strconv.ParseUint(s, 16, 32); err == nil {
		return uint32(v), nil
	}
	if v, err := strconv.ParseUint(s, 10, 32); err == nil {
		return uint32(v), nil
	}
	return 0, fmt.Errorf("gb28181: invalid ssrc %q", s)
}
