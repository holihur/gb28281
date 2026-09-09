"""Black-box tests: python emulates the platform against the Go device."""
import os
import re
import socket
import sys
import time

import pytest
import signal

sys.path.insert(0, os.path.dirname(__file__))
from helpers import (  # noqa: E402
    CHANNEL_ID, DEVICE_ID, HOST, PASSWORD, SERVER_ID,
    SipMsg, build, digest_response, free_port, spawn,
)


class PlatformStub:
    """Raw-UDP platform that a Go device registers to."""

    def __init__(self, port=None):
        self.port = port or free_port()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((HOST, self.port))
        self.sock.settimeout(5)
        self.nonces = {}
        self.passwords = {DEVICE_ID: PASSWORD}
        self.device_src = None

    def recv(self, timeout=5):
        self.sock.settimeout(timeout)
        data, src = self.sock.recvfrom(65535)
        return SipMsg(data), src

    def respond(self, msg, src, status, extra="", body=b""):
        lines = [f"SIP/2.0 {status} {self._reason(status)}",
                 f"Via: {msg.header('Via')}",
                 f"From: {msg.header('From')}"]
        to = msg.header("To")
        if status >= 200 and "tag=" not in to:
            to += f";tag=plt{os.urandom(3).hex()}"
        lines += [f"To: {to}",
                  f"Call-ID: {msg.header('Call-ID')}",
                  f"CSeq: {msg.header('CSeq')}"]
        if extra:
            lines.append(extra)
        lines.append(f"Content-Length: {len(body)}")
        raw = ("\r\n".join(lines) + "\r\n\r\n").encode() + body
        self.sock.sendto(raw, src)

    @staticmethod
    def _reason(status):
        return {200: "OK", 401: "Unauthorized"}.get(status, "Response")

    def _device_of(self, msg):
        return re.search(r"sip:(\d+)@", msg.header("From")).group(1)

    def register_flow(self, timeout=15):
        """Run the 401-challenge digest flow until success."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                msg, src = self.recv(timeout=2)
            except socket.timeout:
                continue
            if msg.method != "REGISTER":
                continue
            self.device_src = src
            if msg.authorization().get("response"):
                if self.verify(msg, src):
                    return True
            else:
                self.challenge(msg, src)
        return False

    def challenge(self, msg, src):
        nonce = os.urandom(8).hex()
        self.nonces[self._device_of(msg)] = nonce
        www = f'Digest realm="{SERVER_ID}", nonce="{nonce}"'
        self.respond(msg, src, 401, extra=f"WWW-Authenticate: {www}")

    def verify(self, msg, src):
        auth = msg.authorization()
        device = self._device_of(msg)
        nonce = self.nonces.get(device, "")
        expected = digest_response(device, self.passwords.get(device, ""), SERVER_ID,
                                   "REGISTER", auth.get("uri", ""), nonce)
        self.respond(msg, src, 200 if auth.get("response") == expected else 401)
        return auth.get("response") == expected

    def send_message(self, device, src, xml):
        body = xml.encode()
        req = (
            f"MESSAGE sip:{device}@{src[0]}:{src[1]} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP {HOST}:{self.port};branch=z9hG4bKq{os.urandom(4).hex()}\r\n"
            f"From: <sip:{SERVER_ID}@{SERVER_ID}>;tag=pltq\r\n"
            f"To: <sip:{device}@{src[0]}:{src[1]}>\r\n"
            f"Call-ID: q-{os.urandom(6).hex()}\r\n"
            f"CSeq: 1 MESSAGE\r\n"
            f"Max-Forwards: 70\r\n"
            f"Content-Type: application/MANSCDP+xml\r\n"
            f"Content-Length: {len(body)}\r\n\r\n").encode() + body
        self.sock.sendto(req, src)

    def invite(self, device, src, ssrc="01000001", media_port=36000):
        sdp = (f"v=0\r\no={SERVER_ID} 0 0 IN IP4 {HOST}\r\ns=Play\r\n"
               f"c=IN IP4 {HOST}\r\nt=0 0\r\n"
               f"m=video {media_port} RTP/AVP 96 98 97\r\n"
               f"a=recvonly\r\na=rtpmap:96 PS/90000\r\ny={ssrc}\r\n").encode()
        req = (
            f"INVITE sip:{device}@{src[0]}:{src[1]} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP {HOST}:{self.port};branch=z9hG4bKi{os.urandom(4).hex()}\r\n"
            f"From: <sip:{SERVER_ID}@{SERVER_ID}>;tag=pltinv\r\n"
            f"To: <sip:{device}@{src[0]}:{src[1]}>\r\n"
            f"Call-ID: inv-{os.urandom(6).hex()}\r\n"
            f"CSeq: 1 INVITE\r\n"
            f"Max-Forwards: 70\r\n"
            f"Contact: <sip:{SERVER_ID}@{HOST}:{self.port}>\r\n"
            f"Content-Type: application/sdp\r\n"
            f"Content-Length: {len(sdp)}\r\n\r\n").encode() + sdp
        self.sock.sendto(req, src)


@pytest.fixture(scope="module")
def device():
    build()
    plt = PlatformStub()
    local_port = free_port()
    proc = spawn([
        "-mode", "device", "-port", str(local_port),
        "-server-host", HOST, "-server-port", str(plt.port),
        "-server-id", SERVER_ID, "-device-id", DEVICE_ID, "-password", PASSWORD, "-channels", "2",
    ], wait_line="device")
    assert plt.register_flow(), "device did not complete digest registration"
    yield plt, proc
    proc.send_signal(signal.SIGTERM)
    proc.wait(timeout=5)


def _drain_until(plt, predicate, timeout=10):
    """Consume incoming SIP messages until predicate(msg) is true."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            msg, src = plt.recv(timeout=2)
        except socket.timeout:
            continue
        if msg.method == "MESSAGE":
            plt.respond(msg, src, 200)
        if predicate(msg):
            return msg
    return None


def test_device_answers_catalog_and_deviceinfo_queries(device):
    plt, _ = device
    assert plt.device_src is not None
    plt.send_message(DEVICE_ID, plt.device_src,
                     f'<?xml version="1.0" encoding="GB2312"?>\r\n<Query>'
                     f"<CmdType>Catalog</CmdType><SN>11</SN>"
                     f"<DeviceID>{DEVICE_ID}</DeviceID></Query>")
    msg = _drain_until(plt, lambda m: "MANSCDP" in (m.header("Content-Type") or "")
                       and "<CmdType>Catalog</CmdType>" in m.body)
    assert msg is not None, "no catalog response"
    assert "<SN>11</SN>" in msg.body
    assert CHANNEL_ID in msg.body

    plt.send_message(DEVICE_ID, plt.device_src,
                     f'<?xml version="1.0" encoding="GB2312"?>\r\n<Query>'
                     f"<CmdType>DeviceInfo</CmdType><SN>12</SN>"
                     f"<DeviceID>{DEVICE_ID}</DeviceID></Query>")
    msg = _drain_until(plt, lambda m: "MANSCDP" in (m.header("Content-Type") or "")
                       and "<CmdType>DeviceInfo</CmdType>" in m.body)
    assert msg is not None, "no deviceinfo response"
    assert "pytest-device" in msg.body


def test_device_sends_keepalives(device):
    plt, _ = device
    msg = _drain_until(plt, lambda m: "<CmdType>Keepalive</CmdType>" in m.body, timeout=12)
    assert msg is not None, "no keepalive observed"
    assert f"<DeviceID>{DEVICE_ID}</DeviceID>" in msg.body


def test_device_answers_ptz_control(device):
    plt, _ = device
    plt.send_message(DEVICE_ID, plt.device_src,
                     f'<?xml version="1.0" encoding="GB2312"?>\r\n<Control>'
                     f"<CmdType>PTZCmd</CmdType><SN>13</SN>"
                     f"<DeviceID>{DEVICE_ID}</DeviceID>"
                     f"<PTZCmd>A50F0104000000</PTZCmd></Control>")
    msg = _drain_until(plt, lambda m: m.status == 200
                       and "MANSCDP" not in (m.header("Content-Type") or ""))
    assert msg is not None, "control MESSAGE not answered with 200"


def test_device_answers_invite_with_sdp(device):
    plt, _ = device
    plt.invite(DEVICE_ID, plt.device_src, ssrc="01000001", media_port=36000)
    deadline = time.time() + 10
    resp = None
    while time.time() < deadline:
        try:
            msg, _ = plt.recv(timeout=2)
        except socket.timeout:
            break
        if msg.status == 100:
            continue
        resp = msg
        break
    assert resp is not None and resp.status == 200, getattr(resp, "first_line", "no answer")
    assert "y=01000001" in resp.body, resp.body
    assert re.search(r"m=video (\d+) RTP/AVP", resp.body)
    ack = (
        f"ACK sip:{DEVICE_ID}@{HOST}:{plt.device_src[1]} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {HOST}:{plt.port};branch=z9hG4bKack\r\n"
        f"From: {resp.header('From')}\r\n"
        f"To: {resp.header('To')}\r\n"
        f"Call-ID: {resp.header('Call-ID')}\r\n"
        f"CSeq: 1 ACK\r\n"
        f"Max-Forwards: 70\r\n"
        f"Content-Length: 0\r\n\r\n")
    plt.sock.sendto(ack.encode(), plt.device_src)
