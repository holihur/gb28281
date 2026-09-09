"""Shared helpers: spawn Go endpoints and speak raw SIP over the wire."""
import hashlib
import os
import re
import signal
import socket
import subprocess
import threading
import time

import pytest

HOST = "127.0.0.1"
ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
BIN = os.path.join(ROOT, "bin", "gb28181serv")

DEVICE_ID = "34020000001320000001"
CHANNEL_ID = "34020000001320000002"
SERVER_ID = "34020000002000000001"
PASSWORD = "12345678"


def build():
    subprocess.run(["go", "build", "-o", BIN, "./cmd/gb28181serv"], check=True, cwd=ROOT)


def free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((HOST, 0))
    port = s.getsockname()[1]
    s.close()
    return port


def spawn(args, wait_line=None, timeout=10):
    proc = subprocess.Popen([BIN] + args, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)
    if wait_line:
        deadline = time.time() + timeout
        got = threading.Event()
        buf = []

        def reader():
            for line in proc.stdout:
                buf.append(line)
                if wait_line in line:
                    got.set()
        threading.Thread(target=reader, daemon=True).start()
        while not got.wait(0.1):
            if time.time() > deadline:
                proc.send_signal(signal.SIGTERM)
                raise RuntimeError(f"timeout waiting for {wait_line!r}; output: {buf}")
    return proc


class SipMsg:
    def __init__(self, raw):
        self.raw = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
        head, _, body = self.raw.partition("\r\n\r\n")
        self.headers = {}
        self.first_line = head.split("\r\n")[0]
        for line in head.split("\r\n")[1:]:
            k, _, v = line.partition(":")
            k = k.strip().lower()
            if k and k not in self.headers:
                self.headers[k] = v.strip()
        self.body = body
        m = re.match(r"SIP/2\.0 (\d+)", self.first_line)
        self.status = int(m.group(1)) if m else None
        m = re.match(r"(\w+) ", self.first_line)
        self.method = m.group(1) if m else None

    def header(self, name):
        return self.headers.get(name.lower())

    def www_auth(self):
        return parse_auth(self.header("WWW-Authenticate") or "")

    def authorization(self):
        return parse_auth(self.header("Authorization") or "")


def parse_auth(value):
    out = {}
    m = re.match(r"\s*Digest\s*(.*)", value, re.I)
    if not m:
        return out
    for part in re.split(r",\s*|\s+", m.group(1)):
        if "=" in part:
            k, _, v = part.partition("=")
            out[k.lower()] = v.strip('"')
    return out


def digest_response(username, password, realm, method, uri, nonce):
    ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    return hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()


def xml_envelope(root, cmd, sn, device_id, extra=""):
    return (f'<?xml version="1.0" encoding="GB2312"?>\r\n<{root}>'
            f"<CmdType>{cmd}</CmdType><SN>{sn}</SN><DeviceID>{device_id}</DeviceID>"
            f"{extra}</{root}>")


class DeviceClient:
    """Minimal GB28181 device speaking raw UDP to a platform."""

    def __init__(self, port):
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((HOST, 0))
        self.local_port = self.sock.getsockname()[1]
        self.sock.settimeout(5)
        self.call_id = "py-" + os.urandom(6).hex()
        self.seq = 1

    def via(self, branch):
        return f"Via: SIP/2.0/UDP {HOST}:{self.local_port};branch={branch}\r\n"

    def send(self, raw: bytes):
        self.sock.sendto(raw, (HOST, self.port))

    def recv(self, timeout=5):
        self.sock.settimeout(timeout)
        data, _ = self.sock.recvfrom(65535)
        return SipMsg(data)

    def register(self, authorization=None, cseq=1, call_id=None):
        uri = f"sip:{SERVER_ID}@{SERVER_ID}"
        req = (
            f"REGISTER {uri} SIP/2.0\r\n"
            + self.via("z9hG4bKpy" + os.urandom(4).hex())
            + f"From: <sip:{DEVICE_ID}@{SERVER_ID}>;tag=pytag{os.urandom(3).hex()}\r\n"
            + f"To: <sip:{SERVER_ID}@{SERVER_ID}>\r\n"
            + f"Call-ID: {call_id or self.call_id}\r\n"
            + f"CSeq: {cseq} REGISTER\r\n"
            + "Max-Forwards: 70\r\n"
            + f"Contact: <sip:{DEVICE_ID}@{HOST}:{self.local_port}>\r\n"
            + "Expires: 3600\r\n"
        )
        if authorization:
            req += f"Authorization: {authorization}\r\n"
        req += "Content-Length: 0\r\n\r\n"
        self.send(req.encode())
        return self.recv()

    def register_authorized(self):
        """Full 401-challenge digest flow; returns (final, challenge)."""
        r401 = self.register()
        assert r401.status == 401, r401.first_line
        ch = r401.www_auth()
        uri = f"sip:{SERVER_ID}@{SERVER_ID}"
        resp = digest_response(DEVICE_ID, PASSWORD, ch["realm"], "REGISTER", uri, ch["nonce"])
        auth = (f'Digest username="{DEVICE_ID}", realm="{ch["realm"]}", nonce="{ch["nonce"]}", '
                f'uri="{uri}", response="{resp}", algorithm="MD5"')
        final = self.register(authorization=auth, cseq=2)
        return final, ch

    def message(self, xml: str, cseq_method="MESSAGE", ctype="application/MANSCDP+xml"):
        body = xml.encode()
        req = (
            f"MESSAGE sip:{SERVER_ID}@{SERVER_ID} SIP/2.0\r\n"
            + self.via("z9hG4bKpy" + os.urandom(4).hex())
            + f"From: <sip:{DEVICE_ID}@{SERVER_ID}>;tag=pytag{os.urandom(3).hex()}\r\n"
            + f"To: <sip:{SERVER_ID}@{SERVER_ID}>\r\n"
            + f"Call-ID: {self.call_id}-{os.urandom(2).hex()}\r\n"
            + f"CSeq: {self.seq} {cseq_method}\r\n"
            + "Max-Forwards: 70\r\n"
            + f"Content-Type: {ctype}\r\n"
            + f"Content-Length: {len(body)}\r\n\r\n"
        ).encode() + body
        self.seq += 1
        self.send(req)
        return self.recv()

    def keepalive(self, sn=1):
        xml = xml_envelope("Notify", "Keepalive", sn, DEVICE_ID)
        return self.message(xml)
