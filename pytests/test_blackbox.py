import socket
import time
import os
import signal
import subprocess
import pytest

HOST = "127.0.0.1"
BIN = os.path.join(os.path.dirname(__file__), "..", "bin", "sipserv")


@pytest.fixture(scope="session")
def server():
    subprocess.run(["go", "build", "-o", BIN, "./cmd/sipserv"], check=True,
                   cwd=os.path.join(os.path.dirname(__file__), ".."))
    port = _free_udp_port()
    proc = subprocess.Popen([BIN, "-port", str(port), "-host", HOST])
    time.sleep(0.5)
    yield port
    proc.send_signal(signal.SIGTERM)
    proc.wait(timeout=5)


def _free_udp_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((HOST, 0))
    port = s.getsockname()[1]
    s.close()
    return port


class SipClient:
    def __init__(self, port, transport="udp"):
        self.port = port
        self.transport = transport
        if transport == "udp":
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind((HOST, 0))
            self.addr = (HOST, self.sock.getsockname()[1])
        else:
            self.sock = socket.create_connection((HOST, port), timeout=5)
            self.addr = (HOST, self.sock.getsockname()[1])
        self.sock.settimeout(5)
        self.branch = "z9hG4bKpytest" + os.urandom(4).hex()
        self.cid = "pytest-" + os.urandom(8).hex()
        self.seq = 100
        self.from_tag = "ptag" + os.urandom(4).hex()

    def next_branch(self):
        self.branch = "z9hG4bKpytest" + os.urandom(4).hex()
        return self.branch

    def send(self, raw: bytes):
        if self.transport == "udp":
            self.sock.sendto(raw, (HOST, self.port))
        else:
            self.sock.sendall(raw)

    def recv(self, timeout=5):
        self.sock.settimeout(timeout)
        if self.transport == "udp":
            data, _ = self.sock.recvfrom(65535)
        else:
            data = self._recv_message()
        return data.decode()

    def _recv_message(self):
        buf = b""
        while True:
            chunk = self.sock.recv(65535)
            buf += chunk
            if b"\r\n\r\n" in buf:
                head, _, rest = buf.partition(b"\r\n\r\n")
                cl = 0
                for line in head.split(b"\r\n"):
                    k, _, v = line.partition(b":")
                    if k.strip().lower() == b"content-length":
                        cl = int(v.strip())
                if len(rest) >= cl:
                    return head + b"\r\n\r\n" + rest[:cl]

    def request(self, method, ruri, extra="", body="", compact=False, headers=(), to_tag=None):
        self.seq += 1
        via = "v" if compact else "Via"
        fromh = "f" if compact else "From"
        toh = "t" if compact else "To"
        cid = "i" if compact else "Call-ID"
        cseq = "CSeq"
        cl = "l" if compact else "Content-Length"
        ct = "c" if compact else "Content-Type"
        lines = [
            f"{method} {ruri} SIP/2.0",
            f"{via}: SIP/2.0/{self.transport.upper()} {HOST}:{self.addr[1]};branch={self.branch};rport",
            f"{fromh}: <sip:alice@{HOST}>;tag={self.from_tag}",
            f"{toh}: <{ruri}>" + (f";tag={to_tag}" if to_tag else ""),
            f"{cid}: {self.cid}",
            f"{cseq}: {self.seq} {method}",
        ]
        lines.extend(headers)
        if body:
            lines.append(f"{ct}: application/sdp")
        lines.append(f"{cl}: {len(body)}")
        raw = "\r\n".join(lines) + "\r\n\r\n" + body
        self.send(raw.encode())
        return raw

    def close(self):
        self.sock.close()


def parse(resp: str):
    lines = resp.split("\r\n")
    status = lines[0]
    headers = {}
    i = 1
    while i < len(lines) and lines[i]:
        k, _, v = lines[i].partition(":")
        headers[k.strip().lower()] = v.strip()
        i += 1
    body = "\r\n".join(lines[i + 1:]) if len(lines) > i else ""
    return status, headers, body


def test_options(server):
    c = SipClient(server)
    c.request("OPTIONS", f"sip:server@{HOST}")
    status, headers, body = parse(c.recv())
    assert status == "SIP/2.0 200 OK"
    assert headers["cseq"].endswith("OPTIONS")
    assert headers["call-id"] == c.cid
    assert headers["via"].startswith("SIP/2.0/UDP")
    assert f";branch={c.branch}" in headers["via"]
    c.close()


def test_register(server):
    c = SipClient(server)
    c.request("REGISTER", f"sip:{HOST}", headers=(
        f"Contact: <sip:alice@{HOST}:{c.addr[1]}>;expires=3600",
        "Expires: 3600",
    ))
    status, headers, body = parse(c.recv())
    assert status == "SIP/2.0 200 OK"
    assert headers["cseq"].endswith("REGISTER")
    c.close()


def test_invite_flow(server):
    c = SipClient(server)
    sdp = "v=0\r\no=alice 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n"
    c.request("INVITE", f"sip:bob@{HOST}", body=sdp)
    r1 = c.recv()
    assert r1.startswith("SIP/2.0 180 Ringing")
    status, headers, _ = parse(r1)
    assert headers["cseq"].endswith("INVITE")
    # to-tag present
    assert "tag=" in headers["to"]

    r2 = c.recv()
    status, headers, body = parse(r2)
    assert status == "SIP/2.0 200 OK"
    assert headers["content-type"] == "application/sdp"
    assert headers["content-length"] == str(len(body))
    assert body.startswith("v=0")
    remote_tag = headers["to"].split("tag=")[1]

    # ACK for 2xx
    c.next_branch()
    c.request("ACK", f"sip:bob@{HOST}", to_tag=remote_tag)

    # BYE: server acks with 200
    c.next_branch()
    c.request("BYE", f"sip:bob@{HOST}", to_tag=remote_tag)
    status, _, _ = parse(c.recv())
    assert status == "SIP/2.0 200 OK"
    c.close()


def test_unknown_method(server):
    c = SipClient(server)
    c.next_branch()
    c.request("FOOBAR", f"sip:{HOST}")
    status, _, _ = parse(c.recv())
    assert status == "SIP/2.0 501 Not Implemented"
    c.close()


def test_compact_headers(server):
    c = SipClient(server)
    c.next_branch()
    c.request("OPTIONS", f"sip:{HOST}", compact=True)
    status, headers, _ = parse(c.recv())
    assert status == "SIP/2.0 200 OK"
    c.close()


def test_folded_header(server):
    c = SipClient(server)
    c.next_branch()
    c.seq += 1
    raw = (
        f"OPTIONS sip:{HOST} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {HOST}:{c.addr[1]};branch={c.branch}\r\n"
        f"From: <sip:alice@{HOST}>;tag={c.from_tag}\r\n"
        f"To: <sip:{HOST}>\r\n"
        f"Call-ID: {c.cid}\r\n"
        f"CSeq: {c.seq} OPTIONS\r\n"
        f"Subject: folded\r\n subject header\r\n"
        f"Content-Length: 0\r\n\r\n"
    )
    c.send(raw.encode())
    status, headers, _ = parse(c.recv())
    assert status == "SIP/2.0 200 OK"
    c.close()


def test_tcp_options(server):
    c = SipClient(server, transport="tcp")
    c.next_branch()
    c.request("OPTIONS", f"sip:{HOST}")
    status, headers, _ = parse(c.recv())
    assert status == "SIP/2.0 200 OK"
    assert headers["via"].startswith("SIP/2.0/TCP")
    c.close()


def test_tcp_two_messages_one_connection(server):
    c = SipClient(server, transport="tcp")
    c.request("OPTIONS", f"sip:{HOST}")
    assert parse(c.recv())[0] == "SIP/2.0 200 OK"
    c.next_branch()
    c.request("REGISTER", f"sip:{HOST}", headers=("Contact: <sip:alice@127.0.0.1>;expires=60", "Expires: 60"))
    assert parse(c.recv())[0] == "SIP/2.0 200 OK"
    c.close()
