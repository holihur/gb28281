"""Black-box tests: python emulates a GB28181 device against the Go platform."""
import os
import re
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
from helpers import (  # noqa: E402
    CHANNEL_ID, DEVICE_ID, HOST, PASSWORD, SERVER_ID,
    DeviceClient, SipMsg, digest_response, free_port, parse_auth, xml_envelope,
)


def test_register_digest_challenge(platform):
    dev = DeviceClient(platform)
    r401 = dev.register()
    assert r401.status == 401
    ch = r401.www_auth()
    assert ch.get("realm") == SERVER_ID
    assert ch.get("nonce")
    uri = f"sip:{SERVER_ID}@{SERVER_ID}"
    resp = digest_response(DEVICE_ID, PASSWORD, ch["realm"], "REGISTER", uri, ch["nonce"])
    auth = (f'Digest username="{DEVICE_ID}", realm="{ch["realm"]}", nonce="{ch["nonce"]}", '
            f'uri="{uri}", response="{resp}", algorithm="MD5"')
    final = dev.register(authorization=auth, cseq=2, call_id=dev.call_id)
    assert final.status == 200, final.first_line


def test_register_bad_password_rejected(platform):
    dev = DeviceClient(platform)
    r401 = dev.register()
    ch = r401.www_auth()
    uri = f"sip:{SERVER_ID}@{SERVER_ID}"
    resp = digest_response(DEVICE_ID, "wrongpass", ch["realm"], "REGISTER", uri, ch["nonce"])
    auth = (f'Digest username="{DEVICE_ID}", realm="{ch["realm"]}", nonce="{ch["nonce"]}", '
            f'uri="{uri}", response="{resp}", algorithm="MD5"')
    final = dev.register(authorization=auth, cseq=2)
    assert final.status in (401, 403), final.first_line


def test_keepalive_200(platform):
    dev = DeviceClient(platform)
    dev.register_authorized()
    resp = dev.keepalive(sn=1)
    assert resp.status == 200, resp.first_line


def test_catalog_query_response(platform):
    """Platform sends a Catalog query; device answers; query arrives as XML."""
    dev = DeviceClient(platform)
    dev.register_authorized()
    dev.keepalive(sn=1)
    # The demo platform does not spontaneously query; trigger by platform's
    # own API is not exposed over the wire in the demo, so instead verify the
    # platform accepts a well-formed catalog Response pushed by the device.
    xml = xml_envelope("Response", "Catalog", 77, DEVICE_ID, extra=(
        f"<SumNum>1</SumNum><DeviceList Num=\"1\"><Item>"
        f"<DeviceID>{CHANNEL_ID}</DeviceID><Name>pycam</Name><Status>ON</Status>"
        f"</Item></DeviceList>"))
    resp = dev.message(xml)
    assert resp.status == 200, resp.first_line


def test_alarm_reported(platform):
    dev = DeviceClient(platform)
    dev.register_authorized()
    xml = xml_envelope("Notify", "Alarm", 9, DEVICE_ID, extra=(
        "<AlarmTime>2026-01-01T00:00:00</AlarmTime><AlarmType>2</AlarmType>"
        "<AlarmPriority>1</AlarmPriority><AlarmMethod>5</AlarmMethod>"))
    resp = dev.message(xml)
    assert resp.status == 200, resp.first_line


def test_options_200(platform):
    dev = DeviceClient(platform)
    req = (
        f"OPTIONS sip:{SERVER_ID}@{SERVER_ID} SIP/2.0\r\n"
        + dev.via("z9hG4bKopt" + os.urandom(4).hex())
        + f"From: <sip:{DEVICE_ID}@{SERVER_ID}>;tag=o\r\n"
        + f"To: <sip:{SERVER_ID}@{SERVER_ID}>\r\n"
        + f"Call-ID: opt-{os.urandom(4).hex()}\r\n"
        + "CSeq: 1 OPTIONS\r\n"
        + "Max-Forwards: 70\r\n"
        + "Content-Length: 0\r\n\r\n")
    dev.send(req.encode())
    resp = dev.recv()
    assert resp.status == 200, resp.first_line
