import os
import signal
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from helpers import SERVER_ID, build, free_port, spawn


@pytest.fixture(scope="session")
def platform():
    """Go platform under test; python acts as a device."""
    build()
    port = free_port()
    proc = spawn(["-mode", "platform", "-port", str(port), "-server-id", SERVER_ID],
                    wait_line="listening")
    yield port
    proc.send_signal(signal.SIGTERM)
    proc.wait(timeout=5)
