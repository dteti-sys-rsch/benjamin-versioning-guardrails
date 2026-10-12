"""All core tests are offline, including SDK tests using mock transports."""
import socket
import threading
import pytest


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs): raise AssertionError("core tests must not use network")
    # Windows asyncio builds its internal wakeup socketpair over loopback.
    # Permit only that library construction, not arbitrary loopback/API clients.
    pair, connect = socket.socketpair, socket.socket.connect
    local = threading.local()
    def local_pair(*args, **kwargs):
        local.creating_pair = True
        try: return pair(*args, **kwargs)
        finally: local.creating_pair = False
    def guarded_connect(sock, address):
        if getattr(local, "creating_pair", False): return connect(sock, address)
        return blocked()
    monkeypatch.setattr(socket, "socketpair", local_pair)
    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
