"""Ground-truth tests: every expectation is built from sockets we control."""

import asyncio
import errno
import os
import socket
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import port_scanner as ps  # noqa: E402

# RFC 5737 TEST-NET-1: never routed, so connects get silence or "unreachable"
BLACKHOLE = "192.0.2.1"


@pytest.fixture
def listeners():
    """Open ports we own; yields the list of ports, closes on teardown"""
    socks = []
    for _ in range(3):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        s.listen(128)
        socks.append(s)
    yield [s.getsockname()[1] for s in socks]
    for s in socks:
        s.close()


def free_ports(count):
    """Ports that were free a moment ago (bound then released)"""
    socks = [socket.socket() for _ in range(count)]
    for s in socks:
        s.bind(("127.0.0.1", 0))
    ports = [s.getsockname()[1] for s in socks]
    for s in socks:
        s.close()
    return ports


def quiet_scan(scanner, capsys):
    scanner.scan()
    capsys.readouterr()
    return scanner


# -- parse_ports -------------------------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("80", [80]),
    ("80,443,8080", [80, 443, 8080]),
    ("1-5", [1, 2, 3, 4, 5]),
    (" 22 , 80-82 ,22", [22, 80, 81, 82]),
    ("1-65535", list(range(1, 65536))),
    ("65535", [65535]),
])
def test_parse_ports_valid(text, expected):
    assert ps.parse_ports(text) == expected


@pytest.mark.parametrize("text", [
    "500-100",      # reversed: must not silently become the default range
    "0", "65536", "99999", "-5", "0-10", "1-65536",
    "", "80,", ",80", "abc", "80-abc", "1-2-3", "8 0",
])
def test_parse_ports_invalid(text):
    with pytest.raises(ValueError):
        ps.parse_ports(text)


# -- constructor -------------------------------------------------------------

def test_empty_ports_is_error_not_default():
    with pytest.raises(ValueError):
        ps.PortScanner("127.0.0.1", ports=[])


def test_default_ports_are_1_to_1024():
    assert ps.PortScanner("127.0.0.1").ports == list(range(1, 1025))


@pytest.mark.parametrize("kwargs", [
    {"ports": [0]}, {"ports": [65536]}, {"ports": ["80"]},
    {"scan_type": "syn"}, {"scan_type": "udp"},
    {"concurrency": 0}, {"timeout": 0}, {"retries": -1},
])
def test_constructor_rejects_bad_input(kwargs):
    with pytest.raises(ValueError):
        ps.PortScanner("127.0.0.1", **kwargs)


def test_unresolvable_target_rejected():
    with pytest.raises(ValueError):
        ps.PortScanner("no-such-host.invalid", ports=[80])


def test_legacy_threads_argument_still_works():
    assert ps.PortScanner("127.0.0.1", ports=[80], threads=7).concurrency == 7


# -- error classification ----------------------------------------------------

def os_error(code, winerror=None):
    e = OSError(code, "x")
    if winerror is not None:
        e.winerror = winerror
    return e


@pytest.mark.parametrize("exc,state", [
    (ConnectionRefusedError(), ps.CLOSED),
    (ConnectionResetError(), ps.CLOSED),
    (os_error(errno.ECONNREFUSED), ps.CLOSED),
    (os_error(22, 1225), ps.CLOSED),              # Windows ConnectEx refusal
    (asyncio.TimeoutError(), ps.FILTERED),
    (os_error(errno.EHOSTUNREACH), ps.FILTERED),
    (os_error(errno.ENETUNREACH), ps.FILTERED),
    (os_error(errno.ETIMEDOUT), ps.FILTERED),
    (os_error(22, 121), ps.FILTERED),             # Windows SYN timeout
    (os_error(22, 10060), ps.FILTERED),
    (os_error(errno.EMFILE), ps.ERROR),           # out of sockets: never "closed"
    (os_error(errno.ENOBUFS), ps.ERROR),
    (os_error(errno.EADDRNOTAVAIL), ps.ERROR),
    (os_error(22, 10055), ps.ERROR),              # WSAENOBUFS
    (PermissionError(13, "denied"), ps.ERROR),
    (os_error(errno.EIO), ps.ERROR),              # unknown: unknown, not closed
])
def test_classify_connect_error(exc, state):
    assert ps.classify_connect_error(exc)[0] == state


# -- scanning against ground truth ------------------------------------------

def test_open_and_closed_exact(listeners, capsys):
    closed = free_ports(20)
    ports = sorted(set(listeners) | set(closed))
    s = quiet_scan(ps.PortScanner("127.0.0.1", ports=ports, timeout=2), capsys)
    assert sorted(s.open_ports) == sorted(listeners)
    assert {p for p, st in s.results.items() if st == ps.CLOSED} == set(closed) - set(listeners)
    assert s.count(ps.FILTERED) == 0 and s.count(ps.ERROR) == 0


def test_every_port_gets_a_state(listeners, capsys):
    ports = sorted(listeners + free_ports(10))
    s = quiet_scan(ps.PortScanner("127.0.0.1", ports=ports), capsys)
    assert set(s.results) == set(ports)


def test_open_port_found_among_many_closed_at_high_concurrency(listeners, capsys):
    target = listeners[0]
    ports = list(range(max(1, target - 1500), min(65535, target + 1500) + 1))
    expected = sorted(set(ports) & set(listeners))
    s = quiet_scan(ps.PortScanner("127.0.0.1", ports=ports, concurrency=1000, timeout=2),
                   capsys)
    assert sorted(s.open_ports) == expected
    assert s.count(ps.ERROR) == 0


def test_closed_ports_not_misread_as_filtered_with_short_timeout(capsys):
    """Windows used to take ~2 s to refuse; a short timeout then said 'filtered'"""
    s = quiet_scan(ps.PortScanner("127.0.0.1", ports=free_ports(10), timeout=0.5,
                                  retries=0), capsys)
    assert s.count(ps.CLOSED) == 10


def test_blackhole_is_filtered_never_closed_or_open(capsys):
    s = quiet_scan(ps.PortScanner(BLACKHOLE, ports=[22, 80, 443], timeout=0.4,
                                  retries=1), capsys)
    assert s.open_ports == []
    assert s.count(ps.CLOSED) == 0
    assert s.count(ps.FILTERED) == 3


def test_blackhole_scan_time_is_bounded_by_concurrency(capsys):
    import time
    ports = list(range(20000, 20200))  # not 113: some gateways RST ident
    t = time.time()
    s = quiet_scan(ps.PortScanner(BLACKHOLE, ports=ports, concurrency=200,
                                  timeout=0.5, retries=0), capsys)
    # 200 ports all in flight at once: about one timeout, not 200 x timeout
    assert time.time() - t < 3
    assert s.count(ps.FILTERED) == 200


def test_resource_exhaustion_is_retried_and_never_closed(listeners, monkeypatch, capsys):
    """First attempt per port fails like EMFILE; the retry must find the open port"""
    s = ps.PortScanner("127.0.0.1", ports=listeners, timeout=2)
    real = s._connect
    seen = set()

    async def flaky(loop, port):
        if port not in seen:
            seen.add(port)
            return ps.classify_connect_error(os_error(errno.EMFILE))
        return await real(loop, port)

    monkeypatch.setattr(s, "_connect", flaky)
    quiet_scan(s, capsys)
    assert sorted(s.open_ports) == sorted(listeners)


def test_persistent_resource_error_reported_as_error(monkeypatch, capsys):
    s = ps.PortScanner("127.0.0.1", ports=[9], timeout=1)

    async def always_emfile(loop, port):
        return ps.classify_connect_error(os_error(errno.EMFILE))

    monkeypatch.setattr(s, "_connect", always_emfile)
    quiet_scan(s, capsys)
    assert s.results[9] == ps.ERROR
    assert s.count(ps.CLOSED) == 0


def test_ipv6_loopback(capsys):
    try:
        srv = socket.socket(socket.AF_INET6)
        srv.bind(("::1", 0))
    except OSError:
        pytest.skip("IPv6 loopback unavailable")
    srv.listen(8)
    try:
        port = srv.getsockname()[1]
        s = quiet_scan(ps.PortScanner("::1", ports=[port]), capsys)
        assert s.open_ports == [port]
    finally:
        srv.close()


# -- CLI ---------------------------------------------------------------------

def run_cli(*args):
    return subprocess.run([sys.executable, os.path.join(ROOT, "port_scanner.py"), *args],
                          capture_output=True, text=True, encoding="utf-8", timeout=60)


def test_cli_output_has_no_ansi_when_piped(listeners):
    r = run_cli("127.0.0.1", "-p", str(listeners[0]))
    assert r.returncode == 0
    assert "\x1b" not in r.stdout
    assert f"{listeners[0]}/tcp open" in r.stdout


@pytest.mark.parametrize("ports", ["500-100", "0", "99999", "abc"])
def test_cli_bad_ports_exit_nonzero_and_scan_nothing(ports):
    r = run_cli("127.0.0.1", "-p", ports)
    assert r.returncode == 1
    assert "Invalid port specification" in r.stdout
    assert "Ports scanned" not in r.stdout


def test_cli_bad_target_exits_nonzero():
    r = run_cli("no-such-host.invalid", "-p", "80")
    assert r.returncode == 1


def test_cli_legacy_threads_flag_accepted(listeners):
    r = run_cli("127.0.0.1", "-p", str(listeners[0]), "-t", "50")
    assert r.returncode == 0 and f"{listeners[0]}/tcp open" in r.stdout
