# tinyscanner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `tinyscanner`, a tiny stdlib-only Python port scanner that reports each scanned port as open or closed and shows the service name on open ports.

**Architecture:** Two modules: `scanner.py` holds the pure/network logic (port-spec parsing, service lookup, TCP/UDP scans) and `tinyscanner.py` is the CLI entry point (arg parsing, validation, output). `tests/` contains pytest suites. Both modules use only the Python standard library.

**Tech Stack:** Python 3.12, stdlib `socket`/`sys`, pytest 9.x for tests. Run Python via `py -3.12` (the `python` on PATH is msys2 without pip/pytest). Windows is the target platform.

## Global Constraints

- Target platform: Windows. No admin privileges required (no raw sockets).
- Stdlib only in `scanner.py` and `tinyscanner.py` (no third-party imports).
- Port range valid values: 1-65535.
- Default protocol: TCP when neither `-t` nor `-u` is given. Passing both `-t` and `-u` is an error.
- Port may be given positionally or via `-p`, but not both.
- Output lines exactly: `Port <n> is open`, `Port <n> is open (<service>)`, `Port <n> is closed`.
- `--help` prints exactly:
  ```
  Usage: tinyscanner [OPTIONS] [HOST] [PORT]
  Options:
    -p               Range of ports to scan
    -u               UDP scan
    -t               TCP scan
    --help           Show this message and exit.
  ```
- Exit code 0 on success, non-zero on usage/scan errors.
- Test commands use `py -3.12 -m pytest ...` because `python` resolves to msys2 without pytest.

---

### Task 1: Project scaffolding + port spec parsing + service lookup

**Files:**
- Create: `pytest.ini`
- Create: `scanner.py`
- Create: `tests/test_scanner.py`

**Interfaces:**
- Produces:
  - `parse_port_spec(spec: str) -> list[int]` — expands `"80"` -> `[80]`, `"80-83"` -> `[80, 81, 82, 83]`. Raises `ValueError` on malformed input or out-of-range (not 1..65535) / inverted ranges.
  - `service_name(port: int, proto: str) -> str | None` — returns the service name, `None` if unknown.
  - `_FALLBACK_SERVICES: dict[int, str]` module constant.

- [ ] **Step 1: Write `pytest.ini` and the failing tests**

Create `pytest.ini` (adds project root to `sys.path` so `import scanner` works):

```ini
[pytest]
pythonpath = .
```

Create `tests/test_scanner.py`:

```python
import pytest

from scanner import parse_port_spec, service_name


@pytest.mark.parametrize("spec,expected", [
    ("80", [80]),
    ("1", [1]),
    ("65535", [65535]),
    ("80-83", [80, 81, 82, 83]),
    ("80-80", [80]),
    ("1-65535", list(range(1, 65536))),
])
def test_parse_port_spec_valid(spec, expected):
    assert parse_port_spec(spec) == expected


@pytest.mark.parametrize("spec", ["0", "65536", "abc", "80-", "-80", "90-80", "80-83-84", "80-abc"])
def test_parse_port_spec_invalid(spec):
    with pytest.raises(ValueError):
        parse_port_spec(spec)


def test_service_name_http():
    assert service_name(80, "tcp") == "http"


def test_service_name_known_by_system_or_fallback():
    assert service_name(5432, "tcp") == "postgresql"


def test_service_name_unknown_returns_none():
    assert service_name(62345, "tcp") is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `py -3.12 -m pytest tests/test_scanner.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'scanner'`.

- [ ] **Step 3: Write the minimal implementation**

Create `scanner.py`:

```python
"""Core scanning logic for tinyscanner."""

import socket

_FALLBACK_SERVICES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    80: "http",
    110: "pop3",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    993: "imaps",
    995: "pop3s",
    1433: "ms-sql-s",
    3306: "mysql",
    3389: "ms-wbt-server",
    5432: "postgresql",
    8080: "http-alt",
    8443: "https-alt",
    27017: "mongod",
}


def parse_port_spec(spec):
    """Expand a port spec like '80' or '80-83' into a list of ports.

    Raises ValueError if the spec is malformed, a port is outside 1-65535,
    or the range start is greater than its end.
    """
    if "-" in spec:
        start_str, end_str = spec.split("-", 1)
        start = int(start_str)
        end = int(end_str)
        if start < 1 or end > 65535 or start > end:
            raise ValueError(f"invalid port range '{spec}'")
        return list(range(start, end + 1))
    port = int(spec)
    if port < 1 or port > 65535:
        raise ValueError(f"invalid port '{spec}'")
    return [port]


def service_name(port, proto):
    """Return the service name for a port/protocol, or None if unknown."""
    try:
        return socket.getservbyport(port, proto)
    except OSError:
        return _FALLBACK_SERVICES.get(port)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `py -3.12 -m pytest tests/test_scanner.py -v`
Expected: PASS (15 tests).

- [ ] **Step 5: Commit**

```bash
git add pytest.ini scanner.py tests/test_scanner.py
git commit -m "feat: add port spec parsing and service lookup"
```

---

### Task 2: TCP and UDP scan functions

**Files:**
- Modify: `scanner.py` (add `DEFAULT_TIMEOUT`, `scan_tcp`, `scan_udp`)
- Modify: `tests/test_scanner.py` (append scan tests)

**Interfaces:**
- Consumes: nothing new (uses stdlib `socket`).
- Produces:
  - `DEFAULT_TIMEOUT: float` = `1.0`
  - `scan_tcp(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> bool` — True if TCP connect succeeds, False otherwise.
  - `scan_udp(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> bool` — True if a reply arrives or nothing is heard (open/filtered), False if ICMP port-unreachable surfaces.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_scanner.py`:

```python
import socket
import threading

import pytest

from scanner import parse_port_spec, scan_tcp, scan_udp, service_name


@pytest.fixture
def open_tcp_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    yield srv
    srv.close()


@pytest.fixture
def udp_echo_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    stop = threading.Event()

    def _serve():
        while not stop.is_set():
            try:
                srv.settimeout(0.2)
                data, addr = srv.recvfrom(1024)
                srv.sendto(data, addr)
            except socket.timeout:
                continue
            except OSError:
                break

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    yield port
    stop.set()
    srv.close()
    thread.join(timeout=1)


def _unbound_tcp_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _unbound_udp_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_scan_tcp_open(open_tcp_server):
    port = open_tcp_server.getsockname()[1]
    assert scan_tcp("127.0.0.1", port, timeout=0.5) is True


def test_scan_tcp_closed():
    assert scan_tcp("127.0.0.1", _unbound_tcp_port(), timeout=0.5) is False


def test_scan_udp_open(udp_echo_server):
    assert scan_udp("127.0.0.1", udp_echo_server, timeout=0.5) is True


def test_scan_udp_closed():
    assert scan_udp("127.0.0.1", _unbound_udp_port(), timeout=0.5) is False
```

Note the existing import line `from scanner import parse_port_spec, service_name` is replaced by the one above.

- [ ] **Step 2: Run tests to verify the new ones fail**

Run: `py -3.12 -m pytest tests/test_scanner.py -v`
Expected: 15 pass (from Task 1), 4 FAIL with `ImportError: cannot import name 'scan_tcp'`.

- [ ] **Step 3: Write the minimal implementation**

Append to `scanner.py`:

```python
DEFAULT_TIMEOUT = 1.0


def scan_tcp(host, port, timeout=DEFAULT_TIMEOUT):
    """Return True if the TCP port is open, False otherwise."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def scan_udp(host, port, timeout=DEFAULT_TIMEOUT):
    """Return True if the UDP port is open (or filtered), False if closed.

    Uses a connected UDP socket so ICMP port-unreachable is surfaced as an
    OSError (ConnectionRefusedError on POSIX, ConnectionResetError on Windows).
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        sock.send(b"")
        try:
            sock.recv(1024)
            return True
        except (ConnectionRefusedError, ConnectionResetError):
            return False
        except socket.timeout:
            return True
    except OSError:
        return False
    finally:
        sock.close()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `py -3.12 -m pytest tests/test_scanner.py -v`
Expected: PASS (19 tests).

- [ ] **Step 5: Commit**

```bash
git add scanner.py tests/test_scanner.py
git commit -m "feat: add tcp and udp scan functions"
```

---

### Task 3: CLI entry point (`tinyscanner.py`)

**Files:**
- Create: `tinyscanner.py`
- Create: `tests/test_cli.py`

**Interfaces:**
- Consumes: `parse_port_spec`, `scan_tcp`, `scan_udp`, `service_name`, `DEFAULT_TIMEOUT` from `scanner.py` (Tasks 1-2).
- Produces:
  - `main(argv: list[str] | None = None) -> int` — parses args, scans, prints results, returns exit code. `None` means `sys.argv[1:]`.
  - `USAGE: str` module constant with the exact help text.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_cli.py`:

```python
import socket

import pytest

from tinyscanner import main


@pytest.fixture
def open_tcp_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    yield srv
    srv.close()


def _unbound_tcp_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _unbound_udp_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_help(capsys):
    rc = main(["--help"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Usage: tinyscanner [OPTIONS] [HOST] [PORT]" in out
    assert "  -p               Range of ports to scan" in out
    assert "  -u               UDP scan" in out
    assert "  -t               TCP scan" in out


def test_scan_open_port(capsys, open_tcp_server):
    port = open_tcp_server.getsockname()[1]
    rc = main(["-t", "127.0.0.1", "-p", str(port)])
    out = capsys.readouterr().out.strip()
    assert rc == 0
    assert out == f"Port {port} is open"


def test_scan_closed_port(capsys):
    port = _unbound_tcp_port()
    rc = main(["-t", "127.0.0.1", "-p", str(port)])
    out = capsys.readouterr().out.strip()
    assert rc == 0
    assert out == f"Port {port} is closed"


def test_scan_range(capsys):
    port = _unbound_tcp_port()
    rc = main(["-t", "127.0.0.1", "-p", f"{port}-{port + 1}"])
    lines = capsys.readouterr().out.strip().splitlines()
    assert rc == 0
    assert lines == [f"Port {port} is closed", f"Port {port + 1} is closed"]


def test_positional_port(capsys):
    port = _unbound_tcp_port()
    rc = main(["-t", "127.0.0.1", str(port)])
    out = capsys.readouterr().out.strip()
    assert rc == 0
    assert out == f"Port {port} is closed"


def test_udp_closed_port(capsys):
    port = _unbound_udp_port()
    rc = main(["-u", "127.0.0.1", "-p", str(port)])
    out = capsys.readouterr().out.strip()
    assert rc == 0
    assert out == f"Port {port} is closed"


def test_default_protocol_is_tcp(capsys):
    port = _unbound_tcp_port()
    rc = main(["127.0.0.1", "-p", str(port)])
    out = capsys.readouterr().out.strip()
    assert rc == 0
    assert out == f"Port {port} is closed"


def test_both_protocols_is_error(capsys):
    rc = main(["-t", "-u", "127.0.0.1", "-p", "80"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "tinyscanner:" in err


def test_missing_host(capsys):
    rc = main(["-t", "-p", "80"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "missing HOST" in err


def test_missing_port(capsys):
    rc = main(["-t", "127.0.0.1"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "missing PORT" in err


def test_port_given_twice(capsys):
    rc = main(["-t", "127.0.0.1", "80", "-p", "81"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "both" in err


def test_unknown_option(capsys):
    rc = main(["-x", "127.0.0.1", "-p", "80"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "unknown option" in err


def test_unresolvable_host(capsys):
    rc = main(["-t", "256.256.256.256", "-p", "80"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "unable to resolve host" in err
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `py -3.12 -m pytest tests/test_cli.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'tinyscanner'`.

- [ ] **Step 3: Write the minimal implementation**

Create `tinyscanner.py`:

```python
"""tinyscanner: a tiny command-line port scanner."""

import socket
import sys

from scanner import DEFAULT_TIMEOUT, parse_port_spec, scan_tcp, scan_udp, service_name

USAGE = """Usage: tinyscanner [OPTIONS] [HOST] [PORT]
Options:
  -p               Range of ports to scan
  -u               UDP scan
  -t               TCP scan
  --help           Show this message and exit.
"""


def _fail(message):
    print(f"tinyscanner: {message}", file=sys.stderr)
    return 1


def main(argv=None):
    args = list(argv) if argv is not None else sys.argv[1:]

    if "--help" in args:
        sys.stdout.write(USAGE)
        return 0

    tcp = False
    udp = False
    port_spec = None
    host = None
    positional = []

    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "-p":
            if i + 1 >= len(args):
                return _fail("option '-p' requires an argument")
            if port_spec is not None:
                return _fail("option '-p' given more than once")
            port_spec = args[i + 1]
            i += 2
        elif arg == "-u":
            udp = True
            i += 1
        elif arg == "-t":
            tcp = True
            i += 1
        elif arg.startswith("-"):
            return _fail(f"unknown option '{arg}'")
        elif host is None:
            host = arg
            i += 1
        else:
            positional.append(arg)
            i += 1

    if tcp and udp:
        return _fail("cannot scan both TCP and UDP at once (choose -t or -u)")

    if host is None:
        return _fail("missing HOST argument")

    if port_spec is not None and positional:
        return _fail("port given both positionally and via '-p'")
    if len(positional) > 1:
        return _fail("too many arguments")
    spec = port_spec if port_spec is not None else (positional[0] if positional else None)
    if spec is None:
        return _fail("missing PORT argument")

    try:
        ports = parse_port_spec(spec)
    except ValueError as exc:
        return _fail(str(exc))

    proto = "udp" if udp else "tcp"

    try:
        socket.gethostbyname(host)
    except socket.gaierror:
        return _fail(f"unable to resolve host '{host}'")

    scan = scan_udp if udp else scan_tcp
    for port in ports:
        is_open = scan(host, port, DEFAULT_TIMEOUT)
        if is_open:
            line = f"Port {port} is open"
            name = service_name(port, proto)
            if name:
                line += f" ({name})"
        else:
            line = f"Port {port} is closed"
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `py -3.12 -m pytest tests/test_cli.py tests/test_scanner.py -v`
Expected: PASS (19 scanner tests + 13 CLI tests).

- [ ] **Step 5: Commit**

```bash
git add tinyscanner.py tests/test_cli.py
git commit -m "feat: add tinyscanner cli"
```

---

### Task 4: README and final verification

**Files:**
- Create: `README.md`

- [ ] **Step 1: Write the README**

Create `README.md`:

```markdown
# tinyscanner

A tiny command-line port scanner written in Python (standard library only). It
tells you whether each scanned port is open or closed, and shows the name of
the service running on open ports.

> For educational purposes only. Only scan machines you own or have explicit
> permission to test.

## Requirements

- Python 3.8+
- pytest (optional, for the tests)

## Usage

```
tinyscanner [OPTIONS] [HOST] [PORT]
```

Options:

| Option     | Description                |
| ---------- | -------------------------- |
| `-p`       | Port or range (e.g. `80` or `80-83`) |
| `-u`       | UDP scan                   |
| `-t`       | TCP scan                   |
| `--help`   | Show usage and exit        |

If neither `-t` nor `-u` is given, the scan defaults to TCP. The port may be
given positionally instead of via `-p`.

## Examples

```bash
python tinyscanner.py --help
python tinyscanner.py -t 127.0.0.1 -p 80
python tinyscanner.py -t 10.53.224.5 -p 80-83
python tinyscanner.py -u 127.0.0.1 -p 53
```

Output:

```
Port 80 is open (http)
Port 81 is closed
```

## How it works

- **TCP:** a `connect()` attempt is made with a timeout. Success means the port
  is open; refusal, timeout, or unreachable means closed.
- **UDP:** an empty datagram is sent over a connected UDP socket. A reply (or a
  timeout, i.e. a filtered port) counts as open; an ICMP port-unreachable error
  means closed.
- **Services:** `socket.getservbyport()` is used first, with a built-in fallback
  table for well-known ports.

## Running the tests

```bash
pip install pytest
pytest
```
```

- [ ] **Step 2: Run the full test suite**

Run: `py -3.12 -m pytest -v`
Expected: PASS (32 tests).

- [ ] **Step 3: Manual smoke test**

Run each command and confirm the output:

```bash
py -3.12 tinyscanner.py --help
py -3.12 tinyscanner.py -t 127.0.0.1 -p 80
py -3.12 tinyscanner.py -t 127.0.0.1 -p 80-83
py -3.12 tinyscanner.py -u 127.0.0.1 -p 9
```

Expected: help prints the usage text; TCP scans print `Port <n> is open` /
`Port <n> is closed`; the UDP scan on port 9 (discard) prints its verdict.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: add tinyscanner readme"
```

---

## Self-Review

- **Spec coverage:** CLI options (`-p`, `-u`, `-t`, `--help`) in Task 3; TCP scan in Task 2; UDP ICMP heuristic in Task 2; service bonus in Task 1 + Task 3 output; exact output format in Tasks 3-4; README in Task 4; error handling and non-zero exits in Task 3; range parsing in Task 1. No gaps.
- **Placeholder scan:** no TBD/TODO; every step has complete code or exact commands.
- **Type consistency:** `parse_port_spec` -> `list[int]`, `service_name` -> `str | None`, `scan_tcp`/`scan_udp` -> `bool` with `timeout` kwarg, `main` -> `int`. Used identically across tasks.
