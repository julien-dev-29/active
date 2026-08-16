# dictattack Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend `tinyscanner` with a `--dict-auth` option that, after a TCP scan, runs a dictionary attack against each open port that speaks the local `authserver` USER/PASS protocol, trying passwords from a dictionary file.

**Architecture:** `dictattack.py` holds the attack logic (service probing + password guessing over the authserver protocol), mirroring how `scanner.py` holds the scan logic. `tinyscanner.py` gains `--dict-auth`, `--user`, `--dict` options, collects open ports during the scan, then attacks them via `dictattack`. The authserver and `scanner.py` are NOT modified.

**Tech Stack:** Python 3.12, stdlib `socket`/`sys`, pytest 9.x. Run Python via `py -3.12` (the `python` on PATH is msys2 without pytest). Windows is the target platform.

## Global Constraints

- Target platform: Windows. Educational use on 127.0.0.1 only.
- Stdlib only in `dictattack.py` (no third-party imports).
- `scanner.py` and `authserver/` are NOT modified by this plan.
- The local authserver must answer `PASS OK` / `PASS FAILED` for the attack to work. If the pre-flight check in Task 2 fails, the authserver is broken (its `LoginServer` currently logs with a `_log` method) — stop and ask the repository owner to fix it; do NOT modify `authserver/server.py` yourself.
- Test commands use `py -3.12 -m pytest ...` because `python` resolves to msys2 without pytest.
- New output lines (result only, no progress spam):
  - success: `Port <port>: password for <user> is '<password>' (attempt <n>)`
  - failure: `Port <port>: no password found for <user> (<n> attempts)`
- Exit code 0 on scan/attack completion (found or not), 1 on usage/argument/dictionary errors.

---

### Task 1: pytest.ini + `probe_service`

**Files:**
- Create: `pytest.ini`
- Create: `dictattack.py`
- Create: `tests/test_dictattack.py`

**Interfaces:**
- Produces:
  - `AUTHSERVER_BANNER: str` = `"authserver 1.0"` (module constant).
  - `probe_service(host: str, port: int, timeout: float) -> bool` — connects over TCP, reads the first line; returns `True` if the banner starts with `"authserver"`, `False` on any OSError or different banner.
- Consumes: `tests/` helper servers built inline (raw sockets, stdlib only).

- [ ] **Step 1: Write `pytest.ini` and the failing tests**

Create `pytest.ini` (puts the repo root AND `authserver/` on `sys.path`, so `import scanner`/`dictattack`/`tinyscanner`/`server` all work):

```ini
[pytest]
pythonpath = . authserver
```

Create `tests/test_dictattack.py`:

```python
import socket
import threading
import time

import pytest

import dictattack

TIMEOUT = 2.0


def unused_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class HelloServer:
    """A TCP server that sends a non-authserver banner on connect."""

    def __init__(self, banner="hello world"):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.banner = banner
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        try:
            conn, _ = self.sock.accept()
        except OSError:
            return
        try:
            conn.sendall((self.banner + "\n").encode())
        finally:
            conn.close()
            self.sock.close()

    @property
    def addr(self):
        return "127.0.0.1", self.port


def test_probe_service_authserver_banner():
    srv = HelloServer(banner=dictattack.AUTHSERVER_BANNER)
    time.sleep(0.05)
    assert dictattack.probe_service(*srv.addr, TIMEOUT) is True


def test_probe_service_other_banner_is_false():
    srv = HelloServer(banner="hello world")
    time.sleep(0.05)
    assert dictattack.probe_service(*srv.addr, TIMEOUT) is False


def test_probe_service_closed_port_is_false():
    port = unused_port()
    assert dictattack.probe_service("127.0.0.1", port, TIMEOUT) is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `py -3.12 -m pytest tests/test_dictattack.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'dictattack'`.

- [ ] **Step 3: Write the minimal implementation**

Create `dictattack.py`:

```python
"""Dictionary attack logic for tinyscanner (educational, localhost only)."""

import socket

AUTHSERVER_BANNER = "authserver 1.0"


def probe_service(host, port, timeout):
    """Return True if host:port speaks the authserver USER/PASS protocol."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
        return banner.startswith("authserver")
    except OSError:
        return False
    finally:
        sock.close()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `py -3.12 -m pytest tests/test_dictattack.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add pytest.ini dictattack.py tests/test_dictattack.py
git commit -m "feat: add dictattack service probe"
```

---

### Task 2: `dict_attack` against the real authserver

**Files:**
- Modify: `dictattack.py` (add `dict_attack`)
- Modify: `tests/test_dictattack.py` (add authserver fixture + attack tests)

**Interfaces:**
- Consumes: `probe_service` (Task 1); the authserver's `LoginServer` (`authserver/server.py`) via `from server import LoginServer`.
- Produces:
  - `dict_attack(host: str, port: int, user: str, words: Iterable[str], timeout: float) -> tuple[str | None, int]` — opens ONE connection per port, sends `USER <user>`, then a `PASS <word>` per word on the same connection. Returns `(password, attempts)` where `password` is the first word answered `PASS OK` (or `None`) and `attempts` is the number of `PASS` commands sent.

- [ ] **Step 1: Pre-flight — verify the authserver answers PASS correctly**

Run:

```powershell
py -3.12 -c "import socket, threading, sys; sys.path.insert(0, 'authserver'); import server; users = server.load_users('authserver/users.conf'); srv = server.LoginServer(users, host='127.0.0.1', port=0); port = srv.start(); threading.Thread(target=srv.serve, daemon=True).start(); s = socket.create_connection(('127.0.0.1', port), timeout=3); print(s.recv(1024).decode().strip()); s.sendall(b'USER francis\n'); print(s.recv(1024).decode().strip()); s.sendall(b'PASS nope\n'); s.settimeout(2); print(s.recv(1024).decode().strip()); srv.stop()"
```

Expected: prints `authserver 1.0`, `USER OK`, `PASS FAILED` (in that order, no `AttributeError` traceback).

If this does NOT print exactly that (e.g. `AttributeError: 'LoginServer' object has no attribute '_log'`), STOP and ask the repository owner to fix `authserver/server.py`. Do NOT modify it yourself.

- [ ] **Step 2: Write the failing tests**

Append to `tests/test_dictattack.py`:

```python
import hashlib

from server import LoginServer


@pytest.fixture()
def authserver():
    salt = "00" * 16
    digest = hashlib.sha256((salt + "secret123").encode()).hexdigest()
    users = {"alice": (salt, digest)}
    srv = LoginServer(users, host="127.0.0.1", port=0)
    srv.start()
    thread = threading.Thread(target=srv.serve, daemon=True)
    thread.start()
    time.sleep(0.05)
    yield "127.0.0.1", srv.port
    srv.stop()
    thread.join(timeout=1)


def test_dict_attack_finds_password(authserver):
    host, port = authserver
    password, attempts = dictattack.dict_attack(
        host, port, "alice", ["nope1", "nope2", "secret123", "nope3"], TIMEOUT
    )
    assert password == "secret123"
    assert attempts == 3


def test_dict_attack_not_found(authserver):
    host, port = authserver
    password, attempts = dictattack.dict_attack(
        host, port, "alice", ["nope1", "nope2"], TIMEOUT
    )
    assert password is None
    assert attempts == 2


def test_dict_attack_unknown_user(authserver):
    host, port = authserver
    password, attempts = dictattack.dict_attack(host, port, "ghost", ["x"], TIMEOUT)
    assert password is None
    assert attempts == 0
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `py -3.12 -m pytest tests/test_dictattack.py -v`
Expected: FAIL with `AttributeError: module 'dictattack' has no attribute 'dict_attack'`.

- [ ] **Step 4: Write the minimal implementation**

Append to `dictattack.py`:

```python
def dict_attack(host, port, user, words, timeout):
    """Try each word in `words` as the password for `user`.

    Returns (password, attempts): the first word the server accepts, or None
    if none matched, plus the number of PASS attempts made.
    """
    attempts = 0
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        sock.recv(1024)
        sock.sendall(f"USER {user}\n".encode())
        if sock.recv(1024).decode().strip() != "USER OK":
            return None, attempts
        for word in words:
            attempts += 1
            sock.sendall(f"PASS {word}\n".encode())
            reply = sock.recv(1024).decode().strip()
            if reply == "PASS OK":
                return word, attempts
    except OSError:
        pass
    finally:
        sock.close()
    return None, attempts
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `py -3.12 -m pytest tests/test_dictattack.py -v`
Expected: PASS (3 probe tests + 3 attack tests).

- [ ] **Step 6: Commit**

```bash
git add dictattack.py tests/test_dictattack.py
git commit -m "feat: add dict_attack over authserver protocol"
```

---

### Task 3: `tinyscanner` CLI integration

**Files:**
- Modify: `tinyscanner.py`
- Create: `tests/test_tinyscanner_cli.py`

**Interfaces:**
- Consumes: `probe_service(host, port, timeout)` and `dict_attack(host, port, user, words, timeout)` from `dictattack.py` (Tasks 1-2); `DEFAULT_TIMEOUT` and the scan functions from `scanner.py`.
- Produces: new CLI surface — `--dict-auth`, `--user <name>`, `--dict <file>` (default `words.txt`); `load_words(path: str) -> list[str]`; the attack runs on every open port that `probe_service` accepts.

- [ ] **Step 1: Write the failing CLI tests**

Create `tests/test_tinyscanner_cli.py`:

```python
import hashlib
import threading
import time

import pytest

import tinyscanner
from server import LoginServer


@pytest.fixture()
def authserver():
    salt = "00" * 16
    digest = hashlib.sha256((salt + "secret123").encode()).hexdigest()
    users = {"alice": (salt, digest)}
    srv = LoginServer(users, host="127.0.0.1", port=0)
    srv.start()
    thread = threading.Thread(target=srv.serve, daemon=True)
    thread.start()
    time.sleep(0.05)
    yield srv.port
    srv.stop()
    thread.join(timeout=1)


def test_dict_auth_requires_user(capsys):
    rc = tinyscanner.main(["127.0.0.1", "9999", "--dict-auth"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "--user" in err


def test_dict_missing_file_fails_before_scan(capsys):
    rc = tinyscanner.main(
        ["127.0.0.1", "9999", "--dict-auth", "--user", "alice", "--dict", "no-such-dict.txt"]
    )
    err = capsys.readouterr().err
    assert rc == 1
    assert "cannot read dictionary" in err


def test_dict_empty_file_fails(tmp_path, capsys):
    d = tmp_path / "empty.txt"
    d.write_text("# nothing\n", encoding="utf-8")
    rc = tinyscanner.main(
        ["127.0.0.1", "9999", "--dict-auth", "--user", "alice", "--dict", str(d)]
    )
    err = capsys.readouterr().err
    assert rc == 1
    assert "is empty" in err


def test_full_attack_finds_password(authserver, tmp_path, capsys):
    d = tmp_path / "words.txt"
    d.write_text("nope\nsecret123\n", encoding="utf-8")
    rc = tinyscanner.main(
        ["127.0.0.1", str(authserver), "--dict-auth", "--user", "alice", "--dict", str(d)]
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert f"Port {authserver} is open" in out
    assert f"password for alice is 'secret123' (attempt 2)" in out


def test_full_attack_not_found(authserver, tmp_path, capsys):
    d = tmp_path / "words.txt"
    d.write_text("nope\nnope2\n", encoding="utf-8")
    rc = tinyscanner.main(
        ["127.0.0.1", str(authserver), "--dict-auth", "--user", "alice", "--dict", str(d)]
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "no password found for alice (2 attempts)" in out
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `py -3.12 -m pytest tests/test_tinyscanner_cli.py -v`
Expected: FAIL — `tinyscanner` rejects `--dict-auth` as `unknow option '--dict-auth'` (rc 1), so the `rc == 0` assertions in the attack tests fail.

- [ ] **Step 3: Write the minimal implementation**

Rewrite `tinyscanner.py`:

```python
import pyfiglet
import socket
import sys
from passlib.context import CryptContext
import dictattack
from scanner import DEFAULT_TIMEOUT, scan_tcp, scan_udp, parse_port_spec, service_name

USAGE = """Usage: tinyscanner [OPTIONS] [HOST] [PORT]
Options:
  -p               Range of ports to scan
  -u               UDP scan
  -t               TCP scan
  --dict-auth      Run a dictionary attack on open authserver ports
  --user <name>    Username for the dictionary attack (with --dict-auth)
  --dict <file>    Password dictionary (default words.txt)
  --help           Show this message and exit.
"""

port_list = [21, 22, 25, 80, 443]

HOST = "127.0.0.1"

DEFAULT_DICT = "words.txt"

def displayBanner():
    ascii_banner = pyfiglet.figlet_format("TINY SCANNER", "doom")
    print (ascii_banner)

def _fail(message):
    print(f"tinyscanner: {message}", file=sys.stderr)
    return 1

def load_words(path):
    """Read one password per line from a dictionary file."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return [line.strip() for line in fh if line.strip()]

def main(argv=None):
    displayBanner()
    args = list(argv) if argv is not None else sys.argv[1:]

    if "--help" in args:
        sys.stdout.write(USAGE)
        return 0

    tcp = False
    udp = False
    dict_auth = False
    user = None
    dict_path = DEFAULT_DICT
    port_spec = None
    host = None
    positional = []

    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "-p":
            if i + 1 >= len(args):
                return _fail("option -p requires an argument")
            if port_spec is not None:
                return _fail("option -p given more than once")
            port_spec = args[i + 1]
            i += 2
        elif arg == "-u":
            udp = True
            i += 1
        elif arg == "-t":
            tcp = True
            i += 1
        elif arg == "--dict-auth":
            dict_auth = True
            i += 1
        elif arg == "--user":
            if i + 1 >= len(args):
                return _fail("option --user requires an argument")
            user = args[i + 1]
            i += 2
        elif arg == "--dict":
            if i + 1 >= len(args):
                return _fail("option --dict requires an argument")
            dict_path = args[i + 1]
            i += 2
        elif arg.startswith("-"):
            return _fail(f"unknow option '{arg}'")
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
    if dict_auth and user is None:
        return _fail("option --dict-auth requires --user")

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

    try:
        socket.gethostbyname(host)
    except socket.gaierror:
        return _fail(f"unable to resolve host '{host}'")

    words = None
    if dict_auth:
        try:
            words = load_words(dict_path)
        except OSError as exc:
            return _fail(f"cannot read dictionary '{dict_path}': {exc}")
        if not words:
            return _fail(f"dictionary '{dict_path}' is empty")

    proto = "udp" if udp else "tcp"

    scan = scan_udp if udp else scan_tcp
    open_ports = []
    for port in ports:
        is_open = scan(host, port, DEFAULT_TIMEOUT)
        if is_open:
            open_ports.append(port)
            line = f"Port {port} is open"
            name = service_name(port, proto)
            if name:
                line += f" ({name})"
        else:
            line = f"Port {port} is closed"
        print(line)

    if dict_auth:
        for port in open_ports:
            if dictattack.probe_service(host, port, DEFAULT_TIMEOUT):
                password, attempts = dictattack.dict_attack(
                    host, port, user, words, DEFAULT_TIMEOUT
                )
                if password is not None:
                    print(
                        f"Port {port}: password for {user} is '{password}' (attempt {attempts})"
                    )
                else:
                    print(
                        f"Port {port}: no password found for {user} ({attempts} attempts)"
                    )
    return 0

if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `py -3.12 -m pytest tests/test_dictattack.py tests/test_tinyscanner_cli.py -v`
Expected: PASS (6 dictattack tests + 5 CLI tests).

- [ ] **Step 5: Commit**

```bash
git add tinyscanner.py tests/test_tinyscanner_cli.py
git commit -m "feat: add --dict-auth dictionary attack to tinyscanner"
```

---

## Self-Review

- **Spec coverage:** `probe_service` -> Task 1; `dict_attack` -> Task 2; `--dict-auth`/`--user`/`--dict` options -> Task 3; attack on each open port after the scan -> Task 3; sober result-only output -> Task 3 (output lines match the spec verbatim); errors (`--dict` unreadable/empty, `--dict-auth` without `--user`) -> Task 3; `words.txt` default -> Task 3 (`DEFAULT_DICT`); exit codes -> Tasks 2-3; no modification of `scanner.py` or `authserver/` -> Global Constraints + only `tinyscanner.py`/`dictattack.py`/`pytest.ini`/tests touched.
- **Placeholder scan:** no TBD/TODO; every code step contains complete, runnable code; test data uses concrete values (`secret123`, attempt counts).
- **Type consistency:** `probe_service(host, port, timeout) -> bool` used identically in Task 3; `dict_attack(host, port, user, words, timeout) -> (password, attempts)` returned as a tuple everywhere; `LoginServer` fixture uses the same `start()/serve()/stop()` API the current authserver exposes; `load_words(path) -> list[str]` defined and consumed in Task 3.
- **Note:** the spec's `dict_attack -> str | None` is refined here to return `(password | None, attempts)` so the CLI can report the attempt count; this is the only deviation and is covered by the Task 3 output lines.
- **authserver dependency:** Task 2 Step 1 is a mandatory pre-flight that fails loudly if the authserver cannot answer `PASS` commands; the plan never edits `authserver/`.
