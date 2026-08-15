# authserver Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `authserver`, a deliberately vulnerable TCP login server (Python stdlib only) for testing a dictionary attack against your own credentials on localhost, plus a helper to generate salted SHA-256 credentials.

**Architecture:** `authserver/gen_hash.py` produces the salt/hash lines for `users.conf`. `authserver/server.py` parses that config, serves a line-based `USER`/`PASS` protocol over a TCP socket (one thread per connection, no rate limiting), verifies with `sha256(salt + password)`, and logs every attempt. A `LoginServer` class keeps the network logic testable; a `main()` wrapper is the CLI entry point.

**Tech Stack:** Python 3.12, stdlib `socket`/`hashlib`/`secrets`/`threading`/`argparse`, pytest 9.x. Run Python via `py -3.12` (the `python` on PATH is msys2 without pytest). Windows is the target platform.

## Global Constraints

- Target platform: Windows. Educational use on 127.0.0.1 only.
- Stdlib only in `server.py` and `gen_hash.py`.
- Server binds `127.0.0.1` by default, port default `9999`, configurable via `--port`.
- Config format (`users.conf`): one user per line `username:salt:hash`, `#` comments, blank lines ignored. Hash is `sha256(salt + password)` in hex.
- Protocol: `USER <name>` -> `USER OK` / `USER NOT FOUND`; `PASS <password>` -> `PASS OK` / `PASS FAILED`; `PASS` before `USER` -> `ERROR: specify USER first`; any other non-empty line -> `ERROR`. Banner `authserver 1.0` sent on connect.
- Every login attempt is logged to stdout: timestamp, IP:port, username, attempted password, result.
- No rate limiting, no TLS, no plaintext password storage (deliberate vulnerabilities).
- Test commands use `py -3.12 -m pytest ...` because `python` resolves to msys2 without pytest.

---

### Task 1: Hash generator (`gen_hash.py`)

**Files:**
- Modify: `pytest.ini` (add `authserver` to `pythonpath`)
- Create: `authserver/gen_hash.py`
- Create: `authserver/tests/test_gen_hash.py`

**Interfaces:**
- Produces:
  - `make_hash(password: str) -> tuple[str, str]` — returns `(salt, digest)` where `salt` is 32 hex chars (16 random bytes via `secrets.token_hex(16)`) and `digest = sha256(salt + password).hexdigest()`.
  - `main(argv: list[str] | None = None) -> int` — prints `salt=...` and `hash=...` to stdout, returns 0; prints usage to stderr and returns 1 when the argument count is wrong.

- [ ] **Step 1: Update `pytest.ini` and write the failing tests**

Update `pytest.ini` so both `scanner` (tinyscanner) and the authserver modules are importable from the repo root:

```ini
[pytest]
pythonpath = . authserver
```

Create `authserver/tests/test_gen_hash.py`:

```python
import hashlib

import pytest

import gen_hash


def test_make_hash_returns_hex_salt_and_digest():
    salt, digest = gen_hash.make_hash("password")
    assert len(salt) == 32
    assert len(digest) == 64
    assert all(c in "0123456789abcdef" for c in salt)
    assert all(c in "0123456789abcdef" for c in digest)


def test_make_hash_digest_matches_sha256():
    salt, digest = gen_hash.make_hash("hunter2")
    assert digest == hashlib.sha256((salt + "hunter2").encode()).hexdigest()


def test_make_hash_uses_random_salt():
    salt1, _ = gen_hash.make_hash("password")
    salt2, _ = gen_hash.make_hash("password")
    assert salt1 != salt2


def test_main_prints_salt_and_hash(capsys):
    rc = gen_hash.main(["secret"])
    out = capsys.readouterr().out
    assert rc == 0
    assert out.startswith("salt=")
    assert "hash=" in out


def test_main_requires_exactly_one_arg(capsys):
    rc = gen_hash.main([])
    err = capsys.readouterr().err
    assert rc == 1
    assert "Usage" in err


def test_main_rejects_extra_args(capsys):
    rc = gen_hash.main(["a", "b"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "Usage" in err
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `py -3.12 -m pytest authserver/tests/test_gen_hash.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'gen_hash'`.

- [ ] **Step 3: Write the minimal implementation**

Create `authserver/gen_hash.py`:

```python
"""Generate salt and SHA-256(salt + password) for authserver's users.conf.

Usage: python gen_hash.py <password>
"""

import hashlib
import secrets
import sys


def make_hash(password):
    """Return (salt, digest) where digest is the hex sha256 of salt+password."""
    salt = secrets.token_hex(16)
    digest = hashlib.sha256((salt + password).encode()).hexdigest()
    return salt, digest


def main(argv=None):
    args = argv if argv is not None else sys.argv[1:]
    if len(args) != 1:
        print("Usage: gen_hash.py <password>", file=sys.stderr)
        return 1
    salt, digest = make_hash(args[0])
    print(f"salt={salt}")
    print(f"hash={digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `py -3.12 -m pytest authserver/tests/test_gen_hash.py -v`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add pytest.ini authserver/gen_hash.py authserver/tests/test_gen_hash.py
git commit -m "feat: add authserver hash generator"
```

---

### Task 2: Sample test account (`users.conf`)

**Files:**
- Create: `authserver/users.conf`

**Interfaces:**
- Produces: `authserver/users.conf` with one documented test account: username `admin`, password `password`, salt `deadbeefcafebabe0000000000000000`, hash `7f545019adf772e0591845cb596bdcf9649e8920950ce22f3a16ab02eb404f53`.
- Consumes: the `username:salt:hash` format defined in Task 1.

- [ ] **Step 1: Write `authserver/users.conf`**

Create `authserver/users.conf`:

```
# authserver test accounts
# format: username:salt:hash
#   salt  = 16 random bytes, hex (generate with gen_hash.py)
#   hash  = sha256(salt + password), hex
#
# Sample account: admin / password
# Generate your own with: python gen_hash.py <password>
admin:deadbeefcafebabe0000000000000000:7f545019adf772e0591845cb596bdcf9649e8920950ce22f3a16ab02eb404f53
```

- [ ] **Step 2: Verify the hash matches**

Run: `py -3.12 -c "import hashlib; assert hashlib.sha256(b'deadbeefcafebabe0000000000000000' + b'password').hexdigest() == '7f545019adf772e0591845cb596bdcf9649e8920950ce22f3a16ab02eb404f53'; print('hash ok')"`
Expected: prints `hash ok`.

- [ ] **Step 3: Commit**

```bash
git add authserver/users.conf
git commit -m "feat: add sample authserver test account"
```

---

### Task 3: Server core (`load_users`, `verify_password`, `LoginServer`)

**Files:**
- Create: `authserver/server.py`
- Create: `authserver/tests/test_server.py`

**Interfaces:**
- Consumes: `authserver/users.conf` (Task 2) and its `username:salt:hash` format.
- Produces:
  - `load_users(path: str) -> dict[str, tuple[str, str]]` — username -> `(salt, digest)`; raises `ValueError` on malformed lines, propagates `OSError` for unreadable files.
  - `verify_password(password: str, salt: str, digest: str) -> bool`
  - `class LoginServer` with `__init__(users: dict, host: str = "127.0.0.1", port: int = 9999)`, `start() -> int` (bind+listen, returns bound port), `serve_forever() -> None` (accept loop, thread per connection), `stop() -> None`.
  - `BANNER: str` = `"authserver 1.0"`, `HOST: str` = `"127.0.0.1"`, `DEFAULT_PORT: int` = `9999`, `DEFAULT_USERS: str` = `"users.conf"`.

- [ ] **Step 1: Write the failing tests**

Create `authserver/tests/test_server.py`:

```python
import os
import socket
import threading

import pytest

import server
from server import LoginServer, load_users, verify_password

USERS_PATH = os.path.join(os.path.dirname(__file__), os.pardir, "users.conf")


@pytest.fixture(scope="module")
def server_addr():
    users = load_users(USERS_PATH)
    srv = LoginServer(users, host="127.0.0.1", port=0)
    srv.start()
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield "127.0.0.1", srv.port
    srv.stop()
    thread.join(timeout=1)


def talk(addr, lines):
    host, port = addr
    with socket.create_connection(addr, timeout=5) as sock:
        banner = sock.recv(1024).decode().strip()
        responses = []
        for line in lines:
            sock.sendall((line + "\n").encode())
            responses.append(sock.recv(1024).decode().strip())
        return banner, responses


def test_load_users_reads_sample_account():
    users = load_users(USERS_PATH)
    assert "admin" in users
    salt, digest = users["admin"]
    assert digest == server.hashlib.sha256((salt + "password").encode()).hexdigest()


def test_load_users_rejects_malformed_line(tmp_path):
    p = tmp_path / "bad.conf"
    p.write_text("admin:onlytwo\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_users(str(p))


def test_verify_password_ok():
    salt = "deadbeefcafebabe0000000000000000"
    digest = "7f545019adf772e0591845cb596bdcf9649e8920950ce22f3a16ab02eb404f53"
    assert verify_password("password", salt, digest) is True


def test_verify_password_wrong():
    salt = "deadbeefcafebabe0000000000000000"
    digest = "7f545019adf772e0591845cb596bdcf9649e8920950ce22f3a16ab02eb404f53"
    assert verify_password("wrong", salt, digest) is False


def test_banner(server_addr):
    banner, _ = talk(server_addr, [])
    assert banner == server.BANNER


def test_user_ok(server_addr):
    _, responses = talk(server_addr, ["USER admin"])
    assert responses == ["USER OK"]


def test_user_not_found(server_addr):
    _, responses = talk(server_addr, ["USER root"])
    assert responses == ["USER NOT FOUND"]


def test_pass_ok(server_addr):
    _, responses = talk(server_addr, ["USER admin", "PASS password"])
    assert responses == ["USER OK", "PASS OK"]


def test_pass_failed(server_addr):
    _, responses = talk(server_addr, ["USER admin", "PASS wrong"])
    assert responses == ["USER OK", "PASS FAILED"]


def test_pass_before_user(server_addr):
    _, responses = talk(server_addr, ["PASS password"])
    assert responses == ["ERROR: specify USER first"]


def test_unknown_command(server_addr):
    _, responses = talk(server_addr, ["HELLO"])
    assert responses == ["ERROR"]


def test_user_then_pass_then_pass_again(server_addr):
    _, responses = talk(server_addr, ["USER admin", "PASS password", "PASS wrong"])
    assert responses == ["USER OK", "PASS OK", "PASS FAILED"]


def test_concurrent_connections(server_addr):
    r1 = talk(server_addr, ["USER admin", "PASS password"])
    r2 = talk(server_addr, ["USER admin", "PASS nope"])
    assert r1 == (server.BANNER, ["USER OK", "PASS OK"])
    assert r2 == (server.BANNER, ["USER OK", "PASS FAILED"])
```

Note: the `import server` in the test relies on `authserver` being on `sys.path` (pytest.ini from Task 1). The `server.hashlib` reference in `test_load_users_reads_sample_account` works because `server.py` does `import hashlib`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `py -3.12 -m pytest authserver/tests/test_server.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'server'`.

- [ ] **Step 3: Write the minimal implementation**

Create `authserver/server.py`:

```python
"""authserver: a deliberately vulnerable TCP login server (educational only).

Serves a line-based USER/PASS protocol over TCP, verifies passwords against
sha256(salt + password) hashes stored in a users file, and logs every attempt.
No rate limiting, no encryption -- by design, for testing a dictionary attack
against your own credentials on localhost.

Usage: python server.py [--host HOST] [--port PORT] [--users FILE]
"""

import argparse
import hashlib
import socket
import sys
import threading
import time

HOST = "127.0.0.1"
DEFAULT_PORT = 9999
DEFAULT_USERS = "users.conf"
BANNER = "authserver 1.0"


def load_users(path):
    """Parse a users file (username:salt:hash per line) into a dict."""
    users = {}
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) != 3:
                raise ValueError(f"malformed line in {path}: {line!r}")
            username, salt, digest = parts
            users[username] = (salt, digest)
    return users


def verify_password(password, salt, digest):
    """Return True if sha256(salt + password) equals digest."""
    return hashlib.sha256((salt + password).encode()).hexdigest() == digest


class LoginServer:
    def __init__(self, users, host=HOST, port=DEFAULT_PORT):
        self.users = users
        self.host = host
        self.port = port
        self._sock = None
        self._running = False

    def start(self):
        """Bind and listen; returns the bound port."""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(5)
        self.port = self._sock.getsockname()[1]
        self._running = True
        return self.port

    def serve_forever(self):
        """Accept connections until stop(), one thread per connection."""
        if self._sock is None:
            self.start()
        try:
            while self._running:
                conn, addr = self._sock.accept()
                threading.Thread(
                    target=self._handle_conn, args=(conn, addr), daemon=True
                ).start()
        except OSError:
            pass

    def stop(self):
        self._running = False
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass

    def _handle_conn(self, conn, addr):
        try:
            conn.sendall((BANNER + "\n").encode())
            stream = conn.makefile("r", encoding="utf-8", errors="replace")
            current_user = None
            for raw in stream:
                text = raw.strip()
                if text.startswith("USER "):
                    name = text[5:].strip()
                    if name in self.users:
                        current_user = name
                        conn.sendall(b"USER OK\n")
                    else:
                        current_user = None
                        conn.sendall(b"USER NOT FOUND\n")
                elif text.startswith("PASS "):
                    password = text[5:].strip()
                    if current_user is None:
                        conn.sendall(b"ERROR: specify USER first\n")
                    elif verify_password(password, *self.users[current_user]):
                        self._log(addr, current_user, password, "OK")
                        conn.sendall(b"PASS OK\n")
                    else:
                        self._log(addr, current_user, password, "FAILED")
                        conn.sendall(b"PASS FAILED\n")
                elif text:
                    conn.sendall(b"ERROR\n")
        except OSError:
            pass
        finally:
            conn.close()

    def _log(self, addr, username, password, result):
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        ip, port = addr
        print(f"[{ts}] {ip}:{port} user={username} pass={password!r} -> {result}")


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="authserver",
        description="Deliberately vulnerable TCP login server (educational, localhost only).",
    )
    parser.add_argument("--host", default=HOST, help=f"bind address (default {HOST})")
    parser.add_argument(
        "--port", type=int, default=DEFAULT_PORT, help=f"TCP port (default {DEFAULT_PORT})"
    )
    parser.add_argument(
        "--users", default=DEFAULT_USERS, help=f"users file (default {DEFAULT_USERS})"
    )
    opts = parser.parse_args(argv)

    try:
        users = load_users(opts.users)
    except OSError as exc:
        print(f"authserver: cannot read {opts.users}: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"authserver: {exc}", file=sys.stderr)
        return 1

    if not users:
        print(f"authserver: no users found in {opts.users}", file=sys.stderr)
        return 1

    srv = LoginServer(users, host=opts.host, port=opts.port)
    try:
        port = srv.start()
        print(f"authserver listening on {opts.host}:{port} ({len(users)} user(s))")
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nauthserver stopped")
        return 0
    finally:
        srv.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `py -3.12 -m pytest authserver/tests/test_server.py -v`
Expected: PASS (13 tests).

- [ ] **Step 5: Commit**

```bash
git add authserver/server.py authserver/tests/test_server.py
git commit -m "feat: add authserver login server"
```

---

### Task 4: CLI error handling (`main`)

**Files:**
- Modify: `authserver/server.py` (already written in Task 3 — verify only)
- Create: `authserver/tests/test_cli.py`

**Interfaces:**
- Consumes: `main(argv)` from `server.py` (Task 3).
- Produces: verified behavior — exit code 1 + stderr message for unreadable/malformed/empty users files; argparse `SystemExit` for invalid arguments.

- [ ] **Step 1: Write the failing tests**

Create `authserver/tests/test_cli.py`:

```python
import pytest

from server import main


def test_main_missing_users_file(capsys):
    rc = main(["--users", "does-not-exist.conf"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "cannot read" in err


def test_main_malformed_users_file(tmp_path, capsys):
    p = tmp_path / "bad.conf"
    p.write_text("admin:onlytwo\n", encoding="utf-8")
    rc = main(["--users", str(p)])
    err = capsys.readouterr().err
    assert rc == 1
    assert "malformed" in err


def test_main_empty_users_file(tmp_path, capsys):
    p = tmp_path / "empty.conf"
    p.write_text("# no users here\n", encoding="utf-8")
    rc = main(["--users", str(p)])
    err = capsys.readouterr().err
    assert rc == 1
    assert "no users" in err


def test_main_invalid_port():
    with pytest.raises(SystemExit):
        main(["--port", "not-a-port"])
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `py -3.12 -m pytest authserver/tests/test_cli.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'server'` (or, if Task 3 is already committed, with `assert` failures because the CLI main from Task 3 is already correct — in that case they PASS; do not re-implement, just verify).

- [ ] **Step 3: Verify implementation exists (no new code needed)**

The `main()` function written in Task 3 already satisfies these tests. If Task 3 was committed, run the tests to confirm. No edits required unless a test fails — fix only the failing assertion.

- [ ] **Step 4: Run tests to verify they pass**

Run: `py -3.12 -m pytest authserver/tests/test_cli.py authserver/tests/test_server.py -v`
Expected: PASS (4 CLI tests + 13 server tests).

- [ ] **Step 5: Commit**

```bash
git add authserver/tests/test_cli.py
git commit -m "test: add authserver cli error tests"
```

---

### Task 5: README and final verification

**Files:**
- Create: `authserver/README.md`

- [ ] **Step 1: Write the README**

Create `authserver/README.md`:

```markdown
# authserver

Un serveur de connexion TCP volontairement fragile (Python, standard library
only), pour tester une attaque par dictionnaire sur ses propres identifiants,
en local, à des fins éducatives.

> À des fins éducatives uniquement. N'attaque que des machines ou des
> identifiants dont tu possèdes l'autorisation explicite.

## Générer un compte de test

```bash
python gen_hash.py password
```

Copie les valeurs `salt=` et `hash=` dans `users.conf` sur une ligne
`username:salt:hash`.

Le repo contient un compte d'exemple : `admin` / `password`.

## Lancer le serveur

```bash
python server.py --port 9999
```

Options : `--host` (défaut `127.0.0.1`), `--port` (défaut `9999`),
`--users` (défaut `users.conf`).

## Protocole

Lignes de texte terminées par `\n` :

```
USER admin      ->  USER OK          (ou USER NOT FOUND)
PASS password   ->  PASS OK          (ou PASS FAILED)
```

- Le serveur envoie le bannière `authserver 1.0` à la connexion.
- Vérification : `sha256(salt + mot_de_passe)` comparé au hash de `users.conf`.
- Chaque tentative est journalisée sur la console (heure, IP, utilisateur,
  mot de passe tenté, résultat).
- Aucune limitation de tentatives : c'est la faille voulue pour l'exercice.

## Tester à la main

```bash
# terminal 1
python server.py --port 9999

# terminal 2
python -c "import socket; s=socket.create_connection(('127.0.0.1',9999)); print(s.recv(1024).decode().strip()); s.sendall(b'USER admin\n'); print(s.recv(1024).decode().strip()); s.sendall(b'PASS password\n'); print(s.recv(1024).decode().strip()); s.sendall(b'PASS nope\n'); print(s.recv(1024).decode().strip())"
```

Résultat attendu :

```
authserver 1.0
USER OK
PASS OK
PASS FAILED
```

## Tests

```bash
pip install pytest
pytest
```
```

- [ ] **Step 2: Run the full test suite**

Run: `py -3.12 -m pytest -v`
Expected: PASS (6 gen_hash + 13 server + 4 CLI = 23 tests).

- [ ] **Step 3: Manual end-to-end smoke test**

Run the server and connect to it with a one-liner (two terminals):

```powershell
# terminal 1 (workdir: authserver)
py -3.12 server.py --port 9999

# terminal 2
py -3.12 -c "import socket; s=socket.create_connection(('127.0.0.1',9999)); print(s.recv(1024).decode().strip()); s.sendall(b'USER admin\n'); print(s.recv(1024).decode().strip()); s.sendall(b'PASS password\n'); print(s.recv(1024).decode().strip()); s.sendall(b'PASS nope\n'); print(s.recv(1024).decode().strip())"
```

Expected terminal 2 output:
```
authserver 1.0
USER OK
PASS OK
PASS FAILED
```
And terminal 1 logs each attempt:
```
authserver listening on 127.0.0.1:9999 (1 user(s))
[...] user=admin pass='password' -> OK
[...] user=admin pass='nope' -> FAILED
```

- [ ] **Step 4: Commit**

```bash
git add authserver/README.md
git commit -m "docs: add authserver readme"
```

---

## Self-Review

- **Spec coverage:** server behavior (banner, USER/PASS replies, ERROR, thread per connection, no rate limit, logging) -> Task 3; SHA-256+salt verification -> Tasks 1-3; config format -> Tasks 1-2; `gen_hash.py` -> Task 1; README -> Task 5; tests (USER OK/NOT FOUND, PASS OK/FAILED, ERROR, concurrency) -> Task 3; error handling -> Task 4. No gaps.
- **Placeholder scan:** no TBD/TODO; `users.conf` uses concrete precomputed salt/hash values (verified in Task 2 Step 2). Every code step is complete.
- **Type consistency:** `load_users -> dict[str, tuple[str, str]]`, `verify_password(password, salt, digest)`, `LoginServer(users, host, port)` with `start`/`serve_forever`/`stop`, `main(argv) -> int`. Used identically across tasks; tests reference `server.hashlib`, `server.BANNER`, `server.HOST`, `server.DEFAULT_PORT` consistently with the implementation.
