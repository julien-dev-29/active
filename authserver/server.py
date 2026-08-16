import socket
import threading
import sys
import hashlib
import argparse
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
    return hashlib.sha256((salt + password).encode()).hexdigest() == digest

class LoginServer:
    
    def __init__(self, users, host=HOST, port=DEFAULT_PORT):
        self.host = host
        self.users = users
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
    
    def serve(self):
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
        srv.serve()
    except KeyboardInterrupt:
        print("\nauthserver stopped")
        return 0
    finally:
        srv.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())