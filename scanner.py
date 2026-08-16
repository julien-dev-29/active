
import socket

DEFAULT_TIMEOUT= 1.0

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
    if "-" in spec:
        start_str, end_str = spec.split("-", 1)
        start = int(start_str)
        end = int(end_str)
        if start < 1 or end > 65535 or start > end:
            raise ValueError(f"invalid port range '{spec}'")
        return list(range(start, end + 1))
    port = int(spec)
    if port < 1 or port > 65535:
        raise ValueError(f"invalid port '{port}'")
    return [port]

def service_name(port, proto):
    """Return the service name for a port/protocol, or None if unknown."""
    try:
        return socket.getservbyport(port, proto)
    except OSError:
        return _FALLBACK_SERVICES.get(port)

def scan_tcp(host, port, timeout=DEFAULT_TIMEOUT):
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
  