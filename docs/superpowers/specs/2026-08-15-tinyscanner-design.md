# tinyscanner Design

Date: 2026-08-15

## Goal

Build a tiny port scanner from scratch that reports whether each scanned port is
open or closed, run on Windows, written in Python (stdlib only, no third-party
dependencies). The scan results print to stdout in the exact format shown in the
subject, plus a bonus that shows the service name for open ports.

## Deliverables

- `tinyscanner.py` — CLI entry point: argument parsing, port iteration, output.
- `scanner.py` — core scanning logic: TCP scan, UDP scan, service lookup, port-spec parsing.
- `tests/test_scanner.py` — pytest tests for parsing, service names, open/closed detection.
- `README.md` — explains how to build/run and how the tool works.

## CLI behavior

```
tinyscanner [OPTIONS] [HOST] [PORT]
  -p <port|range>   port or range to scan, e.g. 80 or 80-83
  -u                UDP scan
  -t                TCP scan
  --help            show usage and exit
```

- The port may be given positionally or via `-p`; if both are given, error.
- If neither `-t` nor `-u` is given, default to TCP.
- No admin/root privileges required (no raw sockets).
- Invalid host, invalid port spec, or port outside 1-65535 produce a clear error
  message and a non-zero exit.

## Scanning logic

### TCP

- Open a socket, set a connect timeout, attempt `connect()`.
- Success -> open.
- `ConnectionRefusedError`, timeout, or unreachable -> closed.

### UDP

- Send an empty datagram to host:port, then wait for a reply on the same socket.
- Reply received -> open.
- ICMP port-unreachable (surfaces as `ConnectionRefusedError` on the socket) -> closed.
- Timeout -> open (likely filtered; matches subject convention).

### Service names (bonus)

- `socket.getservbyport(port, proto)` first, with a small built-in fallback dict
  for well-known ports (e.g. 22, 53, 80, 443, 8080).

## Output

- `Port <n> is open` for open ports.
- `Port <n> is open (<service>)` when a service name is known.
- `Port <n> is closed` for closed ports.
- `--help` prints the usage text from the subject.
- Exit code 0 on success, non-zero on usage/scan errors.

## Error handling

- Hostname resolution failures -> clear message, non-zero exit.
- Malformed port specs (e.g. `80-x`, `-1`) -> clear message, non-zero exit.
- Out-of-range ports -> clear message, non-zero exit.

## Testing

pytest covering:

- `parse_port_spec`: single port and range expansion, malformed input errors.
- `service_name`: known port via system lookup and via fallback dict.
- TCP scan against a throwaway local listening socket (open) and an unbound port (closed).
- UDP scan against an unbound port (closed).

## Non-goals

- No raw sockets / SYN scanning / stealth scanning.
- No concurrency or parallel port scanning.
- No OS fingerprinting or scripting engine (Nmap features out of scope).
