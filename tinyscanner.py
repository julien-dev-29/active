import pyfiglet
import sys
from passlib.context import CryptContext
from scanner import DEFAULT_TIMEOUT, scan_tcp, scan_udp

USAGE = """Usage: tinyscanner [OPTIONS] [HOST] [PORT]
Options:
  -p               Range of ports to scan
  -u               UDP scan
  -t               TCP scan
  --help           Show this message and exit.
"""

port_list = [21, 22, 25, 80, 443]

HOST = "127.0.0.1"

def displayBanner():
    ascii_banner = pyfiglet.figlet_format("TINY SCANNER", "doom")
    print (ascii_banner)

def _fail(message):
    print(f"tinyscanner: {message}", file=sys.stderr)
    return 1

def main(argv=None):
    displayBanner()
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
                return _fail("option -p requires an argument")
            if port_spec is not None:
                return _fail("option -p given more than once")
            port_spec = args[i + 1]
            i+=2
        elif arg == "-u":
            udp = True
            i += 1
        elif arg == "-t":
            tcp = True
            i += 1
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

    if port_spec is not None and positional:
        return _fail("port given both positionally and via '-p'")
    if len(positional) > 1:
        return _fail("too many arguments")
    spec = port_spec if port_spec is not None else (positional[0] if positional else None)
    if spec is None:
        return _fail("missing PORT argument")

if __name__ == "__main__":
    sys.exit(main())