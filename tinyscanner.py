import pyfiglet
import sys
import socket
from passlib.context import CryptContext

DEFAULT_TIMEOUT= 1.0

USAGE = """Usage: tinyscanner [OPTIONS] [HOST] [PORT]
Options:
  -p               Range of ports to scan
  -u               UDP scan
  -t               TCP scan
  --help           Show this message and exit.
"""

port_list = [21, 22, 25, 80, 443]

HOST = "127.0.0.1"

myctx = CryptContext(schemes=["sha256_crypt", "md5_crypt", "des_crypt"])
hashed = myctx.hash("yolo les kikis!")

def displayBanner():
    ascii_banner = pyfiglet.figlet_format("TINY SCANNER", "doom")
    print (ascii_banner)

def readFile():
    dictFile = open("words.txt", "r")
    for word in dictFile.readlines():
        word = word.strip('\n')

def scan_ftp(host, port, timeout=DEFAULT_TIMEOUT):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()

def main(argv=None):
    displayBanner()
    args = list(argv) if argv is not None else sys.argv[1:]

    if "--help" in args:
        sys.stdout.write(USAGE)
        return 0

    for port in port_list:
        print ("[+] Checking " + HOST + ":" + str(port))
        isOpen = scan_ftp(HOST, port)
        if isOpen:
            print ("Port:" + str(port) + " is open")
        else:
            print ("Port:" + str(port) + " is closed")

    return 0

if __name__ == "__main__":
    sys.exit(main())