import socket
import argparse
import sys

def tcp_scan(host, port):
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.settimeout(1)
        conn.connect((host, port))
        print(f"[+] {port}/tcp open")
        conn.close()
    except:
        print(f"[-] {port}/tcp closed")

def upd_scan(host, port):
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        conn.settimeout(1)
        conn.connect((host, port))
        print(f"[+] {port}/udp open")
        conn.close()
    except:
        print(f"[-] {port}/udp closed")
    
def parse_ports(port_str):
    ports = []
    if '-' in port_str:
        start, end = map(int, port_str.split('-'))
        ports = range(start, end + 1)
    else:
        ports = [int(port_str)]
    return ports

def main():
    parser = argparse.ArgumentParser(
        prog="TINY SCANNER",
        description="TCP, UDP scanner for educational purpose",
        epilog="Happy hacking! :)"
    )
    parser.add_argument("-u",action="store_true", help="UDP scan")
    parser.add_argument("-t",action="store_true", help="TCP scan")
    parser.add_argument("host", help="Target host IP address")
    parser.add_argument("-p", dest="ports", required=True, help="Range of ports to scan")
    args = parser.parse_args()
    ports = parse_ports(args.ports)
    host = args.host
    scan_func = upd_scan if args.u else tcp_scan
    try:
        ip = socket.gethostbyname(host)
    except:
        print(f"[-] Cannot resolve {host}: Unknow host")

    try:
        name = socket.gethostbyaddr(ip)
        print(f"\n[+] Scan results for {name[0]}")
    except:
        print(f"\n[-] Scan results for {ip}")

    for port in ports:
        print(f"Scanning port {port}")
        scan_func(host, port)


if __name__ == "__main__":
    sys.exit(main())