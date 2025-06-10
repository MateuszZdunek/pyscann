# scanner_core_sync.py
import ipaddress, json, socket, concurrent.futures
from typing import List, Dict, Iterable

DEFAULT_PORTS = [22, 80, 443, 3389, 8080, 8443]
SOCKET_TIMEOUT = 1.0                  # sekundy

def scan_port(ip: str, port: int) -> Dict | None:
    """Zwraca info o otwartym porcie lub None, jeśli zamknięty."""
    try:
        with socket.create_connection((ip, port), timeout=SOCKET_TIMEOUT) as s:
            s.settimeout(0.5)
            banner = ""
            if port in (80, 8080, 8000):
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(100).decode(errors="ignore")
            elif port == 22:
                banner = s.recv(100).decode(errors="ignore")
            return {"port": port, "banner": banner.strip()}
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None

def scan_host(ip: str, ports: Iterable[int]) -> Dict:
    open_ports = []
    for p in ports:
        res = scan_port(ip, p)
        if res:
            open_ports.append(res)
    return {"ip": ip, "ports": open_ports}

def scan_subnet(subnet: str,
                ports: List[int] | None = None,
                max_workers: int = 100) -> List[Dict]:
    ports = ports or DEFAULT_PORTS
    net = ipaddress.ip_network(subnet, strict=False)
    results: List[Dict] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_to_ip = {
            pool.submit(scan_host, str(ip), ports): str(ip) for ip in net
        }
        for fut in concurrent.futures.as_completed(future_to_ip):
            host_data = fut.result()
            if host_data["ports"]:
                results.append(host_data)
    return results

if __name__ == "__main__":
    import argparse, pprint
    ap = argparse.ArgumentParser(description="Prosty skaner TCP (synchroniczny)")
    ap.add_argument("subnet", help="CIDR, np. 192.168.1.0/24")
    ap.add_argument("-p", "--ports", help="22,80,443 lub puste (domyślne)")
    args = ap.parse_args()

    if args.ports:
        ports = list(map(int, args.ports.split(",")))
    else:
        ports = DEFAULT_PORTS

    data = scan_subnet(args.subnet, ports)
    pprint.pp(data)
    json.dump(data, open("scan.json", "w"), indent=2)
