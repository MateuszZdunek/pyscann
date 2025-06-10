"""
scanner_core_sync.py  –  szybki skaner TCP bez Nmapa
używany przez app_gui_sync.py
"""
import socket, concurrent.futures, ipaddress
from typing import List, Dict, Iterable

# ------- konfiguracja -------
DEFAULT_PORTS  = [22, 80, 443, 3389, 8080, 8443]
SOCKET_TIMEOUT = 0.30        # sek. – ile czekamy na odpowiedź portu
HOST_WORKERS   = 400         # ilu hostów skanujemy równolegle
PORT_WORKERS   = 10          # ilu portów równolegle na jednym hoście

# opisy do tabeli GUI (możesz rozbudować)
PORT_DESC = {
    22:   "SSH",
    80:   "HTTP",
    443:  "HTTPS",
    3389: "RDP",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
}

# ------- skan pojedynczego portu -------
def scan_port(ip: str, port: int,
              timeout: float = SOCKET_TIMEOUT) -> Dict | None:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(0.2)
            banner = ""
            if port in (80, 8080, 8000):
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(100).decode(errors="ignore")
            elif port == 22:
                banner = s.recv(100).decode(errors="ignore")
            return {"port": port, "banner": banner.strip()}
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None

# ------- skan wszystkich portów jednego hosta -------
def scan_host(ip: str, ports: Iterable[int]) -> Dict:
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=PORT_WORKERS) as ppool:
        fut2p = {ppool.submit(scan_port, ip, p): p for p in ports}
        for fut in concurrent.futures.as_completed(fut2p):
            res = fut.result()
            if res:
                open_ports.append(res)
    return {"ip": ip, "ports": open_ports}

# ------- skan całej podsieci -------
def scan_subnet(subnet: str,
                ports: List[int],
                stop_flag,
                max_workers: int = HOST_WORKERS) -> List[Dict]:
    results = []
    net = ipaddress.ip_network(subnet, strict=False)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        fut2ip = {pool.submit(scan_host, str(ip), ports): str(ip) for ip in net}
        for fut in concurrent.futures.as_completed(fut2ip):
            if stop_flag.is_set():          # użytkownik kliknął “Stop”
                break
            host_data = fut.result()
            if host_data["ports"]:
                results.append(host_data)
    return results

# ------- uruchomienie z CLI (testowe) -------
if __name__ == "__main__":
    import argparse, json, pprint, threading
    ap = argparse.ArgumentParser(description="CLI – szybki skaner TCP")
    ap.add_argument("subnet", help="CIDR, np. 192.168.1.0/24")
    ap.add_argument("-p", "--ports", help="22,80,443 lub puste (domyślne)")
    args = ap.parse_args()

    ports = list(map(int, args.ports.split(","))) if args.ports else DEFAULT_PORTS
    stop = threading.Event()
    data = scan_subnet(args.subnet, ports, stop)
    pprint.pp(data)
    json.dump(data, open("scan.json", "w"), indent=2)
