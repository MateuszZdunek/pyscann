# --- nowa wersja ---
import socket, concurrent.futures, ipaddress
from typing import List, Dict, Iterable

DEFAULT_PORTS = [22, 80, 443, 3389, 8080, 8443]
SOCKET_TIMEOUT = 0.3                   # było 1.0
HOST_WORKERS   = 400                   # było 100
PORT_WORKERS   = 10                    # równoległe porty w obrębie hosta

def scan_port(ip: str, port: int, timeout=SOCKET_TIMEOUT) -> Dict | None:
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

def scan_host(ip: str, ports: Iterable[int]) -> Dict:
    open_ports = []
    # pool per-host → scanujemy porty jednocześnie
    with concurrent.futures.ThreadPoolExecutor(max_workers=PORT_WORKERS) as ppool:
        fut_to_port = {ppool.submit(scan_port, ip, p): p for p in ports}
        for fut in concurrent.futures.as_completed(fut_to_port):
            res = fut.result()
            if res:
                open_ports.append(res)
    return {"ip": ip, "ports": open_ports}

def scan_subnet(subnet: str, ports: List[int], stop_flag, max_workers=HOST_WORKERS):
    results = []
    net = ipaddress.ip_network(subnet, strict=False)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        fut_to_ip = {pool.submit(scan_host, str(ip), ports): str(ip) for ip in net}
        for fut in concurrent.futures.as_completed(fut_to_ip):
            if stop_flag.is_set():          # użytkownik kliknął „Stop”
                break
            host_data = fut.result()
            if host_data["ports"]:
                results.append(host_data)
    return results
