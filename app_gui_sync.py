# app_gui_sync.py  –  live status + port-description
import threading, queue, ipaddress, tkinter as tk
from tkinter import ttk, messagebox
from scanner_core_sync import scan_port, DEFAULT_PORTS

QUE_POLL_MS = 100   # co 100 ms sprawdzamy kolejkę z wątku skanującego

# krótki słownik opisów portów
PORT_DESC = {
    22:  "SSH",
    80:  "HTTP",
    443: "HTTPS",
    3389: "RDP",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
}

class ScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Simple Network Scanner")
        self.geometry("820x550")
        self._build_widgets()
        self.task_q: queue.Queue = queue.Queue()

    # ---------- widżety ----------
    def _build_widgets(self):
        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text="Subnet (CIDR):").grid(row=0, column=0, sticky="w")
        self.ent_sub = ttk.Entry(top, width=25)
        self.ent_sub.insert(0, "192.168.1.0/24")
        self.ent_sub.grid(row=0, column=1, padx=5)

        ttk.Label(top, text="Ports:").grid(row=1, column=0, sticky="w")
        self.ent_ports = ttk.Entry(top, width=25)
        self.ent_ports.insert(0, ",".join(map(str, DEFAULT_PORTS)))
        self.ent_ports.grid(row=1, column=1, padx=5)

        ttk.Button(top, text="Scan", command=self.start_scan).grid(
            row=0, column=2, rowspan=2, padx=10
        )

        # pasek postępu + etykieta statusu
        self.pbar = ttk.Progressbar(top, length=250, mode="determinate")
        self.pbar.grid(row=0, column=3, rowspan=2, padx=10)
        self.lbl_status = ttk.Label(top, text="Ready", width=30)
        self.lbl_status.grid(row=0, column=4, rowspan=2, sticky="w")

        # tabela wyników
        cols = ("ip", "port", "banner")
        self.tree = ttk.Treeview(self, columns=cols, show="headings")
        for c in cols:
            self.tree.heading(c, text=c.upper())
            self.tree.column(c, anchor="w",
                             width=140 if c != "banner" else 520)
        self.tree.pack(fill="both", expand=True, padx=10, pady=10)

    # ---------- skanowanie ----------
    def start_scan(self):
        subnet = self.ent_sub.get().strip()
        try:
            ports = list(map(int, self.ent_ports.get().split(",")))
        except ValueError:
            messagebox.showerror("Error",
                                 "Ports must be comma-separated integers")
            return

        self.tree.delete(*self.tree.get_children())
        self.task_q.queue.clear()
        net = ipaddress.ip_network(subnet, strict=False)
        self.pbar.configure(maximum=net.num_addresses, value=0)
        self.lbl_status.config(text="Starting…")

        threading.Thread(
            target=self.worker_scan,
            args=(net, ports, self.task_q),
            daemon=True
        ).start()

        self.after(QUE_POLL_MS, self.process_queue)

    @staticmethod
    def worker_scan(net, ports, q: queue.Queue):
        for ip in net:
            ip_str = str(ip)
            for p in ports:
                # aktualny status
                q.put(("status", f"Scanning {ip_str}:{p}"))
                res = scan_port(ip_str, p)
                if res:
                    desc = PORT_DESC.get(p, "")
                    port_text = f"{p} ({desc})" if desc else str(p)
                    q.put(("row", ip_str, port_text, res["banner"][:120]))
            q.put(("progress",))
        q.put(("status", "Done"))
        q.put(("done",))

    # ---------- kolejka -> GUI ----------
    def process_queue(self):
        try:
            while True:
                tag, *payload = self.task_q.get_nowait()
                if tag == "row":
                    ip, port_txt, banner = payload
                    self.tree.insert("", "end",
                                     values=(ip, port_txt, banner))
                elif tag == "progress":
                    self.pbar.step(1)
                elif tag == "status":
                    self.lbl_status.config(text=payload[0])
                elif tag == "done":
                    self.pbar.stop()
        except queue.Empty:
            pass
        finally:
            self.after(QUE_POLL_MS, self.process_queue)

if __name__ == "__main__":
    ScannerApp().mainloop()
