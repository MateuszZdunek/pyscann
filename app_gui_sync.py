# app_gui_sync.py  –  wersja z paskiem postępu i bieżącymi wpisami
import threading, queue, ipaddress, tkinter as tk
from tkinter import ttk, messagebox
from scanner_core_sync import scan_port, DEFAULT_PORTS      # korzystamy z pojedynczego scan_port
                                                             # żeby móc aktualizować postęp host-po-hoście

QUE_POLL_MS = 100           # co ile ms główny wątek sprawdza kolejkę

class ScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Simple Network Scanner")
        self.geometry("800x520")
        self._build_widgets()
        self.task_q: queue.Queue = queue.Queue()

    # ---------- widżety ----------
    def _build_widgets(self):
        frm = ttk.Frame(self, padding=10)
        frm.pack(fill="x")

        ttk.Label(frm, text="Subnet (CIDR):").grid(row=0, column=0, sticky="w")
        self.ent_sub = ttk.Entry(frm, width=25)
        self.ent_sub.insert(0, "192.168.1.0/24")
        self.ent_sub.grid(row=0, column=1, padx=5)

        ttk.Label(frm, text="Ports:").grid(row=1, column=0, sticky="w")
        self.ent_ports = ttk.Entry(frm, width=25)
        self.ent_ports.insert(0, ",".join(map(str, DEFAULT_PORTS)))
        self.ent_ports.grid(row=1, column=1, padx=5)

        ttk.Button(frm, text="Scan", command=self.start_scan).grid(
            row=0, column=2, rowspan=2, padx=10
        )

        # pasek postępu
        self.pbar = ttk.Progressbar(frm, length=250, mode="determinate")
        self.pbar.grid(row=0, column=3, rowspan=2, padx=10)

        # tabela
        cols = ("ip", "port", "banner")
        self.tree = ttk.Treeview(self, columns=cols, show="headings")
        for c in cols:
            self.tree.heading(c, text=c.upper())
            self.tree.column(c, anchor="w", width=120 if c != "banner" else 500)
        self.tree.pack(fill="both", expand=True, padx=10, pady=10)

    # ---------- obsługa skanowania ----------
    def start_scan(self):
        subnet = self.ent_sub.get().strip()
        try:
            ports = list(map(int, self.ent_ports.get().split(",")))
        except ValueError:
            messagebox.showerror("Error", "Ports must be comma-separated integers")
            return

        self.tree.delete(*self.tree.get_children())
        self.task_q.queue.clear()                # czyścimy kolejkę
        net = ipaddress.ip_network(subnet, strict=False)
        self.pbar.configure(maximum=net.num_addresses, value=0)

        # wątek roboczy
        threading.Thread(
            target=self.worker_scan,
            args=(net, ports, self.task_q),
            daemon=True
        ).start()

        # cykliczne sprawdzanie kolejki
        self.after(QUE_POLL_MS, self.process_queue)

    @staticmethod
    def worker_scan(net: ipaddress.IPv4Network, ports, q: queue.Queue):
        for ip in net:
            ip_str = str(ip)
            for p in ports:
                res = scan_port(ip_str, p)
                if res:
                    q.put(("row", ip_str, res["port"], res["banner"][:100]))
            q.put(("progress",))            # jedno „tik” po przeskanowaniu hosta
        q.put(("done",))

    def process_queue(self):
        try:
            while True:
                item = self.task_q.get_nowait()
                tag = item[0]
                if tag == "row":
                    _, ip, port, banner = item
                    self.tree.insert("", "end", values=(ip, port, banner))
                elif tag == "progress":
                    self.pbar.step(1)
                elif tag == "done":
                    self.pbar.stop()
        except queue.Empty:
            # nic w kolejce – sprawdzimy znowu za QUE_POLL_MS
            pass
        finally:
            self.after(QUE_POLL_MS, self.process_queue)

if __name__ == "__main__":
    ScannerApp().mainloop()
