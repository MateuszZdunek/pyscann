import threading, queue, ipaddress, tkinter as tk
from tkinter import ttk, messagebox
from scanner_core_sync import scan_subnet, DEFAULT_PORTS

QUE_POLL_MS = 80

PORT_DESC = {
    22:   "SSH",
    80:   "HTTP",
    443:  "HTTPS",
    3389: "RDP",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
}

class ScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Simple Network Scanner")
        self.geometry("830x560")
        self.stop_flag = threading.Event()
        self.task_q: queue.Queue = queue.Queue()
        self._build_widgets()

    def _build_widgets(self):
        top = ttk.Frame(self, padding=10); top.pack(fill="x")

        ttk.Label(top, text="Subnet (CIDR):").grid(row=0, column=0, sticky="w")
        self.ent_sub = ttk.Entry(top, width=25)
        self.ent_sub.insert(0, "192.168.1.0/24")
        self.ent_sub.grid(row=0, column=1, padx=5)

        ttk.Label(top, text="Ports:").grid(row=1, column=0, sticky="w")
        self.ent_ports = ttk.Entry(top, width=25)
        self.ent_ports.insert(0, ",".join(map(str, DEFAULT_PORTS)))
        self.ent_ports.grid(row=1, column=1, padx=5)

        ttk.Button(top, text="Scan", command=self.start_scan).grid(row=0, column=2, rowspan=2, padx=5)
        ttk.Button(top, text="Stop", command=self.stop_scan).grid(row=0, column=3, rowspan=2, padx=5)

        self.pbar = ttk.Progressbar(top, length=250, mode="determinate")
        self.pbar.grid(row=0, column=4, rowspan=2, padx=10)
        self.lbl_status = ttk.Label(top, text="Ready", width=35)
        self.lbl_status.grid(row=0, column=5, rowspan=2)

        cols = ("ip", "port", "banner")
        self.tree = ttk.Treeview(self, columns=cols, show="headings")
        for c in cols:
            self.tree.heading(c, text=c.upper())
            self.tree.column(c, anchor="w", width=150 if c != "banner" else 480)
        self.tree.pack(fill="both", expand=True, padx=10, pady=10)

    def start_scan(self):
        subnet = self.ent_sub.get().strip()
        try:
            ports = list(map(int, self.ent_ports.get().split(",")))
        except ValueError:
            messagebox.showerror("Error", "Ports must be comma-separated integers")
            return

        self.stop_flag.clear()
        self.tree.delete(*self.tree.get_children())
        self.task_q.queue.clear()
        net = ipaddress.ip_network(subnet, strict=False)
        self.pbar.configure(maximum=net.num_addresses, value=0)
        self.lbl_status.config(text="Starting…")

        threading.Thread(target=self.worker_scan, args=(subnet, ports), daemon=True).start()
        self.after(QUE_POLL_MS, self.process_queue)

    def stop_scan(self):
        self.stop_flag.set()
        self.lbl_status.config(text="Stopped by user")

    def worker_scan(self, subnet, ports):
        try:
            data = scan_subnet(subnet, ports, self.stop_flag)
            for host in data:
                for p in host["ports"]:
                    desc = PORT_DESC.get(p["port"], "")
                    port_txt = f"{p['port']} ({desc})" if desc else str(p['port'])
                    self.task_q.put(("row", host["ip"], port_txt, p["banner"][:120]))
                self.task_q.put(("progress",))
            self.task_q.put(("done",))
        except Exception as e:
            self.task_q.put(("error", str(e)))

    def process_queue(self):
        try:
            while True:
                tag, *payload = self.task_q.get_nowait()
                if tag == "row":
                    ip, port_txt, banner = payload
                    self.tree.insert("", "end", values=(ip, port_txt, banner))
                elif tag == "progress":
                    self.pbar.step(1)
                elif tag == "done":
                    self.pbar.stop()
                elif tag == "error":
                    self.pbar.stop()
                    self.lbl_status.config(text="Error occurred")
                    messagebox.showerror("Scan Error", payload[0])
        except queue.Empty:
            pass
        if not self.stop_flag.is_set():
            self.after(QUE_POLL_MS, self.process_queue)

if __name__ == "__main__":
    ScannerApp().mainloop()
