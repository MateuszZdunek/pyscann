# app_gui_sync.py
import threading, tkinter as tk
from tkinter import ttk, filedialog, messagebox
from scanner_core_sync import scan_subnet, DEFAULT_PORTS

class ScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Simple Network Scanner")
        self.geometry("750x460")
        self._build_widgets()

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

        self.tree = ttk.Treeview(self, columns=("port", "banner"), show="headings")
        self.tree.heading("port", text="Port")
        self.tree.heading("banner", text="Banner / Info")
        self.tree.column("port", width=60, anchor="center")
        self.tree.column("banner", width=620)
        self.tree.pack(fill="both", expand=True, padx=10, pady=10)

    # ---------- scanning ----------
    def start_scan(self):
        subnet = self.ent_sub.get().strip()
        try:
            ports = list(map(int, self.ent_ports.get().split(",")))
        except ValueError:
            messagebox.showerror("Error", "Ports must be comma-separated integers")
            return
        self.tree.delete(*self.tree.get_children())
        threading.Thread(
            target=self.run_scan,
            args=(subnet, ports),
            daemon=True
        ).start()

    def run_scan(self, subnet, ports):
        data = scan_subnet(subnet, ports)
        # wrzucamy wyniki do GUI w wątku głównym (tk is not thread-safe)
        self.after(0, self.populate_tree, data)

    def populate_tree(self, data):
        for host in data:
            for p in host["ports"]:
                self.tree.insert(
                    "", "end",
                    values=(f"{host['ip']}:{p['port']}", p["banner"][:80])
                )

if __name__ == "__main__":
    ScannerApp().mainloop()
