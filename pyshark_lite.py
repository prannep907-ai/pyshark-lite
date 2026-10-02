#!/usr/bin/env python3
"""PyShark Lite - a small Wireshark-style packet analyzer (Scapy + Tkinter)."""

import queue
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from scapy.all import (
    ARP, DNS, ICMP, IP, TCP, UDP, Ether, IPv6, Raw,
    get_if_list, rdpcap, sniff, wrpcap,
)
from scapy.utils import hexdump


def summarize(pkt):
    """Return (src, dst, protocol, info) for a packet."""
    src = dst = ""
    proto = pkt.lastlayer().name
    info = pkt.summary()

    if pkt.haslayer(ARP):
        a = pkt[ARP]
        src, dst, proto = a.psrc, a.pdst, "ARP"
        info = (f"Who has {a.pdst}? Tell {a.psrc}" if a.op == 1
                else f"{a.psrc} is at {a.hwsrc}")
        return src, dst, proto, info

    if pkt.haslayer(IP):
        src, dst = pkt[IP].src, pkt[IP].dst
    elif pkt.haslayer(IPv6):
        src, dst = pkt[IPv6].src, pkt[IPv6].dst
    elif pkt.haslayer(Ether):
        src, dst = pkt[Ether].src, pkt[Ether].dst

    if pkt.haslayer(DNS):
        d = pkt[DNS]
        proto = "DNS"
        try:
            q = d.qd.qname.decode(errors="ignore") if d.qd else ""
        except Exception:
            q = ""
        info = f"{'Response' if d.qr else 'Query'} {q}"
    elif pkt.haslayer(TCP):
        t = pkt[TCP]
        proto = "TCP"
        if 80 in (t.sport, t.dport):
            proto = "HTTP"
        elif 443 in (t.sport, t.dport):
            proto = "TLS/HTTPS"
        info = f"{t.sport} -> {t.dport} [{t.sprintf('%flags%')}] Seq={t.seq} Ack={t.ack} Win={t.window}"
    elif pkt.haslayer(UDP):
        u = pkt[UDP]
        proto = "UDP"
        info = f"{u.sport} -> {u.dport} Len={u.len}"
    elif pkt.haslayer(ICMP):
        proto = "ICMP"
        info = pkt[ICMP].sprintf("%ICMP.type%")
    return src, dst, proto, info


class App(tk.Tk):
    COLORS = {
        "TCP": "#e7e6ff", "HTTP": "#e4ffc7", "TLS/HTTPS": "#d6e8ff",
        "UDP": "#daeeff", "DNS": "#fff3c4", "ICMP": "#fce0ff", "ARP": "#faf0d7",
    }

    def __init__(self):
        super().__init__()
        self.title("PyShark Lite")
        self.geometry("1150x750")

        self.packets = []
        self.rows = []
        self.q = queue.Queue()
        self.stop_event = threading.Event()
        self.thread = None
        self.start_time = None

        self._build_toolbar()
        self._build_panes()
        self._build_statusbar()
        self.after(100, self._drain_queue)

    def _build_toolbar(self):
        bar = ttk.Frame(self, padding=4)
        bar.pack(fill="x")

        ttk.Label(bar, text="Interface:").pack(side="left")
        self.iface = ttk.Combobox(bar, values=get_if_list(), width=22)
        if self.iface["values"]:
            self.iface.current(0)
        self.iface.pack(side="left", padx=4)

        ttk.Label(bar, text="Capture filter (BPF):").pack(side="left")
        self.bpf = ttk.Entry(bar, width=20)
        self.bpf.pack(side="left", padx=4)

        self.btn_start = ttk.Button(bar, text="▶ Start", command=self.start)
        self.btn_start.pack(side="left", padx=2)
        self.btn_stop = ttk.Button(bar, text="■ Stop", command=self.stop, state="disabled")
        self.btn_stop.pack(side="left", padx=2)
        ttk.Button(bar, text="Clear", command=self.clear).pack(side="left", padx=2)
        ttk.Button(bar, text="Open…", command=self.open_pcap).pack(side="left", padx=2)
        ttk.Button(bar, text="Save…", command=self.save_pcap).pack(side="left", padx=2)

        ttk.Label(bar, text="  Display filter:").pack(side="left")
        self.dfilter = tk.StringVar()
        e = ttk.Entry(bar, textvariable=self.dfilter, width=22)
        e.pack(side="left", padx=4)
        e.bind("<Return>", lambda _e: self.refresh_table())
        ttk.Button(bar, text="Apply", command=self.refresh_table).pack(side="left")

    def _build_panes(self):
        paned = ttk.PanedWindow(self, orient="vertical")
        paned.pack(fill="both", expand=True)

        top = ttk.Frame(paned)
        cols = ("no", "time", "src", "dst", "proto", "len", "info")
        self.tree = ttk.Treeview(top, columns=cols, show="headings", selectmode="browse")
        widths = (60, 80, 160, 160, 90, 60, 520)
        for c, w in zip(cols, widths):
            self.tree.heading(c, text=c.capitalize())
            self.tree.column(c, width=w, anchor="w")
        for proto, color in self.COLORS.items():
            self.tree.tag_configure(proto, background=color)
        sb = ttk.Scrollbar(top, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        paned.add(top, weight=3)

        mid = ttk.Frame(paned)
        self.details = ttk.Treeview(mid, show="tree")
        sb2 = ttk.Scrollbar(mid, orient="vertical", command=self.details.yview)
        self.details.configure(yscrollcommand=sb2.set)
        self.details.pack(side="left", fill="both", expand=True)
        sb2.pack(side="right", fill="y")
        paned.add(mid, weight=2)

        bot = ttk.Frame(paned)
        self.hex = tk.Text(bot, height=8, font=("Courier", 10), wrap="none")
        sb3 = ttk.Scrollbar(bot, orient="vertical", command=self.hex.yview)
        self.hex.configure(yscrollcommand=sb3.set)
        self.hex.pack(side="left", fill="both", expand=True)
        sb3.pack(side="right", fill="y")
        paned.add(bot, weight=2)

    def _build_statusbar(self):
        self.status = tk.StringVar(value="Ready")
        ttk.Label(self, textvariable=self.status, relief="sunken", anchor="w").pack(fill="x")

    def start(self):
        if self.thread and self.thread.is_alive():
            return
        self.stop_event.clear()
        if not self.packets:
            self.start_time = time.time()
        iface = self.iface.get().strip() or None
        bpf = self.bpf.get().strip() or None
        self.thread = threading.Thread(target=self._capture, args=(iface, bpf), daemon=True)
        self.thread.start()
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        self.status.set(f"Capturing on {iface or 'default'}…")

    def _capture(self, iface, bpf):
        try:
            while not self.stop_event.is_set():
                sniff(iface=iface, filter=bpf, store=False, timeout=1,
                      prn=lambda p: self.q.put(p))
        except Exception as exc:
            self.q.put(exc)

    def stop(self):
        self.stop_event.set()
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")
        self.status.set(f"Stopped – {len(self.packets)} packets")

    def _drain_queue(self):
        added = 0
        while True:
            try:
                item = self.q.get_nowait()
            except queue.Empty:
                break
            if isinstance(item, Exception):
                self.stop()
                messagebox.showerror(
                    "Capture error",
                    f"{item}\n\nTip: run as root and make sure libpcap is installed.")
                continue
            self._add_packet(item)
            added += 1
        if added and not self.stop_event.is_set():
            self.status.set(f"Capturing… {len(self.packets)} packets")
        self.after(100, self._drain_queue)

    def _add_packet(self, pkt):
        idx = len(self.packets)
        self.packets.append(pkt)
        ts = float(pkt.time) - (self.start_time or float(pkt.time))
        src, dst, proto, info = summarize(pkt)
        self.rows.append((idx + 1, f"{ts:.6f}", src, dst, proto, len(pkt), info))
        if self._matches(self.rows[-1]):
            self._insert_row(idx)

    def _insert_row(self, idx):
        row = self.rows[idx]
        self.tree.insert("", "end", iid=str(idx), values=row, tags=(row[4],))
        if not self.stop_event.is_set():
            self.tree.yview_moveto(1)

    def _matches(self, row):
        f = self.dfilter.get().strip().lower()
        return not f or f in " ".join(str(c) for c in row).lower()

    def refresh_table(self):
        self.tree.delete(*self.tree.get_children())
        for i, row in enumerate(self.rows):
            if self._matches(row):
                self._insert_row(i)

    def clear(self):
        self.packets.clear()
        self.rows.clear()
        self.tree.delete(*self.tree.get_children())
        self.details.delete(*self.details.get_children())
        self.hex.delete("1.0", "end")
        self.start_time = None
        self.status.set("Cleared")

    def on_select(self, _event):
        sel = self.tree.selection()
        if not sel:
            return
        pkt = self.packets[int(sel[0])]

        self.details.delete(*self.details.get_children())
        layer = pkt
        while layer and layer.name != "NoPayload":
            node = self.details.insert("", "end", text=layer.name, open=True)
            for fname, val in layer.fields.items():
                self.details.insert(node, "end", text=f"{fname}: {val}")
            layer = layer.payload
        if pkt.haslayer(Raw):
            raw = bytes(pkt[Raw].load)
            text = raw[:200].decode("utf-8", errors="replace")
            self.details.insert("", "end", text=f"Payload preview: {text!r}")

        self.hex.delete("1.0", "end")
        self.hex.insert("1.0", hexdump(pkt, dump=True))

    def save_pcap(self):
        if not self.packets:
            messagebox.showinfo("Save", "Nothing to save.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".pcap",
                                            filetypes=[("PCAP", "*.pcap")])
        if path:
            wrpcap(path, self.packets)
            self.status.set(f"Saved {len(self.packets)} packets to {path}")

    def open_pcap(self):
        path = filedialog.askopenfilename(filetypes=[("PCAP", "*.pcap *.pcapng")])
        if not path:
            return
        self.stop()
        self.clear()
        pkts = rdpcap(path)
        if len(pkts):
            self.start_time = float(pkts[0].time)
        for p in pkts:
            self.rows  # keep linter quiet
            self._add_packet(p)
        self.status.set(f"Loaded {len(pkts)} packets from {path}")


if __name__ == "__main__":
    App().mainloop()
