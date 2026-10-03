#!/usr/bin/env python3
# Copyright (c) 2026 Pranjeyy - MIT License
"""
PyShark Lite - a small Wireshark-style packet analyzer built with Scapy + Tkinter.

Features
  * Live capture on any interface, with BPF capture filter (e.g. "tcp port 80")
  * Packet list, layer-by-layer details tree, hex/ASCII dump
  * Quick text display filter (e.g. "dns", "192.168.1.5", "443")
  * Follow TCP Stream  (select a TCP packet -> button, or right-click)
  * Protocol statistics (packets/bytes per protocol, top talkers)
  * Export the visible packet list to CSV
  * Save / open .pcap files (compatible with Wireshark)

Setup
  pip install scapy
  Linux : sudo -E python3 pyshark_lite.py   (Wayland: xhost +SI:localuser:root first)

Only capture traffic on networks you own or have permission to monitor.
"""

import csv
import queue
import threading
import time
import tkinter as tk
from collections import Counter
from tkinter import filedialog, messagebox, ttk

from scapy.all import (
    ARP, DNS, ICMP, IP, TCP, UDP, Ether, IPv6, Raw,
    get_if_list, rdpcap, sniff, wrpcap,
)
from scapy.utils import hexdump


# ----------------------------------------------------------------- analysis
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
        info = (f"{t.sport} -> {t.dport} [{t.sprintf('%flags%')}] "
                f"Seq={t.seq} Ack={t.ack} Win={t.window}")
    elif pkt.haslayer(UDP):
        u = pkt[UDP]
        proto = "UDP"
        info = f"{u.sport} -> {u.dport} Len={u.len}"
    elif pkt.haslayer(ICMP):
        proto = "ICMP"
        info = pkt[ICMP].sprintf("%ICMP.type%")
    return src, dst, proto, info


def stream_key(pkt):
    """Direction-independent key identifying a TCP conversation, or None."""
    if not pkt.haslayer(TCP):
        return None
    if pkt.haslayer(IP):
        ip = pkt[IP]
    elif pkt.haslayer(IPv6):
        ip = pkt[IPv6]
    else:
        return None
    t = pkt[TCP]
    return tuple(sorted(((ip.src, t.sport), (ip.dst, t.dport))))


def printable(data):
    """Bytes -> text, replacing non-printable bytes with '.' (keeps newlines)."""
    return "".join(
        chr(b) if 32 <= b < 127 or b in (9, 10, 13) else "." for b in data
    ).replace("\r\n", "\n")


# --------------------------------------------------------------------- GUI
class App(tk.Tk):
    COLORS = {
        "TCP": "#e7e6ff", "HTTP": "#e4ffc7", "TLS/HTTPS": "#d6e8ff",
        "UDP": "#daeeff", "DNS": "#fff3c4", "ICMP": "#fce0ff", "ARP": "#faf0d7",
    }

    def __init__(self):
        super().__init__()
        self.title("PyShark Lite")
        self.geometry("1250x750")

        self.packets = []            # raw scapy packets
        self.rows = []               # (no, time, src, dst, proto, len, info)
        self.q = queue.Queue()
        self.stop_event = threading.Event()
        self.thread = None
        self.start_time = None

        self._build_toolbar()
        self._build_panes()
        self._build_statusbar()
        self.after(100, self._drain_queue)

    # ---- layout
    def _build_toolbar(self):
        bar = ttk.Frame(self, padding=4)
        bar.pack(fill="x")

        ttk.Label(bar, text="Interface:").pack(side="left")
        self.iface = ttk.Combobox(bar, values=get_if_list(), width=16)
        if self.iface["values"]:
            self.iface.current(0)
        self.iface.pack(side="left", padx=4)

        ttk.Label(bar, text="Capture filter:").pack(side="left")
        self.bpf = ttk.Entry(bar, width=16)
        self.bpf.pack(side="left", padx=4)

        self.btn_start = ttk.Button(bar, text="▶ Start", command=self.start)
        self.btn_start.pack(side="left", padx=2)
        self.btn_stop = ttk.Button(bar, text="■ Stop", command=self.stop, state="disabled")
        self.btn_stop.pack(side="left", padx=2)
        ttk.Button(bar, text="Clear", command=self.clear).pack(side="left", padx=2)
        ttk.Button(bar, text="Open…", command=self.open_pcap).pack(side="left", padx=2)
        ttk.Button(bar, text="Save…", command=self.save_pcap).pack(side="left", padx=2)
        ttk.Button(bar, text="Export CSV…", command=self.export_csv).pack(side="left", padx=2)
        ttk.Button(bar, text="Follow Stream", command=self.follow_stream).pack(side="left", padx=2)
        ttk.Button(bar, text="Statistics", command=self.show_stats).pack(side="left", padx=2)

        ttk.Label(bar, text=" Filter:").pack(side="left")
        self.dfilter = tk.StringVar()
        e = ttk.Entry(bar, textvariable=self.dfilter, width=16)
        e.pack(side="left", padx=4)
        e.bind("<Return>", lambda _e: self.refresh_table())
        ttk.Button(bar, text="Apply", command=self.refresh_table).pack(side="left")

    def _build_panes(self):
        paned = ttk.PanedWindow(self, orient="vertical")
        paned.pack(fill="both", expand=True)

        top = ttk.Frame(paned)
        cols = ("no", "time", "src", "dst", "proto", "len", "info")
        self.tree = ttk.Treeview(top, columns=cols, show="headings", selectmode="browse")
        widths = (60, 80, 160, 160, 90, 60, 560)
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
        self.tree.bind("<Button-3>", self._context_menu)
        paned.add(top, weight=3)

        self.menu = tk.Menu(self, tearoff=0)
        self.menu.add_command(label="Follow TCP Stream", command=self.follow_stream)

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

    # ---- capture
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
        except Exception as exc:  # permissions, bad filter, ...
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

    # ---- packet table
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

    # ---- details
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

    def _context_menu(self, event):
        row = self.tree.identify_row(event.y)
        if row:
            self.tree.selection_set(row)
            self.menu.tk_popup(event.x_root, event.y_root)

    # ---- Follow TCP stream
    def follow_stream(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Follow Stream", "Select a TCP packet first.")
            return
        key = stream_key(self.packets[int(sel[0])])
        if key is None:
            messagebox.showinfo("Follow Stream", "The selected packet is not TCP.")
            return

        client = None
        segments = []     # (is_client, bytes)
        seen = set()      # skip retransmissions
        for p in self.packets:
            if stream_key(p) != key:
                continue
            ip = p[IP] if p.haslayer(IP) else p[IPv6]
            sender = (ip.src, p[TCP].sport)
            if client is None:
                client = sender
            if not p.haslayer(Raw):
                continue
            data = bytes(p[Raw].load)
            mark = (sender, p[TCP].seq, len(data))
            if mark in seen:
                continue
            seen.add(mark)
            segments.append((sender == client, data))

        win = tk.Toplevel(self)
        win.title(f"Follow TCP Stream: {key[0][0]}:{key[0][1]} <-> {key[1][0]}:{key[1][1]}")
        win.geometry("800x550")

        c_bytes = sum(len(d) for c, d in segments if c)
        s_bytes = sum(len(d) for c, d in segments if not c)
        ttk.Label(
            win,
            text=(f"Client {client[0]}:{client[1]} → red ({c_bytes} bytes)    "
                  f"Server → blue ({s_bytes} bytes)"),
        ).pack(anchor="w", padx=6, pady=4)

        frame = ttk.Frame(win)
        frame.pack(fill="both", expand=True)
        text = tk.Text(frame, wrap="word", font=("Courier", 10))
        sb = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=sb.set)
        text.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        text.tag_configure("client", foreground="#b00020", background="#fff0f0")
        text.tag_configure("server", foreground="#0b3d91", background="#f0f5ff")

        if not segments:
            text.insert("end", "No payload data in this stream (handshake/ACKs only).")
        else:
            for is_client, data in segments:
                text.insert("end", printable(data) + "\n",
                            "client" if is_client else "server")
            if key[0][1] == 443 or key[1][1] == 443:
                text.insert("end", "\n[Port 443: traffic is TLS-encrypted, so "
                                   "the content above is unreadable by design.]")

        def save_raw():
            path = filedialog.asksaveasfilename(parent=win, defaultextension=".txt")
            if path:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(text.get("1.0", "end"))

        ttk.Button(win, text="Save as text…", command=save_raw).pack(pady=4)

    # ---- statistics
    def show_stats(self):
        if not self.rows:
            messagebox.showinfo("Statistics", "No packets captured yet.")
            return

        pkts = Counter(r[4] for r in self.rows)
        size = Counter()
        talkers = Counter()
        for r in self.rows:
            size[r[4]] += r[5]
            if r[2]:
                talkers[r[2]] += 1
        total = len(self.rows)

        win = tk.Toplevel(self)
        win.title("Protocol Statistics")
        win.geometry("760x620")
        ttk.Label(win, text=f"{total} packets, {sum(size.values())} bytes total",
                  font=("TkDefaultFont", 11, "bold")).pack(anchor="w", padx=8, pady=6)

        # bar chart (packets per protocol)
        protos = pkts.most_common(10)
        canvas = tk.Canvas(win, height=26 * len(protos) + 10, bg="white",
                           highlightthickness=1, highlightbackground="#ccc")
        canvas.pack(fill="x", padx=8)
        biggest = protos[0][1]
        for i, (name, n) in enumerate(protos):
            y = 8 + i * 26
            width = int(450 * n / biggest)
            canvas.create_text(8, y + 9, text=name, anchor="w")
            canvas.create_rectangle(120, y, 120 + width, y + 18,
                                    fill=self.COLORS.get(name, "#dddddd"),
                                    outline="#888")
            canvas.create_text(128 + width, y + 9, anchor="w",
                               text=f"{n} ({100 * n / total:.1f}%)")

        # table per protocol
        ttk.Label(win, text="Per protocol").pack(anchor="w", padx=8, pady=(10, 0))
        t1 = ttk.Treeview(win, columns=("proto", "pkts", "pct", "bytes"),
                          show="headings", height=6)
        for c, label, w in (("proto", "Protocol", 160), ("pkts", "Packets", 100),
                            ("pct", "% of packets", 110), ("bytes", "Bytes", 120)):
            t1.heading(c, text=label)
            t1.column(c, width=w)
        for name, n in pkts.most_common():
            t1.insert("", "end", values=(name, n, f"{100 * n / total:.1f}", size[name]))
        t1.pack(fill="x", padx=8)

        # top talkers
        ttk.Label(win, text="Top talkers (by packets sent)").pack(anchor="w", padx=8, pady=(10, 0))
        t2 = ttk.Treeview(win, columns=("addr", "pkts"), show="headings", height=8)
        t2.heading("addr", text="Source address")
        t2.heading("pkts", text="Packets")
        t2.column("addr", width=300)
        t2.column("pkts", width=100)
        for addr, n in talkers.most_common(10):
            t2.insert("", "end", values=(addr, n))
        t2.pack(fill="x", padx=8, pady=(0, 8))

    # ---- files
    def export_csv(self):
        visible = [self.rows[int(i)] for i in self.tree.get_children()]
        if not visible:
            messagebox.showinfo("Export CSV", "Nothing to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv",
                                            filetypes=[("CSV", "*.csv")])
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["No", "Time", "Source", "Destination", "Protocol", "Length", "Info"])
            w.writerows(visible)
        self.status.set(f"Exported {len(visible)} rows to {path}")

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
            self._add_packet(p)
        self.status.set(f"Loaded {len(pkts)} packets from {path}")


if __name__ == "__main__":
    App().mainloop()
