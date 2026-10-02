# PyShark Lite

A small Wireshark-style packet analyzer written in Python (Scapy + Tkinter).

## Features
- Live capture on any interface with BPF capture filters
- Packet list, layer-by-layer details, hex/ASCII dump
- Quick display filter
- Save/open `.pcap` files (compatible with Wireshark)

## Install
```bash
pip install -r requirements.txt
```
Linux also needs Tkinter (`sudo dnf install python3-tkinter` or `sudo apt install python3-tk`).

## Run
```bash
sudo -E python3 pyshark_lite.py
```
On Wayland you may first need: `xhost +SI:localuser:root`

## Disclaimer
For educational use. Only capture traffic on networks you own or have permission to monitor.
