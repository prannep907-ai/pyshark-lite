# PyShark Lite

A small Wireshark-style packet analyzer written in Python (Scapy + Tkinter).

## Features
- Live capture on any interface, with BPF capture filters (e.g. `tcp port 80`)
- Packet list colour-coded by protocol (TCP, HTTP, TLS, UDP, DNS, ICMP, ARP)
- Layer-by-layer packet details and hex/ASCII dump
- Quick display filter (`dns`, `icmp`, an IP address, a port...)
- **Follow TCP Stream**: select a TCP packet, click the button or right-click
- **Statistics**: packets/bytes per protocol and top talkers
- **Export CSV** of the visible packet list
- Save / open `.pcap` files (compatible with Wireshark)

## Install

    pip install -r requirements.txt

Linux also needs Tkinter: `sudo dnf install python3-tkinter` (Rocky/Fedora)
or `sudo apt install python3-tk` (Debian/Ubuntu).

## Run

    sudo -E python3 pyshark_lite.py

On Wayland you may first need: `xhost +SI:localuser:root`

## Quick test
1. Pick your interface (e.g. `wlo1`) and click **Start**
2. Run `ping -c 5 8.8.8.8` and `curl http://example.com`
3. Type `icmp` in the filter, or `-> 80 [` to show plain HTTP
4. Select an HTTP packet carrying data (flags `[PA]`) and click **Follow Stream**

Note: HTTPS (port 443) traffic is encrypted, so stream contents are unreadable.

## Tested on
Rocky Linux 10, Python 3.12, Scapy 2.6 / 2.7.

## Disclaimer
For educational use. Only capture traffic on networks you own or have
permission to monitor.

## License
MIT. See [LICENSE](LICENSE).
