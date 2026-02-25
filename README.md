# Coca — Minimalist Packet Sniffer Engine

Coca is a fast, modular, command-line packet sniffer written in C, featuring an interactive **ncurses** dashboard for real-time packet inspection.

## Features

- **Interactive TUI**: Top-top stats bar, scrollable packet list, connection detail view, and bottom hex dump. Wait for packets, then freely examine.
- **Protocol Dissectors**: Automatically parses Ethernet, IPv4, TCP, UDP, ICMP, and ARP packets with live flag decode and sequence numbering.
- **Real-Time Filtering**: Press `f` during capture to instantly filter views by `tcp`, `udp`, `icmp`, `arp`, or via basic source/destination IP substrings.
- **PCAP Export**: Natively writes captured traffic into the standard `libpcap` format (`.pcap`) for later analysis in Wireshark.
- **Low Overhead**: Captures using raw AF_PACKET sockets directly in the kernel space. Uses an internal fixed-size circular ring buffer.

## Prerequisites

- **Linux** (uses raw sockets and AF_PACKET)
- `gcc`, `make`
- `ncurses` development library (`libncurses-dev` or `ncurses-devel`)

```bash
sudo apt-get update
sudo apt-get install build-essential libncurses-dev
```

## Build

```bash
make clean && make
```
*The compiled binary will be placed inside `bin/coca`.*

## Usage

You must run Coca as `root` so it can open raw sockets.

```bash
sudo ./bin/coca [OPTIONS]
```

**Options:**
- `-f, --filter <proto>`: Initial filter (e.g., `tcp`, `arp`). Default is all.
- `-o, --output <file.pcap>`: Write raw packets to a `.pcap` file for Wireshark!
- `-c, --capacity <number>`: Internal ring-buffer capacity (default: 10000)
- `-h, --help`: Show help

### TUI Commands

While capturing, you can use the keyboard to navigate:

- `j`, `k`, `Up`, `Down`: Scroll packet list.
- `f`: Open filter prompt. Type `tcp`, `udp`, `icmp`, `arp`, an IP substring, or `all` to clear.
- `c`: Clear buffer and reset packet statistics.
- `q`: Quit gracefully. 

---
*Stay cold. 🧊*
