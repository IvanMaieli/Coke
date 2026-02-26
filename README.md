# Coke - Modern Enterprise Packet Analyzer

[![Build](https://img.shields.io/badge/Build-Passing-brightgreen.svg)]()
[![Platform](https://img.shields.io/badge/Platform-Linux-blue.svg)]()
[![Language](https://img.shields.io/badge/Language-C-orange.svg)]()

Coke is a lightning-fast, highly modular, and visually stunning command-line packet sniffer written in C. It features an interactive **ncurses** dashboard tailored for real-time packet inspection with a sleek "Ice" theme. 

## Key Features

- **Gorgeous "Ice" TUI**: A beautiful dashboard styled in Cyan, Blue, and White. Enjoy a top-level stats bar, scrollable packet list, detailed connection view, and an integrated hex dump window.
- **Advanced Query Engine**: Forget simple substrings. Press `f` to write complex queries using a tokenized key-value syntax. Filter streams instantly: `proto:tcp src:10.0.0.1 dst_port:443 len:>100`.
- **Conversation Reconstruction**: See an interesting packet? Press `v` to instantly filter the dashboard to that specific 4-tuple bidirectional conversation stream.
- **Real-Time Protocol Graphs**: Press `g` to flip the packet list into a live ASCII bar chart visualizing the volume of TCP, UDP, ICMP, and ARP traffic taking over your network.
- **PCAP Native**: Natively writes captured traffic into the standard `libpcap` format (`.pcap`) for Wireshark analysis without breaking a sweat.
- **Low Overhead Engine**: Captures using raw `AF_PACKET` sockets directly in kernel space, utilizing an internal fixed-size circular ring buffer.

## Prerequisites

- **Linux** (Requires raw sockets and `AF_PACKET`)
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
*The compiled enterprise binary will be placed inside `bin/coke`.*

## Usage

You must run Coke as `root` so it can open raw sockets.

```bash
sudo ./bin/coke [OPTIONS]
```

**Options:**
- `-f, --filter <query>`: Set an initial filter (e.g., `proto:tcp src:192.168`).
- `-o, --output <file.pcap>`: Write raw packets to a `.pcap` file!
- `-c, --capacity <number>`: Internal ring-buffer capacity (default: 10000).
- `-h, --help`: Show help.

### TUI Commands

While capturing, you can use the keyboard to navigate:

- `j`, `k`, `Up`, `Down`: Scroll through the packet list.
- `f`: Open the advanced filter prompt. Enter tokenized queries (e.g. `proto:tcp port:80 src:10.0.0.1`) or type `all` to reset.
- `v`: **Conversation View**. Highlight a TCP/UDP packet and press `v` to instantly reconstruct the bidirectional stream.
- `g`: **Graph View**. Toggle the beautiful live protocol statistics bar-chart.
- `c`: Clear buffer and reset packet statistics.
- `q`: Quit gracefully. 

---
*Stay cold.*
