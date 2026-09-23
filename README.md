# NIDS — Network Intrusion Detection System Project

![image projet](assets/nids.jpg)

A Network Intrusion Detection System written in Go, built on top of [`gopacket`](https://github.com/google/gopacket). It captures live traffic on a network interface, tracks per-IP behavioral statistics over sliding time windows, and flags patterns associated with common reconnaissance and flooding attacks.

## Goal

Built to gain practical experience in analyzing network traffic and exploring the foundations of cybersecurity. It showcases the ability to write efficient Go code and design systems capable of handling complex, simultaneous tasks.


## Detected attack patterns

| Attack type | Mechanism |
|---|---|
| TCP SYN flood | SYN count minus ACK count exceeds threshold |
| Port scan | Number of distinct destination ports touched exceeds threshold |
| TCP FIN scan/flood | Excessive FIN flags |
| TCP NULL scan | Packets with no TCP flags set |
| TCP XMAS scan | Packets with FIN + URG + PSH set simultaneously |
| SSH brute-force | Excessive packets to port 22 |
| ICMP flood | Excessive ICMP packet count |
| UDP flood | Excessive UDP packet count |
| DNS amplification | DNS responses exceed DNS requests by a threshold |
| ARP spoofing | A new MAC address replies for an IP already bound to a different MAC |

## How it works

1. **Capture** — packets are pulled live from a network interface via `pcap`and streamed through a buffered channel to a separate processing goroutine.
2. **Per-IP state** — for each source IP, the IDS maintains a struct (`ipInfo`) of counters: SYN/ACK/FIN counts, distinct destination ports touched, ICMP/UDP/DNS counts, and the MAC address last seen replying via ARP for that IP.
3. **Sliding window** — state resets every `PERIOD` seconds. The previous window (`Memory.Previous`) is kept alongside the current one (`Memory.Current`), so detection can reason across two consecutive windows rather than only the most recent few seconds.
4. **Detection** — after each state update, the relevant counters are checked against fixed thresholds. Detection logic (`detect.go`) only reads `ipInfo`/`IDS` state and never touches `gopacket`/`layers` types directly.
5. **Logging** — detections and periodic traffic summaries (packet count, packets/sec) are appended to `ids.log` via a buffered writer, flushed on each tick and on shutdown.

## Architecture

```
src/main.go              orchestration: CLI, capture loop, windows and shutdown
src/config/               interface, whitelist, BPF filter and packet capture
src/memory/               per-IP state, sliding windows and ARP cache seeding
src/process/              packet validation and dispatch boundary
src/update/               IPv4/ARP/TCP/UDP/DNS counter updates
src/detect/               threshold-based attack detection
src/logger/               buffered log file output
```

The dependency direction is intentionally one-way: `main` coordinates the packages;
`process` delegates to `update`; `update` uses `memory` for state and `detect` for
threshold checks; `logger` is independent of application packages. This keeps packet
capture, state mutation, detection and output separate.

### Design decisions

- **Go prototype.** Go was chosen for fast iteration on detection logic;
- **Two-window memory model.** Keeping both the current and previous statistics window lets detection reason across window boundaries without unbounded memory growth.
- **Capture/processing decoupling.** Packet capture and processing run in separate goroutines connected by a buffered channel, so bursts of traffic don't block capture.
- **ARP cache seeding.** At the start of each window, the system's existing ARP cache is read to seed known IP-to-MAC bindings before live traffic is analyzed.

## Requirements

- Go (version per `go.mod`)
- [`libpcap`](https://www.tcpdump.org/) development headers (required by `gopacket/pcap`)
- Root privileges, or `CAP_NET_RAW`/`CAP_NET_ADMIN` on Linux, to open an interface in promiscuous mode

## Building

```bash
go build -o ids .
```

## Usage

```bash
sudo ./ids <interface name>
```

Example:
```bash
sudo ./ids eth0
```

On startup, the IDS resolves its own IP on the given interface, loads `whitelist.txt`, builds the BPF filter, opens the interface in promiscuous mode, seeds known IP-to-MAC bindings from the system ARP cache, and begins capturing. Stop with `Ctrl+C` or `SIGTERM`; a final summary is flushed to the log before exit.

## Configuration

| Setting | Description | Value |
|---|---|---|
| `PERIOD` | Length of each statistics window, in seconds | 4 |
| `CHANNELSIZE` | Buffer size of the packet channel | 10000 |
| `TimeLimite` | `pcap` read timeout, in milliseconds | 10 |
| `SNAPLEN` | Maximum bytes captured per packet | 1600 |
| `Promiscious` | Whether the interface opens in promiscuous mode | true |
| Whitelist | Path to a file listing IPs excluded from capture | `whitelist.txt` |

## Whitelist format

One IP per line. Lines starting with `#` and empty lines are ignored:

```
# Local gateway
192.168.1.1
```

## Logging

Output is appended to `ids.log` with a timestamp:

```
[Mon Jan 02 15:04:05 2006]  4 seconds summary: 132 packets of 4821  ||  33 packets per second  !!
[Mon Jan 02 15:04:09 2006]  [WARNING] Scan de ports détecté. (35 ports touchés) IP 192.168.1.42
```

The log file opens in append mode, so restarting the IDS preserves prior history.

## Dependencies

The runtime dependency set is deliberately small:

| Dependency | Role |
|---|---|
| `github.com/google/gopacket` | Packet decoding and live capture through `pcap` |
| `github.com/mostlygeek/arp` | Reading the local ARP cache for ARP spoofing checks |

`libpcap` remains a system dependency because `gopacket/pcap` uses CGO.

## Project layout

```
.
   src
    ├── config
    │   └── config.go
    ├── detect
    │   └── detect.go
    ├── go.mod
    ├── go.sum
    ├── ids
    ├── logger
    │   └── logger.go
    ├── main.go
    ├── memory
    │   └── memory.go
    ├── process
    │   └── process.go
    ├── types
    ├── update
    │   ├── update.go
    │   └── util.go
    └── whitelist.txt
            
```

## Testing setup

Detection is validated using two Ubuntu Server VMs on VirtualBox: one running the IDS against a network interface, and one generating both normal and attack traffic (`hping3` for SYN floods, `nmap -sN`/`-sX` for NULL/XMAS scans, ARP spoofing tools) to test detection thresholds.


## Disclaimer

This tool is built for educational purposes, to learn packet-level network programming and intrusion detection concepts. Running it against networks or systems you don't own or have explicit permission to monitor may be illegal in your jurisdiction.
