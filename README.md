# ndpi-observe

TC eBPF + nDPI traffic classifier for any Linux interface.
> **Status: pre-production.** Lab-validated on our own bench, not yet deployed in
> production. Any performance figures below are bench measurements, not production
> telemetry.
Classifies 450+ protocols (YouTube, TLS, DNS, SIP, BitTorrent, …) using [nDPI](https://github.com/ntop/nDPI).
After the first ~8 packets per flow, all subsequent packets are counted **entirely in-kernel** via `BPF_PERCPU_ARRAY` — zero userspace copies.
```
$ sudo ndpictl show applications top 5
Application                    Flows    Packets          Bytes        %
TLS                               12       4821        5621088    44.1%
YouTube                            2       1203        2218044    17.4%
DNS                               31        412          38220     0.3%
$ sudo ndpictl show stats
flows created:     45
flows classified:  43
flows gave up:      2
packets scanned:   344
packets cached:  189422    ← fast path (in-kernel)
```
## Quick start
```bash
# One-command demo (ndpid + Prometheus + Grafana)
IFACE=eth0 docker compose -f compose.demo.yaml up
# Grafana at http://localhost:3000
```
Or run directly:
```bash
sudo ndpid -i wlan0          # observe WiFi traffic
sudo ndpictl show applications top 10
```
## Build
```bash
# Inside Docker (recommended)
docker compose run --rm build
# Native (Ubuntu 22.04+)
sudo apt install clang llvm libbpf-dev libndpi-dev bpftool
make
```
## Test
```bash
docker compose run --rm test
```
## Why not nDPId / ntopng?
| Tool         | nDPI | eBPF fast path | Prometheus | Docker one-liner |
|--------------|------|----------------|------------|------------------|
| nDPId        | ✅   | ❌ all pkts copied | ❌     | ❌               |
| ntopng       | ✅   | ❌             | ❌         | ❌               |
| ayaFlow      | ❌ L4 only | ✅        | ✅         | ❌               |
| **ndpi-observe** | ✅ | ✅ (after 8 pkts) | ✅    | ✅               |
## Install (Debian/Ubuntu)
```bash
wget https://github.com/packetlens/ndpi-observe/releases/latest/download/ndpi-observe_amd64.deb
sudo apt install ./ndpi-observe_amd64.deb
```
Or via APT:
```bash
curl -fsSL https://packetlens.github.io/ndpi-observe/gpg.key | sudo apt-key add -
echo "deb https://packetlens.github.io/ndpi-observe stable main" \
  | sudo tee /etc/apt/sources.list.d/ndpi-observe.list
sudo apt update && sudo apt install ndpi-observe
```
## License
Apache 2.0 (userspace) / GPL 2.0 (eBPF program in `bpf/`)
