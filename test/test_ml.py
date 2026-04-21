"""
ML vs no-ML comparison test.

Sends diverse traffic to two ndpid instances:
  - ndpid-noml:  --no-ml flag  (stock nDPI: no giveup, no ML)
  - ndpid-ml:    default       (nDPI + ndpi_detection_giveup + RF model)

Traffic mix:
  1. Proper TLS with SNI  → classified by nDPI immediately (both daemons)
  2. Random payloads to port 443/80/53/8080 → giveup guesses; stock: GAVE_UP
  3. Truly random payloads to ephemeral ports → gave_up on both

Comparison metric: flows_gave_up / flows_created (% unknown)

Run inside CI container (needs root):
    pytest test/test_ml.py -v -s
"""

import os
import socket
import struct
import subprocess
import signal
import time
import math

import pytest

from test_ndpi_observe import (
    _build_eth_ip_tcp,
    _tls_client_hello,
    _pad_frame,
    _ip_checksum,
)

SRC_DIR      = os.environ.get("SRC_DIR", "/src")
NDPID_SIMPLE = os.path.join(SRC_DIR, "ndpid-simple")   # AF_PACKET — no ring-buffer drops
NDPICTL      = os.path.join(SRC_DIR, "ndpictl")

NOML_IFACE  = "veth-ml0"
NOML_PEER   = "veth-ml1"
NOML_IP     = "10.99.4.1"
NOML_SOCK   = "/run/ndpid-noml/cli.sock"
NOML_PORT   = 19193

ML_IFACE    = "veth-ml2"
ML_PEER     = "veth-ml3"
ML_IP       = "10.99.5.1"
ML_SOCK     = "/run/ndpid-ml/cli.sock"
ML_PORT     = 19192

# Traffic volume
N_TLS_FLOWS     = 20   # proper TLS with SNI  → nDPI classifies
N_PORT_FLOWS    = 40   # random payload to known ports → giveup classifies
N_RANDOM_FLOWS  = 20   # random payload to random ports → stays unknown
PKTS_PER_FLOW   = 9    # send > FLOW_MAX_CLASSIFY_PKTS (8) to trigger giveup path


def _run(cmd, check=True):
    return subprocess.run(cmd, shell=True, check=check,
                          capture_output=True, text=True)


def _ctl(sock_path, cmd):
    env = os.environ.copy()
    env["NDPID_SOCKET"] = sock_path
    r = subprocess.run([NDPICTL] + cmd.split(),
                       capture_output=True, text=True, timeout=5, env=env)
    return r.stdout


def _parse_stats(text):
    result = {}
    for line in text.splitlines():
        if ":" in line:
            k, v = line.rsplit(":", 1)
            try:
                result[k.strip()] = int(v.strip())
            except ValueError:
                pass
    return result


def _start_daemon(binary, iface, port, sock_path, extra_args=()):
    proc = subprocess.Popen(
        [binary, "-i", iface, "-p", str(port), "-s", sock_path] + list(extra_args),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        preexec_fn=os.setsid,
    )
    for _ in range(100):
        if os.path.exists(sock_path):
            break
        if proc.poll() is not None:
            out = proc.stdout.read().decode(errors="replace") if proc.stdout else ""
            pytest.fail(f"daemon exited early: rc={proc.returncode}\n{out}")
        time.sleep(0.1)
    else:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except Exception:
            pass
        pytest.fail(f"daemon failed to create CLI socket at {sock_path}")
    return proc


def _stop_daemon(proc, iface, sock_path):
    try:
        os.killpg(proc.pid, signal.SIGTERM)
        proc.wait(timeout=5)
    except Exception:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except Exception:
            pass
    _run(f"ip link del {iface} 2>/dev/null", check=False)
    _run(f"rm -f {sock_path}", check=False)


def _build_udp_frame(src_ip, dst_ip, sport, dport, payload):
    """Build a raw UDP Ethernet frame."""
    eth = b'\xff\xff\xff\xff\xff\xff' + b'\x02\x00\x00\x00\x00\x01' + b'\x08\x00'
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip_total = 20 + len(udp)
    ip_hdr = struct.pack('!BBHHHBBH4s4s',
        0x45, 0, ip_total, 0, 0, 64, 17, 0, src, dst)
    ip_hdr = ip_hdr[:10] + struct.pack('!H', _ip_checksum(ip_hdr)) + ip_hdr[12:]
    return _pad_frame(eth + ip_hdr + udp)


def _send_frames(iface, frames, count_each=PKTS_PER_FLOW):
    """Send each frame count_each times."""
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((iface, 0))
    for frame in frames:
        for _ in range(count_each):
            s.send(frame)
    s.close()


def _build_traffic(dst_ip):
    """
    Build three sets of frames:
      tls_frames:    proper TLS ClientHello → nDPI classifies immediately
      port_frames:   random payload to well-known ports → giveup rescues
      random_frames: random payload to high ports → truly unknown
    """
    tls_frames = []
    for i in range(N_TLS_FLOWS):
        payload = _tls_client_hello(f"test{i}.youtube.com")
        frame = _build_eth_ip_tcp("10.1.0.2", dst_ip, 30000 + i, 443, payload)
        tls_frames.append(_pad_frame(frame))

    # Ports that ndpi_detection_giveup knows about
    known_ports = [443, 443, 443, 443, 80, 80, 53, 53, 8080, 8443,
                   5060, 5061, 22, 25, 110, 143, 993, 995, 3306, 5432,
                   6379, 27017, 9200, 5672, 1883, 6881, 554, 1935, 123, 161,
                   443, 443, 443, 443, 80, 80, 443, 443, 443, 443]
    port_frames = []
    for i in range(N_PORT_FLOWS):
        dport = known_ports[i % len(known_ports)]
        # Random-looking payload: no recognizable protocol signature
        payload = bytes([(i * 37 + j * 13) & 0xFF for j in range(32)])
        if dport in (53, 161, 123):  # UDP ports
            frame = _build_udp_frame("10.1.0.2", dst_ip,
                                     31000 + i, dport, payload)
        else:
            frame = _build_eth_ip_tcp("10.1.0.2", dst_ip,
                                      31000 + i, dport, payload)
        port_frames.append(_pad_frame(frame))

    random_frames = []
    for i in range(N_RANDOM_FLOWS):
        dport = 40000 + i   # high unpredictable port
        sport = 50000 + i
        payload = bytes([(i * 97 + j * 71) & 0xFF for j in range(40)])
        frame = _build_eth_ip_tcp("10.1.0.2", dst_ip, sport, dport, payload)
        random_frames.append(_pad_frame(frame))

    return tls_frames, port_frames, random_frames


@pytest.fixture(scope="module")
def ml_pair():
    """Start ndpid --no-ml and ndpid (ML) on separate veth pairs."""
    for iface in (NOML_IFACE, ML_IFACE):
        _run(f"ip link del {iface} 2>/dev/null", check=False)
    _run(f"rm -f {NOML_SOCK} {ML_SOCK}", check=False)

    # No-ML daemon
    _run(f"ip link add {NOML_IFACE} type veth peer name {NOML_PEER}")
    _run(f"ip link set {NOML_IFACE} up")
    _run(f"ip link set {NOML_PEER}  up")
    _run(f"ip addr add {NOML_IP}/24  dev {NOML_IFACE}")
    _run(f"ip addr add 10.99.4.2/24  dev {NOML_PEER}")
    # Use ndpid-simple (AF_PACKET) — synchronous recv(), no ring-buffer drops.
    # Every packet reaches ndpi_engine_process() so flows reliably hit the
    # 8-packet give-up threshold and exercise the giveup/ML path.
    noml_proc = _start_daemon(NDPID_SIMPLE, NOML_IFACE, NOML_PORT, NOML_SOCK,
                               extra_args=("--no-ml",))

    # ML-enabled daemon
    _run(f"ip link add {ML_IFACE} type veth peer name {ML_PEER}")
    _run(f"ip link set {ML_IFACE} up")
    _run(f"ip link set {ML_PEER}  up")
    _run(f"ip addr add {ML_IP}/24  dev {ML_IFACE}")
    _run(f"ip addr add 10.99.5.2/24  dev {ML_PEER}")
    ml_proc = _start_daemon(NDPID_SIMPLE, ML_IFACE, ML_PORT, ML_SOCK)

    yield noml_proc, ml_proc

    _stop_daemon(noml_proc, NOML_IFACE, NOML_SOCK)
    _stop_daemon(ml_proc,   ML_IFACE,   ML_SOCK)


def test_ml_reduces_unknown(ml_pair):
    """
    Send identical traffic to both daemons; assert ML+giveup reduces unknown%.
    """
    noml_proc, ml_proc = ml_pair

    noml_tls, noml_port, noml_rand = _build_traffic(NOML_IP)
    ml_tls,   ml_port,  ml_rand   = _build_traffic(ML_IP)

    total_flows = N_TLS_FLOWS + N_PORT_FLOWS + N_RANDOM_FLOWS
    print(f"\n[ml-test] sending {total_flows} flows to each daemon "
          f"({PKTS_PER_FLOW} pkts/flow)…")
    print(f"  {N_TLS_FLOWS} proper TLS  "
          f"+ {N_PORT_FLOWS} known-port random  "
          f"+ {N_RANDOM_FLOWS} truly random")

    _send_frames(NOML_PEER, noml_tls  + noml_port + noml_rand)
    _send_frames(ML_PEER,   ml_tls   + ml_port   + ml_rand)

    # Let the daemons finish processing
    time.sleep(2)

    noml_stats = _parse_stats(_ctl(NOML_SOCK, "show stats"))
    ml_stats   = _parse_stats(_ctl(ML_SOCK,   "show stats"))

    noml_created    = noml_stats.get("flows created",    0)
    noml_classified = noml_stats.get("flows classified", 0)
    noml_guessed    = noml_stats.get("flows guessed",    0)
    noml_ml         = noml_stats.get("flows ml",         0)
    noml_gaveup     = noml_stats.get("flows gave up",    0)

    ml_created      = ml_stats.get("flows created",      0)
    ml_classified   = ml_stats.get("flows classified",   0)
    ml_guessed      = ml_stats.get("flows guessed",      0)
    ml_ml           = ml_stats.get("flows ml",           0)
    ml_gaveup       = ml_stats.get("flows gave up",      0)

    def pct(n, total):
        return 100.0 * n / total if total > 0 else 0.0

    print(f"\n{'='*64}")
    print(f"  {'Metric':35}  {'--no-ml':>8}  {'with ML':>8}")
    print(f"  {'-'*35}  {'-'*8}  {'-'*8}")
    print(f"  {'Flows created':35}  {noml_created:>8}  {ml_created:>8}")
    print(f"  {'Flows classified (nDPI)':35}  "
          f"{noml_classified - noml_guessed - noml_ml:>8}  "
          f"{ml_classified - ml_guessed - ml_ml:>8}")
    print(f"  {'Flows rescued by giveup':35}  "
          f"{noml_guessed:>8}  {ml_guessed:>8}")
    print(f"  {'Flows rescued by ML':35}  "
          f"{noml_ml:>8}  {ml_ml:>8}")
    print(f"  {'Flows gave up (UNKNOWN)':35}  "
          f"{noml_gaveup:>8}  {ml_gaveup:>8}")
    print(f"  {'':35}  {'--------':>8}  {'--------':>8}")
    noml_unk_pct = pct(noml_gaveup, noml_created)
    ml_unk_pct   = pct(ml_gaveup,   ml_created)
    print(f"  {'% unknown':35}  {noml_unk_pct:>7.1f}%  {ml_unk_pct:>7.1f}%")
    reduction = noml_unk_pct - ml_unk_pct
    print(f"  {'Reduction in unknown':35}  {reduction:>7.1f}pp")
    print(f"{'='*64}")

    # Basic sanity
    assert noml_created > 0, "no-ML daemon received no flows"
    assert ml_created   > 0, "ML daemon received no flows"

    # ML+giveup must reduce unknown percentage
    assert ml_unk_pct < noml_unk_pct, (
        f"ML did not reduce unknown: --no-ml={noml_unk_pct:.1f}% vs ML={ml_unk_pct:.1f}%"
    )

    # Port-based giveup should rescue the 'known-port random' flows
    assert ml_guessed > 0 or ml_ml > 0, \
        "ML+giveup rescued zero flows — something is wrong"

    print(f"\n  ML+giveup reduced unknown traffic from "
          f"{noml_unk_pct:.1f}% → {ml_unk_pct:.1f}% "
          f"(-{reduction:.1f} percentage points)")


def test_show_stats_has_ml_fields(ml_pair):
    """show stats must expose the new counters."""
    _, ml_proc = ml_pair
    txt = _ctl(ML_SOCK, "show stats")
    assert "flows guessed:" in txt, f"'flows guessed' missing from show stats:\n{txt}"
    assert "flows ml:"      in txt, f"'flows ml' missing from show stats:\n{txt}"
    assert "flows gave up:" in txt, f"'flows gave up' missing from show stats:\n{txt}"
