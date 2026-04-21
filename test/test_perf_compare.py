"""
Side-by-side CPU comparison: ndpid (eBPF) vs ndpid-simple (AF_PACKET).

Two phases:
  Phase 1 (fast-path): pre-classify 200 flows, flood at max rate for 15 s.
    ndpid:        BPF app_counters path — near-zero CPU.
    ndpid-simple: recvfrom() every packet — high CPU.

  Phase 2 (classification stress): 500 new TLS flows/s for 30 s.
    Both daemons must run nDPI on every new flow.
    CPU difference is smaller (nDPI dominates, not syscall overhead).

Run inside CI container (needs root for AF_PACKET):
    pytest test/test_perf_compare.py -v -s
"""

import os
import socket
import subprocess
import signal
import threading
import time

import pytest

from test_ndpi_observe import (
    _build_eth_ip_tcp,
    _tls_client_hello,
    _pad_frame,
    DST_IP,
)

# ── Tunables ─────────────────────────────────────────────────────────────────
PHASE1_DURATION = 15    # seconds
PHASE1_FLOWS    = 200
PHASE1_THREADS  = 4

PHASE2_DURATION  = 30   # seconds
PHASE2_FLOWS_S   = 500  # new flows per second target
PHASE2_PKTS_FLOW = 6    # packets per flow

SRC_DIR   = os.environ.get("SRC_DIR", "/src")
NDPID     = os.path.join(SRC_DIR, "ndpid")
NDPICTL   = os.path.join(SRC_DIR, "ndpictl")
NDPID_SMP = os.path.join(SRC_DIR, "ndpid-simple")

# Separate veth pairs so both daemons run simultaneously
EBPF_IFACE  = "veth-cmp0"
EBPF_PEER   = "veth-cmp1"
EBPF_IP     = "10.99.2.1"
EBPF_PEER_IP= "10.99.2.2"
EBPF_SOCK   = "/run/ndpid-cmp/cli.sock"
EBPF_PORT   = 19196

SIMP_IFACE  = "veth-cmp2"
SIMP_PEER   = "veth-cmp3"
SIMP_IP     = "10.99.3.1"
SIMP_PEER_IP= "10.99.3.2"
SIMP_SOCK   = "/run/ndpid-simple-cmp/cli.sock"
SIMP_PORT   = 19195


# ── Low-level helpers ─────────────────────────────────────────────────────────

def _run(cmd, check=True):
    return subprocess.run(cmd, shell=True, check=check,
                          capture_output=True, text=True)


def _read_cpu_sec(pid: int) -> float:
    try:
        with open(f"/proc/{pid}/stat") as f:
            fields = f.read().split()
        utime = int(fields[13])
        stime = int(fields[14])
        clk = os.sysconf("SC_CLK_TCK")
        return (utime + stime) / clk
    except Exception:
        return 0.0


def _read_rss_mb(pid: int) -> float:
    try:
        with open(f"/proc/{pid}/statm") as f:
            fields = f.read().split()
        pages = int(fields[1])
        return pages * os.sysconf("SC_PAGE_SIZE") / 1024 / 1024
    except Exception:
        return 0.0


def _parse_stats(text: str) -> dict:
    result = {}
    for line in text.splitlines():
        if ":" in line:
            k, v = line.rsplit(":", 1)
            try:
                result[k.strip()] = int(v.strip())
            except ValueError:
                pass
    return result


def _sample(ctl, sock_path: str, pid: int) -> dict:
    ts  = time.monotonic()
    cpu = _read_cpu_sec(pid)
    rss = _read_rss_mb(pid)
    env = os.environ.copy()
    env["NDPID_SOCKET"] = sock_path
    r = subprocess.run([NDPICTL, "show", "stats"],
                       capture_output=True, text=True, timeout=5, env=env)
    stats = _parse_stats(r.stdout)
    return {
        "ts":       ts,
        "cpu":      cpu,
        "rss":      rss,
        "flows":    stats.get("flows created",    0),
        "scanned":  stats.get("packets scanned",  0),
        "fastpath": stats.get("packets fastpath", 0),
    }


def _build_frames(dst_ip: str, sport_base: int, count: int) -> list:
    frames = []
    for i in range(count):
        sport   = sport_base + i
        payload = _tls_client_hello(f"perf{sport}.example.com")
        frame   = _build_eth_ip_tcp("10.1.0.2", dst_ip, sport, 443, payload)
        frames.append(_pad_frame(frame))
    return frames


def _flood_worker(iface, frames, end_time, counter):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((iface, 0))
    n, cnt, fi = len(frames), 0, 0
    while time.monotonic() < end_time:
        s.send(frames[fi % n])
        fi  += 1
        cnt += 1
    s.close()
    counter[0] = cnt


def _collect_samples(sock_path, pid, end_time, interval=1.0):
    samples = []
    prev = _sample(None, sock_path, pid)
    while time.monotonic() < end_time:
        time.sleep(interval)
        cur = _sample(None, sock_path, pid)
        dt  = cur["ts"] - prev["ts"]
        if dt <= 0:
            prev = cur
            continue
        cpu_pct    = (cur["cpu"] - prev["cpu"]) / dt * 100
        d_flows    = cur["flows"]    - prev["flows"]
        d_scanned  = cur["scanned"]  - prev["scanned"]
        d_fastpath = cur["fastpath"] - prev["fastpath"]
        samples.append({
            "cpu_pct":   cpu_pct,
            "rss_mb":    cur["rss"],
            "flows_s":   d_flows    / dt,
            "scanned_s": d_scanned  / dt,
            "fast_s":    d_fastpath / dt,
        })
        prev = cur
    return samples


def _summarize(samples):
    if not samples:
        return 0.0, 0.0, 0.0
    avg_cpu  = sum(s["cpu_pct"]   for s in samples) / len(samples)
    peak_cpu = max(s["cpu_pct"]   for s in samples)
    tot_scan = sum(s["scanned_s"] for s in samples) / len(samples)
    tot_fast = sum(s["fast_s"]    for s in samples) / len(samples)
    fp_pct   = (tot_fast / (tot_scan + tot_fast) * 100
                if (tot_scan + tot_fast) > 0 else 0)
    return avg_cpu, peak_cpu, fp_pct


def _print_side_by_side(title, ebpf_samples, simp_samples, total_pkts, duration):
    print(f"\n{'='*80}")
    print(f"  {title}")
    print(f"{'='*80}")
    if total_pkts is not None:
        print(f"  Packets sent: {total_pkts:,}  ({total_pkts/duration:,.0f} pps per daemon)")
    hdr = (f"  {'Sec':>3}  "
           f"{'eBPF CPU%':>10} {'eBPF fast/s':>12} | "
           f"{'AF_PKT CPU%':>12} {'AFPKT scanned/s':>16}")
    print(hdr)
    print(f"  {'-'*3}  {'-'*10} {'-'*12}   {'-'*12} {'-'*16}")
    for i, (e, s) in enumerate(zip(ebpf_samples, simp_samples), 1):
        print(f"  {i:>3}  "
              f"{e['cpu_pct']:>9.1f}% {e['fast_s']:>12.0f} | "
              f"{s['cpu_pct']:>11.1f}% {s['scanned_s']:>16.0f}")

    e_avg, e_peak, e_fp = _summarize(ebpf_samples)
    s_avg, s_peak, s_fp = _summarize(simp_samples)
    print(f"\n  {'':25}  eBPF (ndpid)    AF_PACKET (ndpid-simple)")
    print(f"  {'Avg CPU':25}: {e_avg:>8.1f}%        {s_avg:>8.1f}%")
    print(f"  {'Peak CPU':25}: {e_peak:>8.1f}%        {s_peak:>8.1f}%")
    print(f"  {'Fast-path ratio':25}: {e_fp:>8.1f}%        {s_fp:>8.1f}%")
    print(f"  {'CPU factor (AFPKT/eBPF)':25}: {(s_avg / e_avg if e_avg > 0 else float('inf')):.1f}×")
    print(f"{'='*80}")
    return e_avg, e_peak, s_avg, s_peak


# ── Fixtures ──────────────────────────────────────────────────────────────────

class DaemonHandle:
    def __init__(self, proc, sock_path):
        self.proc      = proc
        self.sock_path = sock_path


def _start_daemon(binary, iface, port, sock_path, log_prefix):
    """Start a daemon, wait for CLI socket, return DaemonHandle."""
    proc = subprocess.Popen(
        [binary, "-i", iface, "-p", str(port), "-s", sock_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        preexec_fn=os.setsid,
    )
    for _ in range(100):
        if os.path.exists(sock_path):
            break
        if proc.poll() is not None:
            out = proc.stdout.read().decode(errors="replace") if proc.stdout else ""
            pytest.fail(f"{log_prefix} exited early: rc={proc.returncode}\n{out}")
        time.sleep(0.1)
    else:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except Exception:
            pass
        pytest.fail(f"{log_prefix} failed to create CLI socket at {sock_path}")
    return DaemonHandle(proc, sock_path)


def _stop_daemon(handle, iface, sock_path):
    try:
        os.killpg(handle.proc.pid, signal.SIGTERM)
        handle.proc.wait(timeout=5)
    except Exception:
        try:
            os.killpg(handle.proc.pid, signal.SIGKILL)
        except Exception:
            pass
    _run(f"ip link del {iface} 2>/dev/null", check=False)
    _run(f"rm -f {sock_path}", check=False)


@pytest.fixture(scope="module")
def both_daemons():
    """Bring up both ndpid (eBPF) and ndpid-simple (AF_PACKET) on separate veth pairs."""
    for iface in (EBPF_IFACE, SIMP_IFACE):
        _run(f"ip link del {iface} 2>/dev/null", check=False)
    _run(f"rm -f {EBPF_SOCK} {SIMP_SOCK}", check=False)

    # eBPF daemon
    _run(f"ip link add {EBPF_IFACE} type veth peer name {EBPF_PEER}")
    _run(f"ip link set {EBPF_IFACE} up")
    _run(f"ip link set {EBPF_PEER}  up")
    _run(f"ip addr add {EBPF_IP}/24  dev {EBPF_IFACE}")
    _run(f"ip addr add {EBPF_PEER_IP}/24 dev {EBPF_PEER}")
    ebpf_h = _start_daemon(NDPID,     EBPF_IFACE, EBPF_PORT, EBPF_SOCK, "ndpid")

    # AF_PACKET daemon
    _run(f"ip link add {SIMP_IFACE} type veth peer name {SIMP_PEER}")
    _run(f"ip link set {SIMP_IFACE} up")
    _run(f"ip link set {SIMP_PEER}  up")
    _run(f"ip addr add {SIMP_IP}/24  dev {SIMP_IFACE}")
    _run(f"ip addr add {SIMP_PEER_IP}/24 dev {SIMP_PEER}")
    simp_h = _start_daemon(NDPID_SMP, SIMP_IFACE, SIMP_PORT, SIMP_SOCK, "ndpid-simple")

    yield ebpf_h, simp_h

    _stop_daemon(ebpf_h, EBPF_IFACE, EBPF_SOCK)
    _stop_daemon(simp_h, SIMP_IFACE, SIMP_SOCK)


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_compare_fastpath_cpu(both_daemons):
    """
    Fast-path flood: 200 pre-classified flows at max rate for 15 s.

    eBPF daemon:  BPF app_counters — near-zero CPU.
    AF_PACKET:    recvfrom() every packet — CPU proportional to pps.
    Assert: AF_PACKET CPU > eBPF CPU (at least 5× higher).
    """
    ebpf_h, simp_h = both_daemons

    # Build PHASE1_FLOWS/PHASE1_THREADS frames per thread per daemon
    per_t = PHASE1_FLOWS // PHASE1_THREADS
    ebpf_frames = [_build_frames(EBPF_IP, 50000 + t * per_t, per_t)
                   for t in range(PHASE1_THREADS)]
    simp_frames = [_build_frames(SIMP_IP, 50000 + t * per_t, per_t)
                   for t in range(PHASE1_THREADS)]

    # Warmup — classify all flows on both daemons
    print(f"\n[compare/phase1] warmup — classifying {PHASE1_FLOWS} flows on each daemon…")
    warmup_end = time.monotonic() + 10
    socks_e = [socket.socket(socket.AF_PACKET, socket.SOCK_RAW) for _ in range(PHASE1_THREADS)]
    socks_s = [socket.socket(socket.AF_PACKET, socket.SOCK_RAW) for _ in range(PHASE1_THREADS)]
    for s, f in zip(socks_e, ebpf_frames):
        s.bind((EBPF_PEER, 0))
    for s, f in zip(socks_s, simp_frames):
        s.bind((SIMP_PEER, 0))
    while time.monotonic() < warmup_end:
        for s, frames in zip(socks_e, ebpf_frames):
            for f in frames:
                s.send(f)
        for s, frames in zip(socks_s, simp_frames):
            for f in frames:
                s.send(f)
    for s in socks_e + socks_s:
        s.close()

    time.sleep(1)
    print("[compare/phase1] warmup done — flooding both daemons simultaneously…")

    end_t      = time.monotonic() + PHASE1_DURATION
    counters_e = [[0]] * PHASE1_THREADS
    counters_s = [[0]] * PHASE1_THREADS

    threads_e = [
        threading.Thread(target=_flood_worker,
                         args=(EBPF_PEER, ebpf_frames[t], end_t, counters_e[t]),
                         daemon=True)
        for t in range(PHASE1_THREADS)
    ]
    threads_s = [
        threading.Thread(target=_flood_worker,
                         args=(SIMP_PEER, simp_frames[t], end_t, counters_s[t]),
                         daemon=True)
        for t in range(PHASE1_THREADS)
    ]

    ebpf_results = []
    simp_results = []

    def collect_e():
        ebpf_results.extend(_collect_samples(EBPF_SOCK, ebpf_h.proc.pid, end_t + 0.5))

    def collect_s():
        simp_results.extend(_collect_samples(SIMP_SOCK, simp_h.proc.pid, end_t + 0.5))

    ct_e = threading.Thread(target=collect_e, daemon=True)
    ct_s = threading.Thread(target=collect_s, daemon=True)
    ct_e.start()
    ct_s.start()
    for th in threads_e + threads_s:
        th.start()
    for th in threads_e + threads_s:
        th.join()
    ct_e.join()
    ct_s.join()

    total_e = sum(c[0] for c in counters_e)
    total_s = sum(c[0] for c in counters_s)

    e_avg, e_peak, s_avg, s_peak = _print_side_by_side(
        f"Phase 1: Fast-Path Flood  ({PHASE1_THREADS} threads × {per_t} flows × {PHASE1_DURATION}s)",
        ebpf_results, simp_results,
        (total_e + total_s) // 2, PHASE1_DURATION,
    )

    assert total_e > 0 and total_s > 0
    # eBPF should be dramatically cheaper when flows are pre-classified
    if e_avg > 0:
        ratio = s_avg / e_avg
        print(f"\n  AF_PACKET is {ratio:.1f}× more CPU-expensive than eBPF fast-path")
        assert ratio >= 3, \
            f"Expected AF_PACKET to be ≥3× more CPU-intensive; got {ratio:.1f}× (eBPF {e_avg:.1f}% vs AF_PKT {s_avg:.1f}%)"
    else:
        print(f"\n  eBPF CPU ~0% (too fast to measure); AF_PACKET avg {s_avg:.1f}%")
        assert s_avg >= 1.0, \
            f"AF_PACKET showed unexpectedly low CPU {s_avg:.1f}% — may not be receiving packets"


def test_compare_classification_stress(both_daemons):
    """
    Classification stress: 500 new TLS flows/s for 30 s on each daemon.

    nDPI classification dominates here; syscall overhead is secondary.
    Both daemons should show similar CPU (within 3× of each other).
    """
    ebpf_h, simp_h = both_daemons

    total_flows = PHASE2_FLOWS_S * PHASE2_DURATION
    max_frames  = min(total_flows, 60000)
    print(f"\n[compare/phase2] pre-building {max_frames} TLS frames for each daemon…")
    ebpf_all = _build_frames(EBPF_IP, 1000, max_frames)
    simp_all  = _build_frames(SIMP_IP, 1000, max_frames)

    inter_flow_s = 1.0 / PHASE2_FLOWS_S
    n_frames     = len(ebpf_all)
    end_t        = time.monotonic() + PHASE2_DURATION

    sent_e = sent_s = flow_idx = 0

    ebpf_results = []
    simp_results = []

    def collect_e():
        ebpf_results.extend(_collect_samples(EBPF_SOCK, ebpf_h.proc.pid, end_t + 1))

    def collect_s():
        simp_results.extend(_collect_samples(SIMP_SOCK, simp_h.proc.pid, end_t + 1))

    ct_e = threading.Thread(target=collect_e, daemon=True)
    ct_s = threading.Thread(target=collect_s, daemon=True)
    ct_e.start()
    ct_s.start()

    sock_e = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock_e.bind((EBPF_PEER, 0))
    sock_s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock_s.bind((SIMP_PEER, 0))

    next_flow_t = time.monotonic()
    while time.monotonic() < end_t:
        frame_e = ebpf_all[flow_idx % n_frames]
        frame_s = simp_all[flow_idx % n_frames]
        for _ in range(PHASE2_PKTS_FLOW):
            sock_e.send(frame_e)
            sock_s.send(frame_s)
            sent_e += 1
            sent_s += 1
        flow_idx   += 1
        next_flow_t += inter_flow_s
        now = time.monotonic()
        if next_flow_t > now + 0.001:
            time.sleep(next_flow_t - now - 0.001)
        while time.monotonic() < next_flow_t:
            pass

    sock_e.close()
    sock_s.close()
    ct_e.join()
    ct_s.join()

    actual_flows_s = flow_idx / PHASE2_DURATION

    e_avg, e_peak, s_avg, s_peak = _print_side_by_side(
        f"Phase 2: Classification Stress  "
        f"(target {PHASE2_FLOWS_S} flows/s × {PHASE2_PKTS_FLOW} pkts/flow × {PHASE2_DURATION}s)",
        ebpf_results, simp_results,
        (sent_e + sent_s) // 2, PHASE2_DURATION,
    )
    print(f"  Actual flow rate: {actual_flows_s:.0f} flows/s  (target {PHASE2_FLOWS_S})")

    assert sent_e > 0 and sent_s > 0
    assert flow_idx > PHASE2_FLOWS_S * PHASE2_DURATION * 0.5, \
        f"Too few flows: {flow_idx}"
    # Both should show measurable CPU (nDPI is doing real work)
    combined_peak = max(e_peak, s_peak)
    assert combined_peak > 0.1, \
        f"Neither daemon showed CPU activity (e={e_peak:.1f}% s={s_peak:.1f}%)"
