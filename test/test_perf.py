"""
Performance / load test — high-rate traffic flood.

Two phases:
  Phase 1 (fast-path efficiency): pre-classify flows, then flood at max rate.
    All packets hit the BPF app_counters path with zero ring-buffer copy.
    Shows: ~400 Kpps at < 1% CPU.

  Phase 2 (classification stress): send NEW flows at a sustained rate.
    Each unique source port is a new 5-tuple; nDPI must classify every flow.
    Shows: CPU proportional to classification rate.

Stats are read from the test ndpid via Unix socket + /proc/<pid>/stat so
there is no dependency on the Prometheus port (which may be bound by another
ndpid instance running in the host network namespace).

Run inside the CI container (needs root for AF_PACKET):
    pytest test/test_perf.py -v -s
"""

import os
import socket
import struct
import threading
import time

import pytest

from test_ndpi_observe import (
    _build_eth_ip_tcp,
    _tls_client_hello,
    _pad_frame,
    PEER_IFACE,
    DST_IP,
)

# ── Tuning ──────────────────────────────────────────────────────────────────
PHASE1_DURATION   = 15    # seconds — fast-path flood
PHASE1_FLOWS      = 200   # unique flows for the fast-path phase
PHASE1_THREADS    = 4

PHASE2_DURATION   = 30    # seconds — classification stress
PHASE2_FLOWS_S    = 500   # new flows per second target
PHASE2_PKTS_FLOW  = 6     # packets per flow (enough for TLS SNI classification)

# ── Helpers ──────────────────────────────────────────────────────────────────

def _read_cpu_sec(pid: int) -> float:
    """Total CPU time (user+system) in seconds for pid, via /proc/<pid>/stat."""
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
    """RSS in MB for pid."""
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


def _sample(ndpid_handle, pid: int) -> dict:
    ts = time.monotonic()
    cpu = _read_cpu_sec(pid)
    rss = _read_rss_mb(pid)
    _, txt, _ = ndpid_handle.ctl("show stats")
    stats = _parse_stats(txt)
    return {
        "ts":       ts,
        "cpu":      cpu,
        "rss":      rss,
        "flows":    stats.get("flows created",    0),
        "scanned":  stats.get("packets scanned",  0),
        "fastpath": stats.get("packets fastpath", 0),
    }


def _build_frames(sport_base: int, count: int) -> list:
    """Build count padded TLS frames with sequential source ports."""
    frames = []
    for i in range(count):
        sport   = sport_base + i
        payload = _tls_client_hello(f"perf{sport}.example.com")
        frame   = _build_eth_ip_tcp("10.99.0.2", DST_IP, sport, 443, payload)
        frames.append(_pad_frame(frame))
    return frames


# ── Flood worker ─────────────────────────────────────────────────────────────

def _flood_worker(iface, frames, end_time, counter):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((iface, 0))
    n, cnt, fi = len(frames), 0, 0
    while time.monotonic() < end_time:
        s.send(frames[fi % n])
        fi += 1
        cnt += 1
    s.close()
    counter[0] = cnt


def _collect_samples(ndpid_handle, pid, end_time, interval=1.0):
    """Poll stats every `interval` seconds until end_time; return list of dicts."""
    samples = []
    prev = _sample(ndpid_handle, pid)
    while time.monotonic() < end_time:
        time.sleep(interval)
        cur = _sample(ndpid_handle, pid)
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


def _print_report(title, total_pkts, duration, samples):
    print(f"\n{'='*68}")
    print(f"  {title}")
    print(f"{'='*68}")
    if total_pkts is not None:
        print(f"  Packets attempted: {total_pkts:>12,}  ({total_pkts/duration:>10,.0f} pps)")
    print()
    print(f"  {'Sec':>3}  {'CPU%':>6}  {'RSS MB':>7}  {'Flows/s':>8}  "
          f"{'Scanned/s':>10}  {'Fastpath/s':>11}")
    print(f"  {'-'*3}  {'-'*6}  {'-'*7}  {'-'*8}  {'-'*10}  {'-'*11}")
    for i, s in enumerate(samples, 1):
        print(f"  {i:>3}  {s['cpu_pct']:>5.1f}%  {s['rss_mb']:>6.1f}  "
              f"{s['flows_s']:>8.0f}  {s['scanned_s']:>10.0f}  {s['fast_s']:>11.0f}")

    if not samples:
        return 0, 0, 0
    avg_cpu  = sum(s["cpu_pct"]  for s in samples) / len(samples)
    peak_cpu = max(s["cpu_pct"]  for s in samples)
    avg_rss  = sum(s["rss_mb"]   for s in samples) / len(samples)
    tot_flow = sum(s["flows_s"]  for s in samples) / len(samples)
    tot_scan = sum(s["scanned_s"] for s in samples) / len(samples)
    tot_fast = sum(s["fast_s"]   for s in samples) / len(samples)
    fp_pct   = (tot_fast / (tot_scan + tot_fast) * 100
                if (tot_scan + tot_fast) > 0 else 0)
    print(f"  {'AVG':>3}  {avg_cpu:>5.1f}%  {avg_rss:>6.1f}  "
          f"{tot_flow:>8.0f}  {tot_scan:>10.0f}  {tot_fast:>11.0f}")
    print()
    print(f"  Peak CPU:        {peak_cpu:.1f}%")
    print(f"  Avg CPU:         {avg_cpu:.1f}%")
    print(f"  Avg RSS:         {avg_rss:.1f} MB")
    print(f"  Fast-path ratio: {fp_pct:.1f}%  (of scanned + fastpath)")
    print(f"{'='*68}")
    return avg_cpu, peak_cpu, fp_pct


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_perf_fast_path(ndpid):
    """
    Phase 1 — fast-path efficiency.

    Pre-classify PHASE1_FLOWS unique flows (warmup), then flood all frames at
    maximum AF_PACKET rate.  After warmup every packet hits the BPF
    app_counters path (no ring-buffer copy, no userspace involvement).
    Expected result: near-zero CPU with very high fastpath/s.
    """
    pid = ndpid.proc.pid

    # Build one frame per flow
    print(f"\n[phase1] building {PHASE1_FLOWS} TLS frames for warmup…")
    frames_list = [
        _build_frames(50000 + t * (PHASE1_FLOWS // PHASE1_THREADS),
                      PHASE1_FLOWS // PHASE1_THREADS)
        for t in range(PHASE1_THREADS)
    ]

    # Warmup: send enough packets per flow to reach classification/give-up
    print("[phase1] warmup — classifying all flows…")
    warmup_end = time.monotonic() + 8
    socks = []
    for frames in frames_list:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        s.bind((PEER_IFACE, 0))
        socks.append(s)
    while time.monotonic() < warmup_end:
        for s, frames in zip(socks, frames_list):
            for f in frames:
                s.send(f)
    for s in socks:
        s.close()

    time.sleep(1)
    _, stats_txt, _ = ndpid.ctl("show stats")
    print(f"[phase1] after warmup:\n{stats_txt.strip()}")

    # Timed flood phase
    print(f"[phase1] flooding {PHASE1_THREADS} threads × "
          f"{PHASE1_FLOWS // PHASE1_THREADS} flows for {PHASE1_DURATION}s…")
    counters = [[0]] * PHASE1_THREADS
    end_t    = time.monotonic() + PHASE1_DURATION
    threads  = [
        threading.Thread(
            target=_flood_worker,
            args=(PEER_IFACE, frames_list[t], end_t, counters[t]),
            daemon=True,
        )
        for t in range(PHASE1_THREADS)
    ]

    sample_thread_results = []
    def collect():
        sample_thread_results.extend(
            _collect_samples(ndpid, pid, end_t + 0.5)
        )

    ct = threading.Thread(target=collect, daemon=True)
    ct.start()
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    ct.join()

    total = sum(c[0] for c in counters)
    avg_cpu, peak_cpu, fp_pct = _print_report(
        f"Phase 1: Fast-Path Flood  ({PHASE1_THREADS} threads × "
        f"{PHASE1_FLOWS // PHASE1_THREADS} flows)",
        total, PHASE1_DURATION, sample_thread_results,
    )

    assert total > 0
    assert peak_cpu < 50, f"CPU too high in fast-path mode: {peak_cpu:.1f}%"
    assert fp_pct > 70, f"Expected >70% fast-path, got {fp_pct:.1f}%"


def test_perf_classification_stress(ndpid):
    """
    Phase 2 — classification throughput stress.

    Creates PHASE2_FLOWS_S new flows per second for PHASE2_DURATION seconds.
    Each new 5-tuple must be classified by nDPI — this is the expensive path.
    Expected result: CPU rises proportionally to classification rate.
    """
    pid = ndpid.proc.pid

    total_flows = PHASE2_FLOWS_S * PHASE2_DURATION
    # Sports 1000–61000 to stay within 0–65535 for up to 60000 unique flows
    max_frames  = min(total_flows, 60000)
    print(f"\n[phase2] pre-building {max_frames} unique TLS frames…")
    all_frames = _build_frames(1000, max_frames)

    inter_flow_s = 1.0 / PHASE2_FLOWS_S   # seconds between new flows
    pkts_per_flow = PHASE2_PKTS_FLOW

    print(f"[phase2] sending ~{PHASE2_FLOWS_S} new flows/s × {pkts_per_flow} "
          f"pkts/flow = ~{PHASE2_FLOWS_S * pkts_per_flow} pps "
          f"for {PHASE2_DURATION}s…")

    sent       = 0
    flow_idx   = 0
    n_frames   = len(all_frames)
    end_t      = time.monotonic() + PHASE2_DURATION

    sample_results = []
    def collect():
        sample_results.extend(
            _collect_samples(ndpid, pid, end_t + 1)
        )

    ct = threading.Thread(target=collect, daemon=True)
    ct.start()

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((PEER_IFACE, 0))

    next_flow_t = time.monotonic()
    while time.monotonic() < end_t:
        # Send pkts_per_flow packets for this flow
        frame = all_frames[flow_idx % n_frames]
        for _ in range(pkts_per_flow):
            s.send(frame)
            sent += 1
        flow_idx  += 1
        next_flow_t += inter_flow_s
        # Busy-wait for the next flow slot (sleep is too coarse)
        now = time.monotonic()
        if next_flow_t > now + 0.001:
            time.sleep(next_flow_t - now - 0.001)
        while time.monotonic() < next_flow_t:
            pass   # spin for sub-ms precision

    s.close()
    ct.join()

    actual_flows_s = flow_idx / PHASE2_DURATION
    avg_cpu, peak_cpu, fp_pct = _print_report(
        f"Phase 2: Classification Stress  "
        f"(target {PHASE2_FLOWS_S} flows/s × {pkts_per_flow} pkts/flow)",
        sent, PHASE2_DURATION, sample_results,
    )
    print(f"  Actual flow rate:  {actual_flows_s:.0f} flows/s  "
          f"(target {PHASE2_FLOWS_S})")

    assert sent > 0
    assert flow_idx > PHASE2_FLOWS_S * PHASE2_DURATION * 0.5, \
        f"Too few flows sent: {flow_idx} (expected >{PHASE2_FLOWS_S * PHASE2_DURATION * 0.5:.0f})"
