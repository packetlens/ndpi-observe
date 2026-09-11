#!/usr/bin/env python3
"""
Real-traffic ML comparison: ndpid-simple --no-ml vs ndpid-simple (ML+giveup).

Usage:
  # Capture 30 s from WiFi, replay to both daemons, compare unknown%:
  sudo python3 scripts/compare_ml.py --iface wlp9s0f0

  # Replay from an existing pcap (DLT_EN10MB):
  sudo python3 scripts/compare_ml.py --pcap /tmp/capture.pcap

The script creates two veth pairs, starts two ndpid-simple instances, replays
every IPv4 frame to both simultaneously, then prints a side-by-side table.
"""

import argparse
import os
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

SRC_DIR      = os.environ.get("SRC_DIR", "/src")
NDPID_SIMPLE = os.path.join(SRC_DIR, "ndpid-simple")
NDPICTL      = os.path.join(SRC_DIR, "ndpictl")

# Fall back to system install
for candidate in [NDPID_SIMPLE, "/usr/local/sbin/ndpid-simple", "/usr/sbin/ndpid-simple"]:
    if os.path.isfile(candidate):
        NDPID_SIMPLE = candidate
        break
for candidate in [NDPICTL, "/usr/local/bin/ndpictl", "/usr/bin/ndpictl"]:
    if os.path.isfile(candidate):
        NDPICTL = candidate
        break

NOML_IFACE = "veth-cmp-noml0"
NOML_PEER  = "veth-cmp-noml1"
NOML_IP    = "10.99.20.1"
NOML_SOCK  = "/run/ndpid-cmp-noml/cli.sock"
NOML_PORT  = 19185

ML_IFACE   = "veth-cmp-ml0"
ML_PEER    = "veth-cmp-ml1"
ML_IP      = "10.99.21.1"
ML_SOCK    = "/run/ndpid-cmp-ml/cli.sock"
ML_PORT    = 19184


def run(cmd, check=True):
    return subprocess.run(cmd, shell=True, check=check,
                          capture_output=True, text=True)


def parse_stats(text):
    result = {}
    for line in text.splitlines():
        if ":" in line:
            k, v = line.rsplit(":", 1)
            try:
                result[k.strip()] = int(v.strip())
            except ValueError:
                pass
    return result


def ctl(sock_path, cmd):
    env = os.environ.copy()
    env["NDPID_SOCKET"] = sock_path
    r = subprocess.run([NDPICTL] + cmd.split(),
                       capture_output=True, text=True, timeout=5, env=env)
    return r.stdout


def start_daemon(iface, port, sock_path, extra_args=()):
    proc = subprocess.Popen(
        [NDPID_SIMPLE, "-i", iface, "-p", str(port), "-s", sock_path]
        + list(extra_args),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        preexec_fn=os.setsid,
    )
    for _ in range(80):
        if os.path.exists(sock_path):
            return proc
        if proc.poll() is not None:
            out = proc.stdout.read().decode(errors="replace") if proc.stdout else ""
            sys.exit(f"daemon exited early: rc={proc.returncode}\n{out}")
        time.sleep(0.1)
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except Exception:
        pass
    sys.exit(f"daemon failed to create socket at {sock_path}")


def stop_daemon(proc, iface, sock_path):
    try:
        os.killpg(proc.pid, signal.SIGTERM)
        proc.wait(timeout=5)
    except Exception:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except Exception:
            pass
    run(f"ip link del {iface} 2>/dev/null", check=False)
    run(f"rm -f {sock_path}", check=False)


def setup_veth(iface, peer, ip, peer_ip):
    run(f"ip link del {iface} 2>/dev/null", check=False)
    run(f"ip link add {iface} type veth peer name {peer}")
    run(f"ip link set {iface} up")
    run(f"ip link set {peer}  up")
    run(f"ip addr add {ip}/24     dev {iface}")
    run(f"ip addr add {peer_ip}/24 dev {peer}")


# ── pcap capture ──────────────────────────────────────────────────────────────

def capture_pcap(iface, duration_s, path):
    """Capture live traffic using tcpdump."""
    print(f"[capture] capturing {duration_s}s from {iface} → {path}")
    print("[capture] generate traffic now (browse the web, stream video, etc.)")
    proc = subprocess.Popen(
        ["tcpdump", "-i", iface, "-w", path, "-q"],
        stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(duration_s)
    finally:
        proc.terminate()
        proc.wait(timeout=5)
    size = os.path.getsize(path)
    print(f"[capture] done — {size:,} bytes captured")
    return path


# ── pcap reader ───────────────────────────────────────────────────────────────

def read_pcap(path):
    """Yield raw Ethernet frames from a pcap file (DLT_EN10MB = 1)."""
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic == b"\xd4\xc3\xb2\xa1":
            endian = "<"
        elif magic == b"\xa1\xb2\xc3\xd4":
            endian = ">"
        else:
            sys.exit(f"not a valid pcap file: {path}")

        # Read global header (skip version, timezone, sig, snaplen)
        ver_maj, ver_min, tz, sig, snap, dlt = struct.unpack(
            endian + "HHIIII", f.read(20))
        if dlt not in (1,):   # 1 = LINKTYPE_ETHERNET
            sys.exit(f"unsupported DLT {dlt} — only Ethernet (1) is supported")

        frames = []
        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                endian + "IIII", hdr)
            data = f.read(incl_len)
            if len(data) < incl_len:
                break
            # Keep only IPv4 Ethernet frames (ethertype 0x0800)
            if len(data) >= 14 and data[12:14] == b"\x08\x00":
                frames.append(data)

    print(f"[pcap] read {len(frames)} IPv4 Ethernet frames")
    return frames


# ── replay ────────────────────────────────────────────────────────────────────

def replay_frames(iface, frames, done_event, counter):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((iface, 0))
    cnt = 0
    for frame in frames:
        s.send(frame)
        cnt += 1
    s.close()
    counter[0] = cnt
    done_event.set()


# ── comparison ────────────────────────────────────────────────────────────────

def print_comparison(noml_stats, ml_stats):
    def pct(n, total):
        return 100.0 * n / total if total > 0 else 0.0

    nc = noml_stats.get("flows created",    0)
    mc = ml_stats.get("flows created",      0)

    ncl = noml_stats.get("flows classified", 0)
    mcl = ml_stats.get("flows classified",   0)

    ng  = noml_stats.get("flows guessed",    0)
    mg  = ml_stats.get("flows guessed",      0)

    nm  = noml_stats.get("flows ml",         0)
    mm  = ml_stats.get("flows ml",           0)

    ngv = noml_stats.get("flows gave up",    0)
    mgv = ml_stats.get("flows gave up",      0)

    # nDPI-only classified = total classified minus giveup and ML
    ndpi_noml = ncl - ng - nm
    ndpi_ml   = mcl - mg - mm

    print(f"\n{'='*68}")
    print(f"  ML / giveup comparison on real traffic")
    print(f"{'='*68}")
    print(f"  {'Metric':36}  {'--no-ml':>9}  {'with ML':>9}")
    print(f"  {'-'*36}  {'-'*9}  {'-'*9}")
    print(f"  {'Flows created':36}  {nc:>9}  {mc:>9}")
    print(f"  {'Classified by nDPI (DPI signatures)':36}  "
          f"{ndpi_noml:>8}  {ndpi_ml:>8}  "
          f"   ({pct(ndpi_ml, mc):.1f}%)")
    print(f"  {'Rescued by ndpi_detection_giveup()':36}  "
          f"{ng:>8}  {mg:>8}  "
          f"   ({pct(mg, mc):.1f}%)")
    print(f"  {'Rescued by ML model (RF)':36}  "
          f"{nm:>8}  {mm:>8}  "
          f"   ({pct(mm, mc):.1f}%)")
    print(f"  {'Still unknown (gave up)':36}  "
          f"{ngv:>8}  {mgv:>8}")
    print(f"  {'-'*36}  {'-'*9}  {'-'*9}")
    noml_unk = pct(ngv, nc)
    ml_unk   = pct(mgv, mc)
    print(f"  {'% unknown':36}  {noml_unk:>8.1f}%  {ml_unk:>8.1f}%")
    reduction = noml_unk - ml_unk
    if noml_unk > 0:
        rel = reduction / noml_unk * 100
        print(f"  {'Reduction in unknown traffic':36}  "
              f"{'':>9}  -{reduction:.1f} pp  ({rel:.0f}% relative)")
    print(f"{'='*68}")

    if noml_unk > 0 and ml_unk < noml_unk:
        print(f"\n  ML + giveup reduced unknown from {noml_unk:.1f}% → {ml_unk:.1f}%")
    elif noml_unk == 0 and ml_unk == 0:
        print(f"\n  nDPI classified all flows directly — no giveup/ML needed for this traffic.")
    else:
        print(f"\n  No improvement detected (unexpected).")


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--iface", metavar="IFACE",
                    help="Live interface to capture from (e.g. wlp9s0f0)")
    ap.add_argument("--pcap",  metavar="FILE",
                    help="Existing pcap file to replay (DLT_EN10MB)")
    ap.add_argument("--duration", type=int, default=30,
                    help="Capture duration in seconds (default: 30)")
    args = ap.parse_args()

    if not args.iface and not args.pcap:
        ap.print_help()
        sys.exit(1)

    if os.geteuid() != 0:
        sys.exit("error: must be run as root (needs AF_PACKET + veth creation)")

    if not os.path.isfile(NDPID_SIMPLE):
        sys.exit(f"error: ndpid-simple not found at {NDPID_SIMPLE}\n"
                 f"  Build with: cd ndpi-observe && make ndpid-simple")

    # ── Capture or load pcap ──────────────────────────────────────────────────
    if args.pcap:
        pcap_path = args.pcap
    else:
        pcap_path = tempfile.mktemp(suffix=".pcap", prefix="ndpi_compare_")
        capture_pcap(args.iface, args.duration, pcap_path)

    frames = read_pcap(pcap_path)
    if not frames:
        sys.exit("error: no IPv4 Ethernet frames in pcap")

    # ── Setup veth pairs ──────────────────────────────────────────────────────
    print("[setup] creating veth pairs…")
    setup_veth(NOML_IFACE, NOML_PEER, NOML_IP, "10.99.20.2")
    setup_veth(ML_IFACE,   ML_PEER,   ML_IP,   "10.99.21.2")
    run(f"rm -f {NOML_SOCK} {ML_SOCK}", check=False)

    # ── Start daemons ─────────────────────────────────────────────────────────
    print(f"[daemon] starting ndpid-simple --no-ml on {NOML_IFACE}…")
    noml_proc = start_daemon(NOML_IFACE, NOML_PORT, NOML_SOCK, ("--no-ml",))

    print(f"[daemon] starting ndpid-simple (ML+giveup) on {ML_IFACE}…")
    ml_proc   = start_daemon(ML_IFACE,   ML_PORT,   ML_SOCK)

    # ── Replay frames to both daemons simultaneously ──────────────────────────
    print(f"[replay] sending {len(frames):,} frames to both daemons simultaneously…")
    done_noml = threading.Event()
    done_ml   = threading.Event()
    cnt_noml  = [0]
    cnt_ml    = [0]

    t_noml = threading.Thread(
        target=replay_frames,
        args=(NOML_PEER, frames, done_noml, cnt_noml), daemon=True)
    t_ml = threading.Thread(
        target=replay_frames,
        args=(ML_PEER,   frames, done_ml,   cnt_ml),   daemon=True)

    t_noml.start()
    t_ml.start()
    done_noml.wait(timeout=120)
    done_ml.wait(timeout=120)
    t_noml.join()
    t_ml.join()

    print(f"[replay] --no-ml: {cnt_noml[0]:,} frames,  ML: {cnt_ml[0]:,} frames")
    print("[replay] waiting 3s for daemons to finish processing…")
    time.sleep(3)

    # ── Collect stats ─────────────────────────────────────────────────────────
    noml_stats = parse_stats(ctl(NOML_SOCK, "show stats"))
    ml_stats   = parse_stats(ctl(ML_SOCK,   "show stats"))

    # ── Print comparison ──────────────────────────────────────────────────────
    print_comparison(noml_stats, ml_stats)

    # ── Show top apps for ML-enabled daemon ───────────────────────────────────
    print("\n--- Top applications (ML-enabled) ---")
    print(ctl(ML_SOCK, "show applications top 20"))

    # ── Cleanup ───────────────────────────────────────────────────────────────
    stop_daemon(noml_proc, NOML_IFACE, NOML_SOCK)
    stop_daemon(ml_proc,   ML_IFACE,   ML_SOCK)
    if args.iface and not args.pcap:
        try:
            os.unlink(pcap_path)
        except Exception:
            pass


if __name__ == "__main__":
    main()
