"""Integration tests — inject packets, verify nDPI classification."""

import socket
import struct
import time

import pytest

PEER_IFACE = "veth-obs1"
DST_IP     = "10.99.0.1"
PROM_PORT  = 19197


# ---------------------------------------------------------------------------
# Packet helpers (no scapy dependency — build raw frames manually)
# ---------------------------------------------------------------------------

def _ip_checksum(header):
    if len(header) % 2:
        header += b'\x00'
    s = 0
    for i in range(0, len(header), 2):
        s += (header[i] << 8) + header[i + 1]
    s = (s >> 16) + (s & 0xFFFF)
    s += (s >> 16)
    return ~s & 0xFFFF


def _build_eth_ip_tcp(src_ip, dst_ip, sport, dport, payload):
    # Ethernet (dst=ff:ff:ff:ff:ff:ff, src=02:00:00:00:00:01, type=IPv4)
    eth = b'\xff\xff\xff\xff\xff\xff' + b'\x02\x00\x00\x00\x00\x01' + b'\x08\x00'
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    tcp_len = 20 + len(payload)
    ip_hdr = struct.pack('!BBHHHBBH4s4s',
        0x45, 0, 20 + tcp_len,  # ver/ihl, tos, total len
        0, 0,                    # id, flags+frag
        64, 6, 0,                # ttl, proto=TCP, checksum=0
        src, dst)
    ip_hdr = ip_hdr[:10] + struct.pack('!H', _ip_checksum(ip_hdr)) + ip_hdr[12:]
    # TCP header — must be exactly 20 bytes (data_offset=0x50 → 5×4=20)
    # HHLLBBHHH: sport dport seq ack doff flags window checksum urgent
    tcp_hdr = struct.pack('!HHLLBBHHH',
        sport, dport, 0, 0,         # src, dst, seq, ack
        0x50, 0x18, 65535, 0, 0)    # data offset, PSH|ACK, window, checksum, urgent
    # pseudo header checksum
    pseudo = src + dst + b'\x00\x06' + struct.pack('!H', tcp_len)
    csum_data = pseudo + tcp_hdr + payload
    if len(csum_data) % 2:
        csum_data += b'\x00'
    s = 0
    for i in range(0, len(csum_data), 2):
        s += (csum_data[i] << 8) + csum_data[i + 1]
    s = (s >> 16) + (s & 0xFFFF)
    s += (s >> 16)
    csum = ~s & 0xFFFF
    tcp_hdr = tcp_hdr[:16] + struct.pack('!H', csum) + tcp_hdr[18:]
    return eth + ip_hdr + tcp_hdr + payload


def _tls_client_hello(sni: str) -> bytes:
    """Minimal TLS 1.0 ClientHello with SNI extension."""
    sni_b = sni.encode()
    sni_len = len(sni_b)
    # SNI extension
    ext_sni = (
        b'\x00\x00'                              # ext type: server_name
        + struct.pack('!H', sni_len + 5)         # ext data len
        + struct.pack('!H', sni_len + 3)         # server name list len
        + b'\x00'                                # name type: host_name
        + struct.pack('!H', sni_len)
        + sni_b
    )
    ext_len = struct.pack('!H', len(ext_sni))
    # Minimal ClientHello body
    body = (
        b'\x03\x03'          # client version TLS 1.2
        + b'\x00' * 32       # random (32 bytes)
        + b'\x00'            # session id len
        + b'\x00\x02'        # cipher suites len
        + b'\xc0\x2b'        # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        + b'\x01'            # compression methods len
        + b'\x00'            # null compression
        + ext_len + ext_sni
    )
    # Handshake header
    hs = b'\x01' + struct.pack('!I', len(body))[1:] + body
    # TLS record
    record = b'\x16\x03\x01' + struct.pack('!H', len(hs)) + hs
    return record


_MIN_FRAME = 14 + 128  # ensures the 128-byte fallback load in send_to_ringbuf succeeds


def _pad_frame(frame):
    """Pad to MIN_FRAME so the 128-byte fallback bpf_skb_load_bytes always succeeds."""
    if len(frame) < _MIN_FRAME:
        frame += b'\x00' * (_MIN_FRAME - len(frame))
    return frame


def _send_raw(iface, frame, count=5):
    """Send raw Ethernet frame via AF_PACKET."""
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((iface, 0))
    for _ in range(count):
        s.send(frame)
    s.close()


def _send_tls(sni="www.youtube.com", sport=10001, count=8):
    payload = _tls_client_hello(sni)
    frame = _build_eth_ip_tcp("10.99.0.2", DST_IP, sport, 443, payload)
    _send_raw(PEER_IFACE, _pad_frame(frame), count)


def _send_dns(sport=10100, count=4):
    """Send a minimal DNS query (UDP port 53)."""
    # DNS query for google.com
    dns = (
        b'\xab\xcd'   # txid
        b'\x01\x00'   # standard query
        b'\x00\x01'   # 1 question
        b'\x00\x00\x00\x00\x00\x00'
        b'\x06google\x03com\x00'
        b'\x00\x01'   # type A
        b'\x00\x01'   # class IN
    )
    # Build UDP manually
    eth = b'\xff\xff\xff\xff\xff\xff' + b'\x02\x00\x00\x00\x00\x01' + b'\x08\x00'
    src = socket.inet_aton("10.99.0.2")
    dst = socket.inet_aton(DST_IP)
    udp = struct.pack('!HHHH', sport, 53, 8 + len(dns), 0) + dns
    ip_total = 20 + len(udp)
    ip_hdr = struct.pack('!BBHHHBBH4s4s',
        0x45, 0, ip_total, 0, 0, 64, 17, 0, src, dst)
    ip_hdr = ip_hdr[:10] + struct.pack('!H', _ip_checksum(ip_hdr)) + ip_hdr[12:]
    frame = _pad_frame(eth + ip_hdr + udp)
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((PEER_IFACE, 0))
    for _ in range(count):
        s.send(frame)
    s.close()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_tls_classification(ndpid):
    """TLS ClientHello with SNI → classified as TLS (or QUIC/YouTube)."""
    _send_tls(sni="www.youtube.com", sport=20001, count=10)
    time.sleep(1)

    rc, out, _ = ndpid.ctl("show applications top 20")
    assert rc == 0
    assert "TLS" in out or "YouTube" in out or "Google" in out, \
        f"Expected TLS/YouTube/Google in applications:\n{out}"


def test_dns_classification(ndpid):
    """DNS UDP port 53 → classified as DNS (or Google for google.com queries)."""
    _send_dns(sport=20100, count=6)
    time.sleep(1)

    rc, out, _ = ndpid.ctl("show applications top 20")
    assert rc == 0
    assert "DNS" in out or "Google" in out, \
        f"Expected DNS or Google in applications:\n{out}"


def test_flows_table_populated(ndpid):
    """After sending traffic, show flows should list entries."""
    _send_tls(sni="example.com", sport=20200, count=5)
    time.sleep(1)

    rc, out, _ = ndpid.ctl("show flows count 20")
    assert rc == 0
    # Should have at least header + one flow
    lines = [l for l in out.strip().splitlines() if l and "no active" not in l]
    assert len(lines) >= 2, f"Expected at least one flow:\n{out}"


def test_stats_packets_scanned(ndpid):
    """After traffic, packets_scanned counter must be > 0."""
    rc, out, _ = ndpid.ctl("show stats")
    assert rc == 0
    for line in out.splitlines():
        if "packets scanned" in line:
            val = int(line.split()[-1])
            assert val > 0, f"packets_scanned should be > 0, got {val}"
            return
    pytest.fail(f"'packets scanned' not found in stats:\n{out}")


def test_prometheus_metrics(ndpid):
    """HTTP /metrics endpoint returns Prometheus text."""
    import urllib.request
    try:
        resp = urllib.request.urlopen(f"http://127.0.0.1:{PROM_PORT}/metrics", timeout=5)
        body = resp.read().decode()
    except Exception as e:
        pytest.skip(f"Prometheus not reachable: {e}")

    assert "ndpi_observe_flows_created_total" in body
    assert "ndpi_observe_app_bytes_total" in body
