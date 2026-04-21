// SPDX-License-Identifier: GPL-2.0
/*
 * ndpi_observe.bpf.c — TC eBPF classifier
 *
 * Attaches as TC ingress/egress on any Linux interface.
 * - New flows:         copies first IP packet to ring buffer for userspace nDPI.
 * - Classifying flows: re-sends packets until daemon writes a verdict.
 * - Classified flows:  counts bytes/packets in-kernel (zero userspace copy).
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "ndpi_obs_types.h"

/* ── BPF maps ─────────────────────────────────────────────────────────── */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct ndpi_obs_flow_key);
    __type(value, struct ndpi_obs_flow_state);
} flow_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct ndpi_obs_flow_key);
    __type(value, __u16);
} verdict_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 512);
    __type(key, __u32);
    __type(value, struct ndpi_obs_app_cnt);
} app_counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024);
} flow_events SEC(".maps");

/* ── Helpers ──────────────────────────────────────────────────────────── */

static __always_inline void
update_app_counter(__u32 app_id, __u64 bytes, int is_new_flow)
{
    if (app_id >= 512)
        return;
    struct ndpi_obs_app_cnt *cnt = bpf_map_lookup_elem(&app_counters, &app_id);
    if (!cnt)
        return;
    cnt->bytes   += bytes;
    cnt->packets += 1;
    if (is_new_flow)
        cnt->flows += 1;
}

static __always_inline void
send_to_ringbuf(struct __sk_buff *skb, const struct ndpi_obs_flow_key *key,
                __u32 ip_off, __u16 pkt_len, __u64 ts_ns)
{
    struct ndpi_obs_flow_event *evt =
        bpf_ringbuf_reserve(&flow_events, sizeof(*evt), 0);
    if (!evt)
        return;

    evt->key     = *key;
    evt->ts_ns   = ts_ns;
    evt->pkt_len = pkt_len;

    /*
     * Tiered capture: try the largest size first (512 bytes — covers QUIC
     * Initial packets ≥1200 bytes and large TLS frames ≥526 bytes), then fall
     * back to progressively smaller constants so the BPF verifier can check
     * buffer bounds statically.
     *
     * 256 bytes (frame ≥270): captures ~204 bytes of TLS payload — enough to
     * reach the SNI extension in a typical curl/OpenSSL TLS 1.3 ClientHello
     * (~350-400 byte frame).
     * 128 bytes (frame ≥142): covers padded test frames and medium packets.
     *  60 bytes (frame ≥74):  covers DNS queries (~77 byte frames).
     *
     * A failed bpf_skb_load_bytes writes nothing; data_len tells userspace
     * how many bytes are valid.
     */
    if      (bpf_skb_load_bytes(skb, ip_off, evt->pkt_data, FLOW_EVENT_DATA_LEN) == 0)
        evt->data_len = FLOW_EVENT_DATA_LEN;
    else if (bpf_skb_load_bytes(skb, ip_off, evt->pkt_data, 256) == 0)
        evt->data_len = 256;
    else if (bpf_skb_load_bytes(skb, ip_off, evt->pkt_data, 128) == 0)
        evt->data_len = 128;
    else if (bpf_skb_load_bytes(skb, ip_off, evt->pkt_data,  60) == 0)
        evt->data_len = 60;
    else
        evt->data_len = 0xDEAD0000 | (skb->len & 0xFFFF);

    bpf_ringbuf_submit(evt, 0);
}

static __always_inline int
process_pkt(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    if (ip->version != 4)
        return TC_ACT_OK;

    /* ihl is in 32-bit words; valid range 5-15 → 20-60 bytes */
    __u32 ihl = (__u32)(ip->ihl & 0x0f) * 4;
    if (ihl < 20)
        return TC_ACT_OK;

    /* Verify IP header fits in packet */
    if ((void *)ip + ihl > data_end)
        return TC_ACT_OK;

    struct ndpi_obs_flow_key key = {};
    key.src_ip = ip->saddr;
    key.dst_ip = ip->daddr;
    key.proto  = ip->protocol;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)((void *)ip + ihl);
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;
        key.src_port = tcp->source;
        key.dst_port = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)((void *)ip + ihl);
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;
        key.src_port = udp->source;
        key.dst_port = udp->dest;
    } else {
        return TC_ACT_OK;
    }

    __u64 pkt_bytes = skb->len;
    /* bpf_ntohs loses bounds after bswap — mask explicitly for verifier */
    __u32 ip_tot_u32 = bpf_ntohs(ip->tot_len);
    ip_tot_u32 &= 0xffff;
    __u16 ip_tot    = (__u16)ip_tot_u32;
    __u32 ip_off    = sizeof(*eth);
    __u64 ts        = bpf_ktime_get_ns();

    struct ndpi_obs_flow_state *fs = bpf_map_lookup_elem(&flow_map, &key);
    if (!fs) {
        struct ndpi_obs_flow_state new_fs = {
            .state        = FLOW_STATE_CLASSIFYING,
            .pkt_count    = 1,
            .app_id       = 0,
            .bytes        = pkt_bytes,
            .packets      = 1,
            .last_seen_ns = ts,
        };
        bpf_map_update_elem(&flow_map, &key, &new_fs, BPF_NOEXIST);
        send_to_ringbuf(skb, &key, ip_off, ip_tot, ts);
        return TC_ACT_OK;
    }

    fs->bytes        += pkt_bytes;
    fs->packets      += 1;
    fs->last_seen_ns  = ts;

    if (fs->state == FLOW_STATE_CLASSIFIED || fs->state == FLOW_STATE_GAVE_UP) {
        update_app_counter((__u32)fs->app_id, pkt_bytes, 0);
        return TC_ACT_OK;
    }

    __u16 *verdict = bpf_map_lookup_elem(&verdict_map, &key);
    if (verdict) {
        fs->app_id = *verdict;
        fs->state  = FLOW_STATE_CLASSIFIED;
        update_app_counter((__u32)fs->app_id, pkt_bytes, 1);
        return TC_ACT_OK;
    }

    fs->pkt_count++;
    if (fs->pkt_count >= FLOW_MAX_CLASSIFY_PKTS) {
        fs->state  = FLOW_STATE_GAVE_UP;
        fs->app_id = 0;
        update_app_counter(0, pkt_bytes, 1);
        return TC_ACT_OK;
    }

    send_to_ringbuf(skb, &key, ip_off, ip_tot, ts);
    return TC_ACT_OK;
}

SEC("tc")
int ndpi_observe_ingress(struct __sk_buff *skb)
{
    return process_pkt(skb);
}

SEC("tc")
int ndpi_observe_egress(struct __sk_buff *skb)
{
    return process_pkt(skb);
}

char LICENSE[] SEC("license") = "GPL";
