/* SPDX-License-Identifier: Apache-2.0
 * Shared types between the TC eBPF program and the userspace daemon.
 * Use linux/types.h __uN types so this compiles in both contexts.
 */
#ifndef NDPI_OBS_TYPES_H
#define NDPI_OBS_TYPES_H

/* __u8/__u16/__u32/__u64 from linux/types.h in both BPF and userspace */
#include <linux/types.h>

/* Flow classification states */
#define FLOW_STATE_NEW         0
#define FLOW_STATE_CLASSIFYING 1
#define FLOW_STATE_CLASSIFIED  2
#define FLOW_STATE_GAVE_UP     3

/* Classification give-up threshold (packets per flow) */
#define FLOW_MAX_CLASSIFY_PKTS 8

/*
 * IP packet bytes copied to ring buffer for nDPI classification.
 * 512 bytes is the primary load; the BPF program falls back to 128 then 60
 * bytes for smaller packets (DNS ≈77 bytes, TCP SYN ≈66 bytes).
 * Test frames pad to 14+128=142 bytes to guarantee the 128-byte fallback
 * load succeeds; nDPI clips to the real IP tot_len so padding is invisible.
 */
#define FLOW_EVENT_DATA_LEN 512

/* 5-tuple flow key (IPv4 only for now) */
struct ndpi_obs_flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
    __u8  pad[3];
};

/* Per-flow state maintained in BPF hash map */
struct ndpi_obs_flow_state {
    __u8  state;        /* FLOW_STATE_* */
    __u8  pkt_count;    /* packets seen while CLASSIFYING */
    __u16 app_id;       /* nDPI app id (valid when CLASSIFIED) */
    __u32 pad;
    __u64 bytes;
    __u64 packets;
    __u64 last_seen_ns;
};

/* Per-app counters in PERCPU_ARRAY (fast path, zero userspace copy) */
struct ndpi_obs_app_cnt {
    __u64 bytes;
    __u64 packets;
    __u64 flows;
};

/* Ring buffer event: first packet of a new/classifying flow */
struct ndpi_obs_flow_event {
    struct ndpi_obs_flow_key key;
    __u8  pkt_data[FLOW_EVENT_DATA_LEN]; /* IP packet (L3+), truncated */
    __u32 pkt_len;    /* original IP packet length */
    __u32 data_len;   /* bytes valid in pkt_data */
    __u64 ts_ns;      /* ktime_get_ns() at capture time */
};

#endif /* NDPI_OBS_TYPES_H */
