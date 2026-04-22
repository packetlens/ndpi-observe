/* SPDX-License-Identifier: Apache-2.0
 * Userspace flow table — mirrors the BPF flow_map but stores rich metadata.
 */
#ifndef FLOW_TABLE_H
#define FLOW_TABLE_H

#include <stdint.h>
#include <time.h>
#include "../bpf/ndpi_obs_types.h"

/* Forward declaration */
struct ndpi_flow_struct;

#define FLOW_TABLE_BUCKETS  65536
#define SNI_MAX_LEN         80
#define JA3_MAX_LEN         33
#define FLOW_TCP_IDLE_SEC   300
#define FLOW_UDP_IDLE_SEC   30

typedef struct flow_entry {
    struct ndpi_obs_flow_key key;

    uint8_t  state;      /* mirrors BPF FLOW_STATE_* */
    uint8_t  pkt_count;
    uint16_t app_id;
    uint16_t category;
    uint8_t  classified;
    uint8_t  credit_method; /* which counter holds the classification credit:
                               0=none 1=ndpi 2=giveup 3=sni 4=ml 5=dns */

    uint64_t bytes;
    uint64_t packets;
    double   first_seen;  /* seconds since epoch */
    double   last_seen;

    char sni[SNI_MAX_LEN];
    char ja3[JA3_MAX_LEN];

    struct ndpi_flow_struct *ndpi_flow;  /* freed after classification */

    /* ML feature accumulators — filled per packet, consumed at give-up */
    float    ml_pkt_sum;
    float    ml_pkt_sq;
    uint16_t ml_pkt_min;
    uint16_t ml_pkt_max;
    uint16_t ml_first_pkt;
    uint16_t ml_last_pkt;
    float    ml_iat_sum;
    float    ml_iat_sq;
    float    ml_iat_min;
    float    ml_iat_max;
    double   ml_last_pkt_time;
    uint8_t  ml_n_pkts;

    struct flow_entry *next;  /* hash chain */
} flow_entry_t;

typedef struct {
    flow_entry_t *buckets[FLOW_TABLE_BUCKETS];
    uint32_t      count;
    uint32_t      classified;
    uint32_t      gave_up;
    uint64_t      total_created;
} flow_table_t;

void          flow_table_init(flow_table_t *t);
flow_entry_t *flow_table_lookup(flow_table_t *t,
                                const struct ndpi_obs_flow_key *k);
flow_entry_t *flow_table_get_or_create(flow_table_t *t,
                                       const struct ndpi_obs_flow_key *k);
void          flow_table_remove(flow_table_t *t,
                                const struct ndpi_obs_flow_key *k);
void          flow_table_age(flow_table_t *t, double now,
                             void (*on_expire)(flow_entry_t *, void *),
                             void *ctx);
void          flow_table_destroy(flow_table_t *t);

#endif /* FLOW_TABLE_H */
