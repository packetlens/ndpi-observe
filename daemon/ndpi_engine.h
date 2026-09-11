/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NDPI_ENGINE_H
#define NDPI_ENGINE_H

#include <stdint.h>
#include <stdio.h>
#include "flow_table.h"
#include "ndpi_dns_cache.h"

typedef struct ndpi_detection_module_struct ndpi_mod_t;

typedef struct {
    ndpi_mod_t  *ndpi;
    flow_table_t flows;

    /* Stats */
    uint64_t pkts_scanned;
    uint64_t pkts_cached;
    uint64_t ndpi_calls;
    uint64_t flows_classified;
    uint64_t flows_guessed;       /* rescued by ndpi_detection_giveup() */
    uint64_t flows_ml_classified; /* rescued by ML model */
    uint64_t flows_gave_up;

    int ml_enabled;  /* 1 = giveup+ML active (default); 0 = --no-ml */

    dns_cache_t dns_cache;  /* IP→hostname from observed DNS A responses */

    FILE *dump_features_fp;  /* non-NULL when --dump-features is active */

    char iface[64];  /* interface name for metric labels */

    /* Dynamic DNS-derived labels: SLD strings for unrecognized hostnames.
     * App IDs 400-463 map to dyn_labels[0-63]. Populated at runtime. */
    char dyn_labels[64][64];
    int  dyn_label_count;

    /* Per-app aggregated counters (app_id → totals across all flows) */
    /* These are accessed by show applications / prometheus */
    uint64_t app_bytes[512];
    uint64_t app_packets[512];
    uint64_t app_flows[512];

    /* Per-app classification method counters (incremented at classify time) */
    uint64_t app_classified_ndpi[512];
    uint64_t app_classified_giveup[512];
    uint64_t app_classified_ml[512];
    uint64_t app_classified_ml_dns[512]; /* ML flows where DNS cache confirmed the result */
    uint64_t app_classified_sni[512];    /* TLS ClientHello SNI overrode ndpi/giveup */
    uint64_t app_classified_dns[512];    /* Passive DNS cache (no SNI) overrode ndpi/giveup */

    /* Per-category traffic aggregates (nDPI category enum; <=64 covers all). */
    uint64_t cat_bytes[64];
    uint64_t cat_packets[64];
    uint64_t cat_flows[64];
} ndpi_engine_t;

/* Returns nDPI category name string; uses app_id→category lookup. */
const char *ndpi_engine_category_name(ndpi_engine_t *e, uint16_t app_id);
uint8_t     ndpi_engine_category_id(ndpi_engine_t *e, uint16_t app_id);
/* SNI-aware variant: applies override map for known product subdomains. */
uint8_t     ndpi_engine_category_for(ndpi_engine_t *e, uint16_t app_id, const char *sni);

int  ndpi_engine_init(ndpi_engine_t *e);
void ndpi_engine_set_ml(ndpi_engine_t *e, int enabled);
void ndpi_engine_set_dump_features(ndpi_engine_t *e, const char *path);
void ndpi_engine_process(ndpi_engine_t *e,
                         const struct ndpi_obs_flow_event *evt,
                         int verdict_map_fd);
void ndpi_engine_age(ndpi_engine_t *e);
void ndpi_engine_destroy(ndpi_engine_t *e);

/* Returns static string (thread-unsafe but fine for single-threaded daemon) */
const char *ndpi_engine_app_name(ndpi_engine_t *e, uint16_t app_id);

#endif /* NDPI_ENGINE_H */
