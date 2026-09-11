/* SPDX-License-Identifier: Apache-2.0 */
#include <stdlib.h>
#include <string.h>
#include "flow_table.h"
#include <ndpi/ndpi_api.h>

static uint32_t flow_key_hash(const struct ndpi_obs_flow_key *k)
{
    /* Simple FNV-1a-inspired mix */
    uint32_t h = 2166136261u;
    const uint8_t *p = (const uint8_t *)k;
    for (size_t i = 0; i < sizeof(*k); i++) {
        h ^= p[i];
        h *= 16777619u;
    }
    return h % FLOW_TABLE_BUCKETS;
}

static int flow_key_eq(const struct ndpi_obs_flow_key *a,
                       const struct ndpi_obs_flow_key *b)
{
    return memcmp(a, b, sizeof(*a)) == 0;
}

void flow_table_init(flow_table_t *t)
{
    memset(t, 0, sizeof(*t));
}

flow_entry_t *flow_table_lookup(flow_table_t *t,
                                const struct ndpi_obs_flow_key *k)
{
    uint32_t idx = flow_key_hash(k);
    for (flow_entry_t *e = t->buckets[idx]; e; e = e->next) {
        if (flow_key_eq(&e->key, k))
            return e;
    }
    return NULL;
}

flow_entry_t *flow_table_get_or_create(flow_table_t *t,
                                       const struct ndpi_obs_flow_key *k)
{
    flow_entry_t *e = flow_table_lookup(t, k);
    if (e)
        return e;

    e = calloc(1, sizeof(*e));
    if (!e)
        return NULL;

    e->key        = *k;
    e->state      = FLOW_STATE_NEW;
    e->first_seen = (double)time(NULL);
    e->last_seen  = e->first_seen;

    uint32_t idx = flow_key_hash(k);
    e->next       = t->buckets[idx];
    t->buckets[idx] = e;
    t->count++;
    t->total_created++;
    return e;
}

void flow_table_remove(flow_table_t *t, const struct ndpi_obs_flow_key *k)
{
    uint32_t idx = flow_key_hash(k);
    flow_entry_t **pp = &t->buckets[idx];
    while (*pp) {
        if (flow_key_eq(&(*pp)->key, k)) {
            flow_entry_t *dead = *pp;
            *pp = dead->next;
            if (dead->ndpi_flow)
                ndpi_flow_free(dead->ndpi_flow);
            free(dead);
            t->count--;
            return;
        }
        pp = &(*pp)->next;
    }
}

void flow_table_age(flow_table_t *t, double now,
                    void (*on_expire)(flow_entry_t *, void *), void *ctx)
{
    for (int i = 0; i < FLOW_TABLE_BUCKETS; i++) {
        flow_entry_t **pp = &t->buckets[i];
        while (*pp) {
            flow_entry_t *e = *pp;
            double idle = now - e->last_seen;
            double timeout = (e->key.proto == 6)
                             ? FLOW_TCP_IDLE_SEC
                             : FLOW_UDP_IDLE_SEC;
            if (idle > timeout) {
                if (on_expire)
                    on_expire(e, ctx);
                *pp = e->next;
                if (e->ndpi_flow)
                    ndpi_flow_free(e->ndpi_flow);
                free(e);
                t->count--;
            } else {
                pp = &e->next;
            }
        }
    }
}

void flow_table_destroy(flow_table_t *t)
{
    for (int i = 0; i < FLOW_TABLE_BUCKETS; i++) {
        flow_entry_t *e = t->buckets[i];
        while (e) {
            flow_entry_t *next = e->next;
            if (e->ndpi_flow)
                ndpi_flow_free(e->ndpi_flow);
            free(e);
            e = next;
        }
        t->buckets[i] = NULL;
    }
    t->count = 0;
}
