/* SPDX-License-Identifier: Apache-2.0 */
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <bpf/bpf.h>
#include <ndpi/ndpi_api.h>
#include "ndpi_engine.h"

int ndpi_engine_init(ndpi_engine_t *e)
{
    memset(e, 0, sizeof(*e));

    e->ndpi = ndpi_init_detection_module(0);
    if (!e->ndpi)
        return -1;

    NDPI_PROTOCOL_BITMASK all;
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(e->ndpi, &all);
    ndpi_finalize_initialization(e->ndpi);

    flow_table_init(&e->flows);
    return 0;
}

const char *ndpi_engine_app_name(ndpi_engine_t *e, uint16_t app_id)
{
    return ndpi_get_proto_name(e->ndpi, app_id);
}

static void on_flow_expire(flow_entry_t *f, void *ctx)
{
    ndpi_engine_t *e = ctx;
    if (f->app_id < 512) {
        e->app_bytes  [f->app_id] += f->bytes;
        e->app_packets[f->app_id] += f->packets;
        e->app_flows  [f->app_id] += 1;
    }
}

void ndpi_engine_process(ndpi_engine_t *e,
                         const struct ndpi_obs_flow_event *evt,
                         int verdict_map_fd)
{
    const struct ndpi_obs_flow_key *k = &evt->key;

    flow_entry_t *f = flow_table_get_or_create(&e->flows, k);
    if (!f)
        return;

    f->last_seen = (double)time(NULL);

    if (f->state == FLOW_STATE_CLASSIFIED || f->state == FLOW_STATE_GAVE_UP) {
        e->pkts_cached++;
        return;
    }

    if (!f->ndpi_flow) {
        uint32_t sz = ndpi_detection_get_sizeof_ndpi_flow_struct();
        f->ndpi_flow = ndpi_flow_malloc(sz);
        if (!f->ndpi_flow) {
            f->state = FLOW_STATE_GAVE_UP;
            e->flows_gave_up++;
            return;
        }
        memset(f->ndpi_flow, 0, sz);
    }

    e->pkts_scanned++;
    e->ndpi_calls++;

    ndpi_protocol proto = ndpi_detection_process_packet(
        e->ndpi,
        f->ndpi_flow,
        (uint8_t *)evt->pkt_data,
        (uint16_t)evt->data_len,
        (uint64_t)(f->last_seen * 1000)   /* ms */
    );

    f->pkt_count++;
    f->bytes   += evt->pkt_len;
    f->packets += 1;

    uint16_t app    = proto.app_protocol;
    uint16_t master = proto.master_protocol;

    int got_verdict = 0;

    if (app != NDPI_PROTOCOL_UNKNOWN || master != NDPI_PROTOCOL_UNKNOWN) {
        f->app_id    = (app != NDPI_PROTOCOL_UNKNOWN) ? app : master;
        f->category  = (uint16_t)proto.category;
        f->state     = FLOW_STATE_CLASSIFIED;
        f->classified = 1;
        got_verdict  = 1;
        e->flows_classified++;

        if (f->ndpi_flow->host_server_name[0])
            strncpy(f->sni, (char *)f->ndpi_flow->host_server_name,
                    SNI_MAX_LEN - 1);

        ndpi_flow_free(f->ndpi_flow);
        f->ndpi_flow = NULL;
    } else if (f->pkt_count >= FLOW_MAX_CLASSIFY_PKTS) {
        f->app_id   = 0;
        f->state    = FLOW_STATE_GAVE_UP;
        got_verdict = 1;
        e->flows_gave_up++;

        ndpi_flow_free(f->ndpi_flow);
        f->ndpi_flow = NULL;
    }

    if (got_verdict && verdict_map_fd >= 0) {
        __u16 app_id = (__u16)f->app_id;
        bpf_map_update_elem(verdict_map_fd, k, &app_id, BPF_ANY);

        if (f->app_id < 512) {
            e->app_bytes  [f->app_id] += f->bytes;
            e->app_packets[f->app_id] += f->packets;
            e->app_flows  [f->app_id] += 1;
        }
    }
}

void ndpi_engine_age(ndpi_engine_t *e)
{
    double now = (double)time(NULL);
    flow_table_age(&e->flows, now, on_flow_expire, e);
}

void ndpi_engine_destroy(ndpi_engine_t *e)
{
    flow_table_destroy(&e->flows);
    if (e->ndpi) {
        ndpi_exit_detection_module(e->ndpi);
        e->ndpi = NULL;
    }
}
