/* SPDX-License-Identifier: Apache-2.0 */
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <ndpi/ndpi_api.h>
#include "ndpi_engine.h"
#include "ndpi_ml.h"
#include "ndpi_ai_services.h"

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
    e->ml_enabled = 1;  /* giveup + ML on by default */
    return 0;
}

void ndpi_engine_set_ml(ndpi_engine_t *e, int enabled)
{
    e->ml_enabled = enabled;
}

void ndpi_engine_set_dump_features(ndpi_engine_t *e, const char *path)
{
    e->dump_features_fp = fopen(path, "w");
    if (!e->dump_features_fp) {
        fprintf(stderr, "ndpid: warning: cannot open feature dump file %s\n", path);
        return;
    }
    fprintf(e->dump_features_fp,
        "label,pkt_len_mean,pkt_len_std,pkt_len_min,pkt_len_max,pkt_len_total,"
        "iat_mean_s,iat_std_s,iat_min_s,iat_max_s,duration_s,n_pkts,"
        "proto,dport,first_pkt_len,last_pkt_len\n");
    fflush(e->dump_features_fp);
}

const char *ndpi_engine_app_name(ndpi_engine_t *e, uint16_t app_id)
{
    const char *ai = ndpi_ai_app_name(app_id);
    if (ai) return ai;
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

    /* Opportunistically cache IP→hostname from DNS responses (src_port=53, UDP) */
    if (k->proto == IPPROTO_UDP && ntohs(k->src_port) == 53)
        dns_cache_update(&e->dns_cache, evt->pkt_data, evt->data_len);

    flow_entry_t *f = flow_table_get_or_create(&e->flows, k);
    if (!f)
        return;

    f->last_seen = (double)time(NULL);

    if (f->state == FLOW_STATE_CLASSIFIED || f->state == FLOW_STATE_GAVE_UP) {
        e->pkts_cached++;
        return;
    }

    uint16_t actual_data_len = ((evt->data_len & 0xFFFF0000) == 0xDEAD0000)
                               ? 0 : (uint16_t)evt->data_len;

    f->pkt_count++;
    f->bytes   += evt->pkt_len;
    f->packets += 1;

    /* Don't call nDPI for packets with no captured payload (TCP SYN/ACK, etc.)
     * — those waste nDPI's detection-attempt budget without providing data. */
    if (actual_data_len == 0) {
        if (f->pkt_count >= FLOW_MAX_CLASSIFY_PKTS) {
            f->app_id  = 0;
            f->state   = FLOW_STATE_GAVE_UP;
            e->flows_gave_up++;
            if (verdict_map_fd >= 0) {
                __u16 app_id = 0;
                bpf_map_update_elem(verdict_map_fd, k, &app_id, BPF_ANY);
            }
        }
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

    /* Accumulate ML features from the IP-layer packet length. */
    {
        uint16_t pkt_len = (evt->pkt_len > 0xFFFF) ? 0xFFFF : (uint16_t)evt->pkt_len;
        double   now_s   = f->last_seen;

        if (f->ml_n_pkts == 0) {
            f->ml_first_pkt = pkt_len;
            f->ml_pkt_min   = pkt_len;
            f->ml_pkt_max   = pkt_len;
            f->ml_iat_min   = 1e30f;
            f->ml_iat_max   = 0.0f;
        } else {
            float iat_s = (float)(now_s - f->ml_last_pkt_time);
            f->ml_iat_sum += iat_s;
            f->ml_iat_sq  += iat_s * iat_s;
            if (iat_s < f->ml_iat_min) f->ml_iat_min = iat_s;
            if (iat_s > f->ml_iat_max) f->ml_iat_max = iat_s;
        }
        f->ml_pkt_sum += (float)pkt_len;
        f->ml_pkt_sq  += (float)pkt_len * (float)pkt_len;
        if (pkt_len < f->ml_pkt_min) f->ml_pkt_min = pkt_len;
        if (pkt_len > f->ml_pkt_max) f->ml_pkt_max = pkt_len;
        f->ml_last_pkt      = pkt_len;
        f->ml_last_pkt_time = now_s;
        f->ml_n_pkts++;
    }

    /*
     * Patch a local copy of the packet so nDPI sees a self-consistent
     * truncated packet rather than a large packet with missing bytes.
     */
    uint8_t tmp_pkt[FLOW_EVENT_DATA_LEN];
    memcpy(tmp_pkt, evt->pkt_data, actual_data_len);

    /* Clamp IP tot_len to actual captured length */
    uint16_t ip_tot = (uint16_t)((tmp_pkt[2] << 8) | tmp_pkt[3]);
    if (ip_tot > actual_data_len) {
        tmp_pkt[2] = (uint8_t)(actual_data_len >> 8);
        tmp_pkt[3] = (uint8_t)(actual_data_len & 0xFF);
    }

    /* For TCP, clamp TLS record length if the record extends beyond captured data */
    if (k->proto == 6) {
        uint8_t  ihl   = (tmp_pkt[0] & 0xf) * 4;
        uint8_t  doff  = (tmp_pkt[ihl + 12] >> 4) * 4;
        uint16_t l7off = ihl + doff;
        if (l7off + 5 <= actual_data_len && tmp_pkt[l7off] == 0x16) {
            uint16_t rec_len = (uint16_t)((tmp_pkt[l7off+3] << 8) | tmp_pkt[l7off+4]);
            uint16_t avail   = actual_data_len - l7off - 5;
            if (rec_len > avail) {
                tmp_pkt[l7off+3] = (uint8_t)(avail >> 8);
                tmp_pkt[l7off+4] = (uint8_t)(avail & 0xFF);
            }
        }
    }

    ndpi_protocol proto = ndpi_detection_process_packet(
        e->ndpi,
        f->ndpi_flow,
        tmp_pkt,
        actual_data_len,
        (uint64_t)(f->last_seen * 1000)   /* ms */
    );

    uint16_t app    = proto.app_protocol;
    uint16_t master = proto.master_protocol;

    int got_verdict = 0;

    if (app != NDPI_PROTOCOL_UNKNOWN || master != NDPI_PROTOCOL_UNKNOWN) {
        /* nDPI classified the flow */
        f->app_id    = (app != NDPI_PROTOCOL_UNKNOWN) ? app : master;
        f->category  = (uint16_t)proto.category;
        f->state     = FLOW_STATE_CLASSIFIED;
        f->classified = 1;
        got_verdict  = 1;
        e->flows_classified++;
        if (f->app_id < 512)
            e->app_classified_ndpi[f->app_id]++;

        if (f->ndpi_flow->host_server_name[0])
            strncpy(f->sni, (char *)f->ndpi_flow->host_server_name,
                    SNI_MAX_LEN - 1);

        {
            const char *host = f->sni[0] ? f->sni
                : dns_cache_lookup(&e->dns_cache, k->dst_ip);
            if (host) {
                uint16_t ai_id = match_ai_service(host);
                if (ai_id && f->app_id < 512) {
                    e->app_classified_ndpi[f->app_id]--;
                    f->app_id = ai_id;
                    if (f->app_id < 512) e->app_classified_sni[f->app_id]++;
                }
            }
        }

        ndpi_flow_free(f->ndpi_flow);
        f->ndpi_flow = NULL;

    } else if (f->pkt_count >= FLOW_MAX_CLASSIFY_PKTS) {
        got_verdict = 1;

        if (e->ml_enabled) {
            /* Step 1: nDPI built-in guesser (port-based + heuristic) */
            u_int8_t was_guessed = 0;
            ndpi_protocol gp = ndpi_detection_giveup(
                e->ndpi, f->ndpi_flow, 1 /* enable_guess */, &was_guessed);

            uint16_t ga = gp.app_protocol;
            uint16_t gm = gp.master_protocol;

            if (ga != NDPI_PROTOCOL_UNKNOWN || gm != NDPI_PROTOCOL_UNKNOWN) {
                f->app_id    = (ga != NDPI_PROTOCOL_UNKNOWN) ? ga : gm;
                f->category  = (uint16_t)gp.category;
                f->state     = FLOW_STATE_CLASSIFIED;
                f->classified = 1;
                e->flows_guessed++;
                e->flows_classified++;
                if (f->app_id < 512)
                    e->app_classified_giveup[f->app_id]++;

                if (f->ndpi_flow->host_server_name[0])
                    strncpy(f->sni, (char *)f->ndpi_flow->host_server_name,
                            SNI_MAX_LEN - 1);

                {
                    const char *host = f->sni[0] ? f->sni
                        : dns_cache_lookup(&e->dns_cache, k->dst_ip);
                    if (host) {
                        uint16_t ai_id = match_ai_service(host);
                        if (ai_id && f->app_id < 512) {
                            e->app_classified_giveup[f->app_id]--;
                            f->app_id = ai_id;
                            if (f->app_id < 512) e->app_classified_sni[f->app_id]++;
                        }
                    }
                }
            }

            /* Step 2: ML model — runs on ALL flows (including giveup-classified ones).
             * Giveup returns generic labels (TLS, Google, Cloudflare); ML can refine
             * these into specific apps (YouTube, Netflix, Zoom, Steam, GitHub).
             * Only override if ML is confident (threshold enforced in ndpi_ml_classify). */
            if (f->ml_n_pkts > 0) {
                ndpi_ml_features_t feat;
                float n        = (float)f->ml_n_pkts;
                float iat_n    = (n > 1.0f) ? (n - 1.0f) : 1.0f;
                float pkt_mean = f->ml_pkt_sum / n;
                float iat_mean = f->ml_iat_sum / iat_n;
                float pkt_var  = (f->ml_pkt_sq / n) - pkt_mean * pkt_mean;
                float iat_var  = (n > 2.0f)
                    ? ((f->ml_iat_sq / iat_n) - iat_mean * iat_mean) : 0.0f;

                feat.pkt_len_mean  = pkt_mean;
                feat.pkt_len_std   = (pkt_var > 0.0f) ? sqrtf(pkt_var) : 0.0f;
                feat.pkt_len_min   = (float)f->ml_pkt_min;
                feat.pkt_len_max   = (float)f->ml_pkt_max;
                feat.pkt_len_total = f->ml_pkt_sum;
                feat.iat_mean_s    = iat_mean;
                feat.iat_std_s     = (iat_var > 0.0f) ? sqrtf(iat_var) : 0.0f;
                feat.iat_min_s     = (n > 1.0f) ? f->ml_iat_min : 0.0f;
                feat.iat_max_s     = f->ml_iat_max;
                feat.duration_s    = (float)(f->last_seen - f->first_seen);
                feat.n_pkts        = n;
                feat.proto         = (float)k->proto;
                feat.dport         = (float)ntohs(k->dst_port);
                feat.first_pkt_len = (float)f->ml_first_pkt;
                feat.last_pkt_len  = (float)f->ml_last_pkt;

                uint16_t ml_app = ndpi_ml_classify(&feat);
                if (ml_app != 0) {
                    if (f->state == FLOW_STATE_CLASSIFIED) {
                        /* ML refines a giveup result: undo the per-app giveup credit */
                        if (f->app_id < 512)
                            e->app_classified_giveup[f->app_id]--;
                        e->flows_guessed--;
                    } else {
                        /* ML classifies a truly unknown flow */
                        e->flows_classified++;
                    }
                    /* MCP sub-type: SNI first, DNS cache fallback for reused connections */
                    if (ml_app == NDPI_APP_MCP) {
                        const char *host = f->sni[0] ? f->sni
                            : dns_cache_lookup(&e->dns_cache, k->dst_ip);
                        ml_app = match_mcp_service(host);
                    }
                    f->app_id    = ml_app;
                    f->state     = FLOW_STATE_CLASSIFIED;
                    f->classified = 1;
                    e->flows_ml_classified++;
                    if (f->app_id < 512)
                        e->app_classified_ml[f->app_id]++;
                }
            }
        }

        if (f->state != FLOW_STATE_CLASSIFIED) {
            f->app_id = 0;
            f->state  = FLOW_STATE_GAVE_UP;
            e->flows_gave_up++;
        }

        ndpi_flow_free(f->ndpi_flow);
        f->ndpi_flow = NULL;
    }

    if (got_verdict) {
        if (verdict_map_fd >= 0) {
            __u16 app_id = (__u16)f->app_id;
            bpf_map_update_elem(verdict_map_fd, k, &app_id, BPF_ANY);
        }

        if (f->app_id < 512) {
            e->app_bytes  [f->app_id] += f->bytes;
            e->app_packets[f->app_id] += f->packets;
            e->app_flows  [f->app_id] += 1;
        }

        /* Feature dump for ML retraining (--dump-features). Only write rows
         * where we have enough packets to compute meaningful statistics. */
        if (e->dump_features_fp && f->ml_n_pkts > 0) {
            float n        = (float)f->ml_n_pkts;
            float iat_n    = (n > 1.0f) ? (n - 1.0f) : 1.0f;
            float pkt_mean = f->ml_pkt_sum / n;
            float iat_mean = f->ml_iat_sum / iat_n;
            float pkt_var  = (f->ml_pkt_sq / n) - pkt_mean * pkt_mean;
            float iat_var  = (n > 2.0f)
                ? ((f->ml_iat_sq / iat_n) - iat_mean * iat_mean) : 0.0f;
            float pkt_std  = (pkt_var > 0.0f) ? sqrtf(pkt_var) : 0.0f;
            float iat_std  = (iat_var > 0.0f) ? sqrtf(iat_var) : 0.0f;
            float iat_min  = (n > 1.0f) ? f->ml_iat_min : 0.0f;
            float duration = (float)(f->last_seen - f->first_seen);

            const char *label = ndpi_engine_app_name(e, f->app_id);
            if (!label || label[0] == '\0') label = "unknown";

            fprintf(e->dump_features_fp,
                "%s,%.4f,%.4f,%.4f,%.4f,%.4f,"
                "%.6f,%.6f,%.6f,%.6f,%.4f,%.0f,"
                "%.0f,%.0f,%.4f,%.4f\n",
                label,
                pkt_mean, pkt_std,
                (float)f->ml_pkt_min, (float)f->ml_pkt_max, f->ml_pkt_sum,
                iat_mean, iat_std, iat_min, f->ml_iat_max,
                duration, n,
                (float)k->proto, (float)ntohs(k->dst_port),
                (float)f->ml_first_pkt, (float)f->ml_last_pkt);
            fflush(e->dump_features_fp);
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
    if (e->dump_features_fp) {
        fclose(e->dump_features_fp);
        e->dump_features_fp = NULL;
    }
}
