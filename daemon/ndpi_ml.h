/* SPDX-License-Identifier: Apache-2.0
 * ML classification fallback — fires after ndpi_detection_giveup() fails.
 * Ported from vpp-ndpi (PacketFlow).
 */
#ifndef NDPI_ML_H
#define NDPI_ML_H

#include <stdint.h>

#define NDPI_ML_N_FEATURES 15

typedef struct {
    float pkt_len_mean;
    float pkt_len_std;
    float pkt_len_min;
    float pkt_len_max;
    float pkt_len_total;
    float iat_mean_s;
    float iat_std_s;
    float iat_min_s;
    float iat_max_s;
    float duration_s;
    float n_pkts;
    float proto;
    float dport;
    float first_pkt_len;
    float last_pkt_len;
} ndpi_ml_features_t;

struct ndpi_detection_module_struct;

/* Resolve class names → nDPI proto IDs; call once after ndpi init. */
void ndpi_ml_init(struct ndpi_detection_module_struct *ndpi);

/* Returns nDPI app_protocol ID if model is confident, or 0 (UNKNOWN). */
uint16_t ndpi_ml_classify(const ndpi_ml_features_t *feat);

#endif /* NDPI_ML_H */
