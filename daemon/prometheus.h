/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PROMETHEUS_H
#define PROMETHEUS_H

#include "ndpi_engine.h"

#define PROMETHEUS_PORT 9197

int  prometheus_init(int port);
void prometheus_handle(int server_fd, ndpi_engine_t *e, int app_cnt_fd);
void prometheus_destroy(int server_fd);

#endif /* PROMETHEUS_H */
