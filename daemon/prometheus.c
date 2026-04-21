/* SPDX-License-Identifier: Apache-2.0
 * Minimal hand-rolled HTTP server for Prometheus /metrics endpoint.
 * Single-threaded, non-blocking accept; reads request, writes response, closes.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "prometheus.h"
#include "../bpf/ndpi_obs_types.h"

int prometheus_init(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0)
        return -1;

    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons((uint16_t)port),
        .sin_addr   = { .s_addr = INADDR_ANY },
    };
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    listen(fd, 4);
    return fd;
}

static void write_metrics(int cfd, ndpi_engine_t *e, int app_cnt_fd)
{
    /* Build metrics body in a large buffer */
    char *body = malloc(131072);
    if (!body) return;
    int pos = 0;

#define APPEND(fmt, ...) pos += snprintf(body + pos, 131072 - pos, fmt, ##__VA_ARGS__)

    const char *iface = e->iface[0] ? e->iface : "unknown";

    APPEND("# HELP ndpi_observe_info Static daemon metadata\n");
    APPEND("# TYPE ndpi_observe_info gauge\n");
    APPEND("ndpi_observe_info{iface=\"%s\"} 1\n", iface);

    APPEND("# HELP ndpi_observe_flows_created_total Total flows seen\n");
    APPEND("# TYPE ndpi_observe_flows_created_total counter\n");
    APPEND("ndpi_observe_flows_created_total{iface=\"%s\"} %lu\n", iface, e->flows.total_created);

    APPEND("# HELP ndpi_observe_flows_classified_total Flows successfully classified\n");
    APPEND("# TYPE ndpi_observe_flows_classified_total counter\n");
    APPEND("ndpi_observe_flows_classified_total{iface=\"%s\"} %lu\n", iface, e->flows_classified);

    APPEND("# HELP ndpi_observe_flows_guessed_total Flows rescued by ndpi_detection_giveup()\n");
    APPEND("# TYPE ndpi_observe_flows_guessed_total counter\n");
    APPEND("ndpi_observe_flows_guessed_total{iface=\"%s\"} %lu\n", iface, e->flows_guessed);

    APPEND("# HELP ndpi_observe_flows_ml_total Flows rescued by ML model\n");
    APPEND("# TYPE ndpi_observe_flows_ml_total counter\n");
    APPEND("ndpi_observe_flows_ml_total{iface=\"%s\"} %lu\n", iface, e->flows_ml_classified);

    APPEND("# HELP ndpi_observe_flows_gave_up_total Flows that hit the give-up threshold\n");
    APPEND("# TYPE ndpi_observe_flows_gave_up_total counter\n");
    APPEND("ndpi_observe_flows_gave_up_total{iface=\"%s\"} %lu\n", iface, e->flows_gave_up);

    APPEND("# HELP ndpi_observe_flows_active Current active flows\n");
    APPEND("# TYPE ndpi_observe_flows_active gauge\n");
    APPEND("ndpi_observe_flows_active{iface=\"%s\"} %u\n", iface, e->flows.count);

    APPEND("# HELP ndpi_observe_packets_scanned_total Packets sent to nDPI\n");
    APPEND("# TYPE ndpi_observe_packets_scanned_total counter\n");
    APPEND("ndpi_observe_packets_scanned_total{iface=\"%s\"} %lu\n", iface, e->pkts_scanned);

    /* Per-app stats: merge userspace + BPF fast-path */
    uint64_t bytes[512]   = {};
    uint64_t packets[512] = {};
    uint64_t flows[512]   = {};
    uint64_t bpf_fastpath_pkts  = 0;
    uint64_t bpf_fastpath_bytes = 0;

    memcpy(bytes,   e->app_bytes,   sizeof(bytes));
    memcpy(packets, e->app_packets, sizeof(packets));
    memcpy(flows,   e->app_flows,   sizeof(flows));

    if (app_cnt_fd >= 0) {
        int ncpu = libbpf_num_possible_cpus();
        if (ncpu < 0) ncpu = 1;
        if (ncpu > 256) ncpu = 256;
        for (uint32_t i = 0; i < 512; i++) {
            struct ndpi_obs_app_cnt per_cpu[256] = {};
            if (bpf_map_lookup_elem(app_cnt_fd, &i, per_cpu) == 0) {
                for (int c = 0; c < ncpu; c++) {
                    bytes  [i] += per_cpu[c].bytes;
                    packets[i] += per_cpu[c].packets;
                    flows  [i] += per_cpu[c].flows;
                    bpf_fastpath_pkts  += per_cpu[c].packets;
                    bpf_fastpath_bytes += per_cpu[c].bytes;
                }
            }
        }
    }

    APPEND("# HELP ndpi_observe_packets_fastpath_total Packets counted in BPF fast path (no userspace copy)\n");
    APPEND("# TYPE ndpi_observe_packets_fastpath_total counter\n");
    APPEND("ndpi_observe_packets_fastpath_total{iface=\"%s\"} %lu\n", iface, bpf_fastpath_pkts);

    APPEND("# HELP ndpi_observe_bytes_fastpath_total Bytes counted in BPF fast path (no userspace copy)\n");
    APPEND("# TYPE ndpi_observe_bytes_fastpath_total counter\n");
    APPEND("ndpi_observe_bytes_fastpath_total{iface=\"%s\"} %lu\n", iface, bpf_fastpath_bytes);

    APPEND("# HELP ndpi_observe_app_bytes_total Bytes per application\n");
    APPEND("# TYPE ndpi_observe_app_bytes_total counter\n");
    for (int i = 0; i < 512; i++) {
        if (bytes[i] == 0) continue;
        const char *name = ndpi_engine_app_name(e, (uint16_t)i);
        APPEND("ndpi_observe_app_bytes_total{iface=\"%s\",app=\"%s\"} %lu\n", iface, name, bytes[i]);
    }

    APPEND("# HELP ndpi_observe_app_packets_total Packets per application\n");
    APPEND("# TYPE ndpi_observe_app_packets_total counter\n");
    for (int i = 0; i < 512; i++) {
        if (packets[i] == 0) continue;
        const char *name = ndpi_engine_app_name(e, (uint16_t)i);
        APPEND("ndpi_observe_app_packets_total{iface=\"%s\",app=\"%s\"} %lu\n", iface, name, packets[i]);
    }

    APPEND("# HELP ndpi_observe_app_flows_total Flows per application\n");
    APPEND("# TYPE ndpi_observe_app_flows_total counter\n");
    for (int i = 0; i < 512; i++) {
        if (flows[i] == 0) continue;
        const char *name = ndpi_engine_app_name(e, (uint16_t)i);
        APPEND("ndpi_observe_app_flows_total{iface=\"%s\",app=\"%s\"} %lu\n", iface, name, flows[i]);
    }

    APPEND("# HELP ndpi_observe_app_classified_total Flows classified per app and method\n");
    APPEND("# TYPE ndpi_observe_app_classified_total counter\n");
    for (int i = 0; i < 512; i++) {
        uint64_t n = e->app_classified_ndpi[i];
        uint64_t g = e->app_classified_giveup[i];
        uint64_t m = e->app_classified_ml[i];
        if (n == 0 && g == 0 && m == 0) continue;
        const char *name = ndpi_engine_app_name(e, (uint16_t)i);
        if (n > 0)
            APPEND("ndpi_observe_app_classified_total{iface=\"%s\",app=\"%s\",method=\"ndpi\"} %lu\n",   iface, name, n);
        if (g > 0)
            APPEND("ndpi_observe_app_classified_total{iface=\"%s\",app=\"%s\",method=\"giveup\"} %lu\n", iface, name, g);
        if (m > 0)
            APPEND("ndpi_observe_app_classified_total{iface=\"%s\",app=\"%s\",method=\"ml\"} %lu\n",     iface, name, m);
    }

    /* Process metrics from /proc/self/stat */
    {
        FILE *f = fopen("/proc/self/stat", "r");
        if (f) {
            unsigned long utime = 0, stime = 0;
            long rss = 0;
            /* fields: pid(1) name(2) state(3) ... utime(14) stime(15) ... rss(24) */
            fscanf(f, "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u "
                      "%lu %lu %*d %*d %*d %*d %*d %*d %*u %*u %ld",
                   &utime, &stime, &rss);
            fclose(f);
            long clk = sysconf(_SC_CLK_TCK);
            if (clk <= 0) clk = 100;
            double cpu_sec = (double)(utime + stime) / (double)clk;
            long page = sysconf(_SC_PAGE_SIZE);
            if (page <= 0) page = 4096;
            APPEND("# HELP process_cpu_seconds_total Total CPU time used by ndpid\n");
            APPEND("# TYPE process_cpu_seconds_total counter\n");
            APPEND("process_cpu_seconds_total{iface=\"%s\"} %.3f\n", iface, cpu_sec);
            APPEND("# HELP process_resident_memory_bytes RSS memory used by ndpid\n");
            APPEND("# TYPE process_resident_memory_bytes gauge\n");
            APPEND("process_resident_memory_bytes{iface=\"%s\"} %ld\n", iface, rss * page);
        }
    }
#undef APPEND

    /* Send HTTP response */
    char header[256];
    snprintf(header, sizeof(header),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain; version=0.0.4\r\n"
        "Content-Length: %d\r\n"
        "\r\n", pos);

    (void)write(cfd, header, strlen(header));
    (void)write(cfd, body, pos);
    free(body);
}

void prometheus_handle(int server_fd, ndpi_engine_t *e, int app_cnt_fd)
{
    /* accept4 without SOCK_NONBLOCK — client socket must be blocking for writes */
    int cfd = accept4(server_fd, NULL, NULL, SOCK_CLOEXEC);
    if (cfd < 0)
        return;

    /* Read and discard the HTTP request */
    char req[1024];
    (void)read(cfd, req, sizeof(req));

    write_metrics(cfd, e, app_cnt_fd);
    close(cfd);
}

void prometheus_destroy(int server_fd)
{
    close(server_fd);
}
