/* SPDX-License-Identifier: Apache-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <ndpi/ndpi_api.h>
#include "unix_socket.h"
#include "../bpf/ndpi_obs_types.h"

#define NDPI_OBS_VERSION "0.1.0"
#define RESP_BUF 65536

int unix_socket_init(const char *path)
{
    mkdir("/run/ndpid", 0755);
    unlink(path);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    struct sockaddr_un addr = {};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    listen(fd, 8);
    return fd;
}

static void fmt_ip(char *buf, size_t len, uint32_t ip_be)
{
    struct in_addr a = { .s_addr = ip_be };
    inet_ntop(AF_INET, &a, buf, (socklen_t)len);
}

static void handle_show_version(int fd)
{
    dprintf(fd, "ndpi-observe %s  libndpi %s\n",
            NDPI_OBS_VERSION, ndpi_revision());
}

static void handle_show_stats(int fd, ndpi_engine_t *e, int app_cnt_fd)
{
    uint64_t bpf_fastpath_pkts = 0;
    if (app_cnt_fd >= 0) {
        int ncpu = libbpf_num_possible_cpus();
        if (ncpu < 0) ncpu = 1;
        if (ncpu > 256) ncpu = 256;
        for (uint32_t i = 0; i < 512; i++) {
            struct ndpi_obs_app_cnt per_cpu[256] = {};
            if (bpf_map_lookup_elem(app_cnt_fd, &i, per_cpu) == 0) {
                for (int c = 0; c < ncpu; c++)
                    bpf_fastpath_pkts += per_cpu[c].packets;
            }
        }
    }

    dprintf(fd,
        "flows created:     %lu\n"
        "flows classified:  %lu\n"
        "flows gave up:     %lu\n"
        "flows active:      %u\n"
        "packets scanned:   %lu\n"
        "packets fastpath:  %lu\n"
        "nDPI calls:        %lu\n",
        e->flows.total_created,
        e->flows_classified,
        e->flows_gave_up,
        e->flows.count,
        e->pkts_scanned,
        bpf_fastpath_pkts,
        e->ndpi_calls);
}

static void handle_show_applications(int fd, ndpi_engine_t *e,
                                     int app_cnt_fd, int top_n)
{
    /* Collect per-app stats: merge userspace engine totals with BPF fast-path
     * counters still in BPF maps */
    uint64_t bytes[512]   = {};
    uint64_t packets[512] = {};
    uint64_t flows[512]   = {};

    /* Userspace classified flows */
    memcpy(bytes,   e->app_bytes,   sizeof(bytes));
    memcpy(packets, e->app_packets, sizeof(packets));
    memcpy(flows,   e->app_flows,   sizeof(flows));

    /* Add BPF PERCPU_ARRAY fast-path counters */
    if (app_cnt_fd >= 0) {
        for (uint32_t i = 0; i < 512; i++) {
            struct ndpi_obs_app_cnt per_cpu[256] = {};
            if (bpf_map_lookup_elem(app_cnt_fd, &i, per_cpu) == 0) {
                /* Sum per-cpu values */
                int ncpu = libbpf_num_possible_cpus();
                if (ncpu < 0) ncpu = 1;
                if (ncpu > 256) ncpu = 256;
                for (int c = 0; c < ncpu; c++) {
                    bytes  [i] += per_cpu[c].bytes;
                    packets[i] += per_cpu[c].packets;
                    flows  [i] += per_cpu[c].flows;
                }
            }
        }
    }

    /* Compute total bytes for percentage */
    uint64_t total_bytes = 0;
    for (int i = 0; i < 512; i++)
        total_bytes += bytes[i];

    /* Sort by bytes descending (simple insertion sort for 512 entries) */
    int order[512];
    for (int i = 0; i < 512; i++) order[i] = i;
    for (int i = 1; i < 512; i++) {
        int key = order[i];
        int j = i - 1;
        while (j >= 0 && bytes[order[j]] < bytes[key]) {
            order[j+1] = order[j];
            j--;
        }
        order[j+1] = key;
    }

    dprintf(fd, "%-30s %6s %10s %15s %8s\n",
            "Application", "Flows", "Packets", "Bytes", "%");

    int shown = 0;
    for (int i = 0; i < 512 && shown < top_n; i++) {
        int id = order[i];
        if (bytes[id] == 0)
            continue;
        const char *name = ndpi_engine_app_name(e, (uint16_t)id);
        double pct = total_bytes > 0
                     ? (double)bytes[id] * 100.0 / (double)total_bytes
                     : 0.0;
        dprintf(fd, "%-30s %6lu %10lu %15lu %7.1f%%\n",
                name, flows[id], packets[id], bytes[id], pct);
        shown++;
    }
    if (shown == 0)
        dprintf(fd, "(no classified flows yet)\n");
}

static void handle_show_flows(int fd, ndpi_engine_t *e, int count)
{
    dprintf(fd, "%-16s %-16s %5s %5s %5s %-16s %-32s %12s\n",
            "Src IP", "Dst IP", "Proto", "SPort", "DPort",
            "App", "SNI", "Bytes");

    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    int shown = 0;

    for (int i = 0; i < FLOW_TABLE_BUCKETS && shown < count; i++) {
        for (flow_entry_t *f = e->flows.buckets[i];
             f && shown < count;
             f = f->next) {
            fmt_ip(src, sizeof(src), f->key.src_ip);
            fmt_ip(dst, sizeof(dst), f->key.dst_ip);
            const char *app = ndpi_engine_app_name(e, f->app_id);
            dprintf(fd, "%-16s %-16s %5u %5u %5u %-16s %-32s %12lu\n",
                    src, dst, f->key.proto,
                    ntohs(f->key.src_port), ntohs(f->key.dst_port),
                    app, f->sni, f->bytes);
            shown++;
        }
    }
    if (shown == 0)
        dprintf(fd, "(no active flows)\n");
}

void unix_socket_handle(int server_fd, ndpi_engine_t *e, int app_cnt_fd)
{
    int cfd = accept(server_fd, NULL, NULL);
    if (cfd < 0)
        return;

    char buf[256] = {};
    ssize_t n = read(cfd, buf, sizeof(buf) - 1);
    if (n <= 0) {
        close(cfd);
        return;
    }
    /* Strip trailing newline */
    for (int i = 0; i < n; i++)
        if (buf[i] == '\n' || buf[i] == '\r') { buf[i] = '\0'; break; }

    if (strncmp(buf, "show version", 12) == 0) {
        handle_show_version(cfd);
    } else if (strncmp(buf, "show stats", 10) == 0) {
        handle_show_stats(cfd, e, app_cnt_fd);
    } else if (strncmp(buf, "show applications", 17) == 0) {
        int top = 20;
        char *p = strstr(buf, "top ");
        if (p) top = atoi(p + 4);
        handle_show_applications(cfd, e, app_cnt_fd, top);
    } else if (strncmp(buf, "show flows", 10) == 0) {
        int count = 50;
        char *p = strstr(buf, "count ");
        if (p) count = atoi(p + 6);
        handle_show_flows(cfd, e, count);
    } else {
        dprintf(cfd, "unknown command: %s\n"
                     "commands: show version | show stats | "
                     "show applications [top N] | show flows [count N]\n", buf);
    }

    close(cfd);
}

void unix_socket_destroy(int server_fd)
{
    close(server_fd);
    unlink(CLI_SOCK_PATH);
}
