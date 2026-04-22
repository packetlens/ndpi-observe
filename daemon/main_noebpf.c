/* SPDX-License-Identifier: Apache-2.0
 * ndpid-simple — AF_PACKET + nDPI daemon (no eBPF)
 *
 * Every packet crosses the kernel/userspace boundary via recvfrom().
 * Classified flows are counted in userspace (no BPF fast path).
 * Use alongside ndpid to measure the eBPF fast-path CPU savings.
 *
 * Usage: ndpid-simple -i <interface> [-p <prometheus_port>] [-s <cli_socket>]
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <getopt.h>
#include <poll.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#include "../bpf/ndpi_obs_types.h"
#include "ndpi_engine.h"
#include "unix_socket.h"
#include "prometheus.h"

#define SIMPLE_CLI_SOCK_PATH  "/run/ndpid-simple/cli.sock"
#define SIMPLE_PROM_PORT      19198
#define PKT_BUF_SIZE          65536

static volatile int g_running = 1;

static void sig_handler(int sig) { (void)sig; g_running = 0; }

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s -i <interface> [-p <port>] [-s <socket>] [--no-ml] [--dump-features <file>]\n"
        "  -i                Network interface to observe (required)\n"
        "  -p                Prometheus metrics port (default: %d)\n"
        "  -s                CLI socket path (default: %s)\n"
        "  --no-ml           Disable ndpi_detection_giveup + ML fallback\n"
        "  --dump-features   Write per-flow ML feature vectors to CSV for retraining\n",
        prog, SIMPLE_PROM_PORT, SIMPLE_CLI_SOCK_PATH);
}

int main(int argc, char **argv)
{
    const char *ifname             = NULL;
    int         prom_port          = SIMPLE_PROM_PORT;
    const char *sock_path          = SIMPLE_CLI_SOCK_PATH;
    int         ml_enabled         = 1;
    const char *dump_features_path = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--no-ml") == 0) {
            ml_enabled = 0;
            argv[i] = (char *)"";
        } else if (strcmp(argv[i], "--dump-features") == 0 && i + 1 < argc) {
            dump_features_path = argv[i + 1];
            argv[i]     = (char *)"";
            argv[i + 1] = (char *)"";
            i++;
        }
    }

    int opt;
    while ((opt = getopt(argc, argv, "i:p:s:h")) != -1) {
        switch (opt) {
        case 'i': ifname    = optarg;       break;
        case 'p': prom_port = atoi(optarg); break;
        case 's': sock_path = optarg;       break;
        case 'h':
        default:
            usage(argv[0]);
            return opt == 'h' ? 0 : 1;
        }
    }

    if (!ifname) {
        fprintf(stderr, "error: -i <interface> is required\n");
        usage(argv[0]);
        return 1;
    }

    /* Resolve interface index */
    int ifindex = (int)if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "error: interface %s not found\n", ifname);
        return 1;
    }

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    /* ── AF_PACKET raw socket ─────────────────────────────────────────── */
    int pkt_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (pkt_fd < 0) {
        perror("socket(AF_PACKET)");
        return 1;
    }

    struct sockaddr_ll sll = {
        .sll_family   = AF_PACKET,
        .sll_protocol = htons(ETH_P_ALL),
        .sll_ifindex  = ifindex,
    };
    if (bind(pkt_fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind(AF_PACKET)");
        close(pkt_fd);
        return 1;
    }

    fprintf(stderr, "ndpid-simple: observing %s (AF_PACKET, no eBPF)\n", ifname);

    /* ── nDPI engine ─────────────────────────────────────────────────── */
    ndpi_engine_t engine;
    if (ndpi_engine_init(&engine) < 0) {
        fprintf(stderr, "error: failed to initialize nDPI\n");
        close(pkt_fd);
        return 1;
    }
    ndpi_engine_set_ml(&engine, ml_enabled);
    snprintf(engine.iface, sizeof(engine.iface), "%s", ifname);
    if (!ml_enabled)
        fprintf(stderr, "ndpid-simple: ML/giveup disabled (--no-ml)\n");
    if (dump_features_path) {
        ndpi_engine_set_dump_features(&engine, dump_features_path);
        fprintf(stderr, "ndpid-simple: dumping ML features to %s\n", dump_features_path);
    }

    /* ── CLI Unix socket ─────────────────────────────────────────────── */
    int cli_fd = unix_socket_init(sock_path);
    if (cli_fd < 0)
        fprintf(stderr, "warning: failed to create CLI socket at %s: %s\n",
                sock_path, strerror(errno));

    /* ── Prometheus HTTP ─────────────────────────────────────────────── */
    int prom_fd = prometheus_init(prom_port);
    if (prom_fd < 0)
        fprintf(stderr, "warning: failed to start Prometheus on port %d: %s\n",
                prom_port, strerror(errno));
    else
        fprintf(stderr, "ndpid-simple: Prometheus metrics on :%d/metrics\n", prom_port);
    if (cli_fd >= 0)
        fprintf(stderr, "ndpid-simple: CLI socket at %s\n", sock_path);

    /* ── Packet buffer ───────────────────────────────────────────────── */
    uint8_t *buf = malloc(PKT_BUF_SIZE);
    if (!buf) {
        fprintf(stderr, "error: out of memory\n");
        return 1;
    }

    /* ── Main event loop ─────────────────────────────────────────────── */
    time_t last_age = time(NULL);

    struct pollfd pfds[3];
    int nfds = 0;

    pfds[nfds].fd     = pkt_fd;
    pfds[nfds].events = POLLIN;
    nfds++;
    if (cli_fd >= 0) {
        pfds[nfds].fd     = cli_fd;
        pfds[nfds].events = POLLIN;
        nfds++;
    }
    if (prom_fd >= 0) {
        pfds[nfds].fd     = prom_fd;
        pfds[nfds].events = POLLIN;
        nfds++;
    }

    while (g_running) {
        int ret = poll(pfds, nfds, 200 /* ms */);
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }

        /* ── Drain all pending packets ── */
        if (pfds[0].revents & POLLIN) {
            ssize_t n;
            /* Drain the socket in a tight loop while data is available */
            while ((n = recv(pkt_fd, buf, PKT_BUF_SIZE, MSG_DONTWAIT)) > 0) {

                /* Must have Ethernet header + IP header minimum */
                if (n < (ssize_t)(14 + 20))
                    continue;

                /* Only IPv4 */
                uint16_t ethertype = (uint16_t)((buf[12] << 8) | buf[13]);
                if (ethertype != ETH_P_IP)
                    continue;

                uint8_t *ip = buf + 14;
                int      ip_len = n - 14;

                if (ip[0] >> 4 != 4)        /* not IPv4 */
                    continue;
                uint8_t ihl = (ip[0] & 0xf) * 4;
                if (ihl < 20 || ip_len < (int)ihl)
                    continue;

                uint8_t proto = ip[9];
                if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
                    continue;

                /* Build flow event identical to what the BPF ring buffer sends */
                struct ndpi_obs_flow_event evt;
                memset(&evt, 0, sizeof(evt));

                memcpy(&evt.key.src_ip, ip + 12, 4);
                memcpy(&evt.key.dst_ip, ip + 16, 4);
                evt.key.proto = proto;

                if (proto == IPPROTO_TCP) {
                    if (ip_len < (int)ihl + 4) continue;
                    memcpy(&evt.key.src_port, ip + ihl,     2);
                    memcpy(&evt.key.dst_port, ip + ihl + 2, 2);
                } else {
                    if (ip_len < (int)ihl + 4) continue;
                    memcpy(&evt.key.src_port, ip + ihl,     2);
                    memcpy(&evt.key.dst_port, ip + ihl + 2, 2);
                }

                uint16_t ip_tot = (uint16_t)((ip[2] << 8) | ip[3]);
                evt.pkt_len  = ip_tot;

                uint32_t copy_len = (uint32_t)ip_len;
                if (copy_len > FLOW_EVENT_DATA_LEN)
                    copy_len = FLOW_EVENT_DATA_LEN;
                memcpy(evt.pkt_data, ip, copy_len);
                evt.data_len = copy_len;

                /* verdict_map_fd = -1: no BPF verdict writeback */
                ndpi_engine_process(&engine, &evt, -1);
            }
        }

        /* ── CLI requests ── */
        if (cli_fd >= 0) {
            for (int i = 0; i < nfds; i++) {
                if (pfds[i].fd == cli_fd && (pfds[i].revents & POLLIN))
                    /* app_cnt_fd = -1: no BPF per-app counters */
                    unix_socket_handle(cli_fd, &engine, -1);
            }
        }

        /* ── Prometheus scrapes ── */
        if (prom_fd >= 0) {
            for (int i = 0; i < nfds; i++) {
                if (pfds[i].fd == prom_fd && (pfds[i].revents & POLLIN))
                    prometheus_handle(prom_fd, &engine, -1);
            }
        }

        /* ── Age flows every 10 seconds ── */
        time_t now = time(NULL);
        if (now - last_age >= 10) {
            ndpi_engine_age(&engine);
            last_age = now;
        }
    }

    fprintf(stderr, "ndpid-simple: shutting down\n");

    free(buf);
    close(pkt_fd);
    ndpi_engine_destroy(&engine);
    if (cli_fd  >= 0) unix_socket_destroy(cli_fd, sock_path);
    if (prom_fd >= 0) prometheus_destroy(prom_fd);

    return 0;
}
