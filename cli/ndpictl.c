/* SPDX-License-Identifier: Apache-2.0
 * ndpictl — CLI client for ndpid
 * Usage: ndpictl [show version | show stats | show applications [top N] | show flows [count N]]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>

#define CLI_SOCK_PATH "/run/ndpid/cli.sock"
#define SOCK_ENV      "NDPID_SOCKET"

int main(int argc, char **argv)
{
    const char *sock_path = getenv(SOCK_ENV);
    if (!sock_path)
        sock_path = CLI_SOCK_PATH;

    if (argc < 2) {
        fprintf(stderr,
            "Usage: ndpictl <command>\n"
            "Commands:\n"
            "  show version\n"
            "  show stats\n"
            "  show applications [top N]\n"
            "  show flows [count N]\n");
        return 1;
    }

    /* Build command string from argv[1..] */
    char cmd[256] = {};
    for (int i = 1; i < argc; i++) {
        if (i > 1) strncat(cmd, " ", sizeof(cmd) - strlen(cmd) - 1);
        strncat(cmd, argv[i], sizeof(cmd) - strlen(cmd) - 1);
    }
    strncat(cmd, "\n", sizeof(cmd) - strlen(cmd) - 1);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_un addr = {};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "ndpictl: cannot connect to %s: %s\n"
                        "Is ndpid running? Try: sudo ndpid -i <interface>\n",
                sock_path, strerror(errno));
        close(fd);
        return 1;
    }

    /* Send command */
    if (write(fd, cmd, strlen(cmd)) < 0) {
        perror("write");
        close(fd);
        return 1;
    }

    /* Shut down write side so server knows we're done sending */
    shutdown(fd, SHUT_WR);

    /* Read and print response */
    char buf[4096];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0)
        fwrite(buf, 1, n, stdout);

    close(fd);
    return 0;
}
