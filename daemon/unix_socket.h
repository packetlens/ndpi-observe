/* SPDX-License-Identifier: Apache-2.0 */
#ifndef UNIX_SOCKET_H
#define UNIX_SOCKET_H

#include "ndpi_engine.h"

#define CLI_SOCK_PATH "/run/ndpid/cli.sock"

int  unix_socket_init(const char *path);
void unix_socket_handle(int server_fd, ndpi_engine_t *e, int app_cnt_fd);
void unix_socket_destroy(int server_fd);

#endif /* UNIX_SOCKET_H */
