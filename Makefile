# SPDX-License-Identifier: Apache-2.0

CC      = gcc
CLANG   = clang
BPFTOOL = bpftool

BPF_SRC  = bpf/ndpi_observe.bpf.c
BPF_OBJ  = bpf/ndpi_observe.bpf.o
BPF_SKEL = bpf/ndpi_observe.skel.h

DAEMON_SRCS       = daemon/main.c daemon/flow_table.c daemon/ndpi_engine.c \
                    daemon/unix_socket.c daemon/prometheus.c
SIMPLE_SRCS       = daemon/main_noebpf.c daemon/flow_table.c daemon/ndpi_engine.c \
                    daemon/unix_socket.c daemon/prometheus.c
CLI_SRCS          = cli/ndpictl.c

CFLAGS            = -O2 -Wall -Wextra -g -I. -Idaemon -Ibpf
LDFLAGS           = -lbpf -lndpi -lm -lpthread
LDFLAGS_SIMPLE    = -lbpf -lndpi -lm -lpthread

PREFIX  ?= /usr/local
SBINDIR ?= $(PREFIX)/sbin
BINDIR  ?= $(PREFIX)/bin

.PHONY: all clean install

all: ndpid ndpid-simple ndpictl

# Step 1: Compile eBPF program
$(BPF_OBJ): $(BPF_SRC) bpf/ndpi_obs_types.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86 \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-I. -c $< -o $@

# Step 2: Generate libbpf skeleton
$(BPF_SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

# Step 3: Build daemon (depends on skeleton)
ndpid: $(BPF_SKEL) $(DAEMON_SRCS)
	$(CC) $(CFLAGS) $(DAEMON_SRCS) -o $@ $(LDFLAGS)

# Step 4: Build AF_PACKET daemon (no eBPF dependency)
ndpid-simple: $(SIMPLE_SRCS)
	$(CC) $(CFLAGS) $(SIMPLE_SRCS) -o $@ $(LDFLAGS_SIMPLE)

# Step 5: Build CLI
ndpictl: $(CLI_SRCS)
	$(CC) $(CFLAGS) $< -o $@

install: ndpid ndpid-simple ndpictl
	install -d $(DESTDIR)$(SBINDIR) $(DESTDIR)$(BINDIR)
	install -m 755 ndpid        $(DESTDIR)$(SBINDIR)/ndpid
	install -m 755 ndpid-simple $(DESTDIR)$(SBINDIR)/ndpid-simple
	install -m 755 ndpictl      $(DESTDIR)$(BINDIR)/ndpictl

clean:
	rm -f $(BPF_OBJ) $(BPF_SKEL) ndpid ndpid-simple ndpictl
