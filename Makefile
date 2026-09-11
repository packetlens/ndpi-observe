# SPDX-License-Identifier: Apache-2.0

CC      = gcc
CLANG   = clang
# bpftool resolution.
#
# linux-tools-generic installs bpftool at a kernel-versioned path and ships a
# wrapper that looks up the *running* kernel.  Inside a container the running
# kernel is the host's, which never matches the installed package, so the
# wrapper fails with "bpftool not found for kernel ...".  Ubuntu has no
# standalone bpftool package to fall back on.
#
# Probe each candidate by actually running it, and take the first that works.
BPFTOOL ?= $(shell for c in bpftool \
                             /usr/lib/linux-tools/*/bpftool \
                             /usr/lib/linux-tools-*/bpftool \
                             /usr/sbin/bpftool; do \
                     "$$c" version >/dev/null 2>&1 && { echo "$$c"; break; }; \
                   done)

BPF_SRC  = bpf/ndpi_observe.bpf.c
BPF_OBJ  = bpf/ndpi_observe.bpf.o
BPF_SKEL = bpf/ndpi_observe.skel.h

ML_SRCS           = daemon/ndpi_ml.c daemon/ndpi_ml_model.c
DAEMON_SRCS       = daemon/main.c daemon/flow_table.c daemon/ndpi_engine.c \
                    daemon/unix_socket.c daemon/prometheus.c $(ML_SRCS)
SIMPLE_SRCS       = daemon/main_noebpf.c daemon/flow_table.c daemon/ndpi_engine.c \
                    daemon/unix_socket.c daemon/prometheus.c $(ML_SRCS)
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
	@test -n "$(BPFTOOL)" || { echo "ERROR: no working bpftool found. Install linux-tools-generic or build bpftool from libbpf."; exit 1; }
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
