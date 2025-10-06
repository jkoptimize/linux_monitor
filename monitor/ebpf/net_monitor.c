// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <signal.h>
#include <unistd.h>
#include "net_monitor.h"
#include "net_monitor.skel.h"

static volatile sig_atomic_t exiting = 0;

static void sig_int(int signo)
{
	exiting = 1;
}

int main(int argc, char **argv)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook_in, .ifindex = ETH0_IFINDEX,
			    .attach_point = BPF_TC_INGRESS);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts_in, .handle = 1, .priority = 1);
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook_out, .ifindex = ETH0_IFINDEX,
			    .attach_point = BPF_TC_EGRESS);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts_out, .handle = 1, .priority = 1);

	bool hook_created = false;
	struct net_monitor_bpf *skel;
	int err;

    // printf("Attaching to ifindex: %d\n", if_nametoindex("eth0"));
    // 1. Open and load BPF application
	skel = net_monitor_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

    // 2. Create TC hooks
	err = bpf_tc_hook_create(&tc_hook_in);
	if (!err)
		hook_created = true;
	if (err && err != -EEXIST) {
		fprintf(stderr, "Failed to create TC hook: %d\n", err);
		goto cleanup;
	}
	err = bpf_tc_hook_create(&tc_hook_out);
	if (!err)
		hook_created = true;
	if (err && err != -EEXIST) {
		fprintf(stderr, "Failed to create TC hook: %d\n", err);
		goto cleanup;
	}

    // 3. Attach BPF program to the hooks
	tc_opts_in.prog_fd = bpf_program__fd(skel->progs.tc_ingress);
	err = bpf_tc_attach(&tc_hook_in, &tc_opts_in);
	if (err) {
		fprintf(stderr, "Failed to attach TC: %d\n", err);
		goto cleanup;
	}
	tc_opts_out.prog_fd = bpf_program__fd(skel->progs.tc_egress);
	err = bpf_tc_attach(&tc_hook_out, &tc_opts_out);
	if (err) {
		fprintf(stderr, "Failed to attach TC: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		err = errno;
		fprintf(stderr, "Can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF program.\n");

	while (!exiting) {
		fprintf(stderr, ".");
		sleep(1);
	}

	tc_opts_in.flags = tc_opts_in.prog_fd = tc_opts_in.prog_id = 0;
    tc_opts_out.flags = tc_opts_out.prog_fd = tc_opts_out.prog_id = 0;
	err = bpf_tc_detach(&tc_hook_in, &tc_opts_in);
	if (err) {
		fprintf(stderr, "Failed to detach TC: %d\n", err);
		goto cleanup;
	}
	err = bpf_tc_detach(&tc_hook_out, &tc_opts_out);
	if (err) {
		fprintf(stderr, "Failed to detach TC: %d\n", err);
		goto cleanup;
	}

cleanup:
	if (hook_created) {
		bpf_tc_hook_destroy(&tc_hook_in);
		bpf_tc_hook_destroy(&tc_hook_out);
	}
	net_monitor_bpf__destroy(skel);
	return -err;
}
