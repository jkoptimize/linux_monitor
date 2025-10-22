// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <signal.h>
#include <unistd.h>
#include "net_monitor.h"
#include "net_monitor.skel.h"

static volatile sig_atomic_t exiting = 0;
static struct net_monitor_bpf *skel;
static int packetsInfo_fd = 0;
static bool hook_created = false;
static struct bpf_tc_hook tc_hook_in, tc_hook_out;
static struct bpf_tc_opts tc_opts_in, tc_opts_out;

static void sig_int(int signo)
{
	tc_opts_in.flags = tc_opts_in.prog_fd = tc_opts_in.prog_id = 0;
    tc_opts_out.flags = tc_opts_out.prog_fd = tc_opts_out.prog_id = 0;
	bpf_tc_detach(&tc_hook_in, &tc_opts_in);
	bpf_tc_detach(&tc_hook_out, &tc_opts_out);

	if (hook_created) {
		bpf_tc_hook_destroy(&tc_hook_in);
		bpf_tc_hook_destroy(&tc_hook_out);
	}
	net_monitor_bpf__destroy(skel);
}

int init_net_monitor()
{
	int err;

	tc_hook_in.ifindex = ETH0_IFINDEX;
	tc_hook_in.attach_point = BPF_TC_INGRESS;
	tc_hook_in.sz = sizeof(struct bpf_tc_hook);
	tc_opts_in.handle = 1;
	tc_opts_in.priority = 1;
	tc_opts_in.sz = sizeof(struct bpf_tc_opts);

	tc_hook_out.ifindex = ETH0_IFINDEX;
	tc_hook_out.attach_point = BPF_TC_EGRESS;
	tc_hook_out.sz = sizeof(struct bpf_tc_hook);
	tc_opts_out.handle = 1;
	tc_opts_out.priority = 1;
	tc_opts_out.sz = sizeof(struct bpf_tc_opts);

    printf("Attaching to ifindex: %d\n", if_nametoindex("eth0"));
    // 1. Open and load BPF application
	skel = net_monitor_bpf__open_and_load();
	if (!skel) {
		printf("Failed to open BPF skeleton\n");
		return 1;
	}

    // 2. Create TC hooks
	err = bpf_tc_hook_create(&tc_hook_in);
	if (!err)
		hook_created = true;
	if (err && err != -EEXIST) {
		printf("Failed to create TC hook: %d\n", err);
		goto cleanup;
	}

	err = bpf_tc_hook_create(&tc_hook_out);
	if (!err)
		hook_created = true;
	if (err && err != -EEXIST) {
		printf("Failed to create TC hook: %d\n", err);
		goto cleanup;
	}

    // 3. Attach BPF program to the hooks
	tc_opts_in.prog_fd = bpf_program__fd(skel->progs.tc_ingress);
	err = bpf_tc_attach(&tc_hook_in, &tc_opts_in);
	if (err) {
		printf("Failed to attach TC: %d\n", err);
		goto cleanup;
	}
	tc_opts_out.prog_fd = bpf_program__fd(skel->progs.tc_egress);
	err = bpf_tc_attach(&tc_hook_out, &tc_opts_out);
	if (err) {
		printf("Failed to attach TC: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		err = errno;
		printf("Can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	return 0;

cleanup:
	if (hook_created) {
		bpf_tc_hook_destroy(&tc_hook_in);
		bpf_tc_hook_destroy(&tc_hook_out);
	}
	net_monitor_bpf__destroy(skel);
	return -err;
}


int net_monitor_get_packetsinfo_fd()
{
    packetsInfo_fd = bpf_map__fd(skel->maps.packetsInfo);
    return packetsInfo_fd;
}

__attribute__((destructor)) void my_destructor(void) {
    sig_int(0);
}

int main()
{
    init_net_monitor();

    while(1){};

    return 0;
}
