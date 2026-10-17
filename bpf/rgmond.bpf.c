// SPDX-License-Identifier: GPL-2.0-only OR BSD-3-Clause
// rgmond's BPF programs. All of them attach to plain tracepoints and read
// fields at fixed offsets, so they need no BTF (some distribution kernels ship none).
// The loader (src/collect/bpf.rs) checks every offset used here against
// /sys/kernel/tracing/events/*/format before loading, and skips a program
// whose tracepoint layout differs.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Legacy map definitions ("maps" section): no BTF needed to create them.
struct legacy_map {
	unsigned int type, key_size, value_size, max_entries, map_flags;
};
#define MAP(name, t, k, v, n) \
	struct legacy_map name SEC("maps") = { t, sizeof(k), sizeof(v), n, 0 }

#define SLOTS 32
// Log2 histogram of microseconds, plus count and total nanoseconds.
struct hist {
	__u64 slots[SLOTS];
	__u64 count;
	__u64 sum_ns;
};

static __always_inline __u32 log2u(__u64 v)
{
	__u32 r = 0;
	if (v >> 32) { v >>= 32; r += 32; }
	if (v >> 16) { v >>= 16; r += 16; }
	if (v >> 8) { v >>= 8; r += 8; }
	if (v >> 4) { v >>= 4; r += 4; }
	if (v >> 2) { v >>= 2; r += 2; }
	if (v >> 1) { r += 1; }
	return r;
}

static __always_inline void hist_add(struct hist *h, __u64 ns)
{
	__u32 slot = log2u(ns / 1000);
	if (slot >= SLOTS)
		slot = SLOTS - 1;
	__sync_fetch_and_add(&h->slots[slot], 1);
	__sync_fetch_and_add(&h->count, 1);
	__sync_fetch_and_add(&h->sum_ns, ns);
}

static __always_inline struct hist *hist_get(void *map, void *key)
{
	struct hist *h = bpf_map_lookup_elem(map, key);
	if (h)
		return h;
	struct hist zero = {};
	bpf_map_update_elem(map, key, &zero, BPF_NOEXIST);
	return bpf_map_lookup_elem(map, key);
}

// ---- block I/O latency: block_rq_issue -> block_rq_complete ---------------
// Both events: dev_t dev @8 (4), sector_t sector @16 (8).
struct tp_block_rq {
	__u64 common;
	__u32 dev;
	__u32 pad;
	__u64 sector;
};

struct rq_key {
	__u32 dev;
	__u32 pad;
	__u64 sector;
};

MAP(bio_start, BPF_MAP_TYPE_HASH, struct rq_key, __u64, 16384);
MAP(bio_hist, BPF_MAP_TYPE_HASH, __u32, struct hist, 128);

SEC("tracepoint/block/block_rq_issue")
int block_issue(struct tp_block_rq *ctx)
{
	struct rq_key k = { .dev = ctx->dev, .sector = ctx->sector };
	__u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&bio_start, &k, &ts, BPF_ANY);
	return 0;
}

SEC("tracepoint/block/block_rq_complete")
int block_complete(struct tp_block_rq *ctx)
{
	struct rq_key k = { .dev = ctx->dev, .sector = ctx->sector };
	__u64 *ts = bpf_map_lookup_elem(&bio_start, &k);
	if (!ts)
		return 0;
	__u64 delta = bpf_ktime_get_ns() - *ts;
	bpf_map_delete_elem(&bio_start, &k);
	__u32 dev = ctx->dev;
	struct hist *h = hist_get(&bio_hist, &dev);
	if (h)
		hist_add(h, delta);
	return 0;
}

// ---- TCP retransmits and received resets, per local port ------------------
// tcp_retransmit_skb: __u16 sport @28.  tcp_receive_reset: __u16 sport @16.
struct tp_tcp_retransmit_skb {
	__u64 common;
	__u64 skbaddr;
	__u64 skaddr;
	__s32 state;
	__u16 sport;
	__u16 dport;
};

struct tp_tcp_receive_reset {
	__u64 common;
	__u64 skaddr;
	__u16 sport;
	__u16 dport;
};

MAP(tcp_retx, BPF_MAP_TYPE_HASH, __u16, __u64, 4096);
MAP(tcp_rst, BPF_MAP_TYPE_HASH, __u16, __u64, 4096);

static __always_inline void count_port(void *map, __u16 port)
{
	__u64 *v = bpf_map_lookup_elem(map, &port);
	if (v) {
		__sync_fetch_and_add(v, 1);
		return;
	}
	__u64 one = 1;
	if (bpf_map_update_elem(map, &port, &one, BPF_NOEXIST)) {
		v = bpf_map_lookup_elem(map, &port);
		if (v)
			__sync_fetch_and_add(v, 1);
	}
}

SEC("tracepoint/tcp/tcp_retransmit_skb")
int tcp_retransmit(struct tp_tcp_retransmit_skb *ctx)
{
	count_port(&tcp_retx, ctx->sport);
	return 0;
}

SEC("tracepoint/tcp/tcp_receive_reset")
int tcp_reset(struct tp_tcp_receive_reset *ctx)
{
	count_port(&tcp_rst, ctx->sport);
	return 0;
}

// ---- run-queue latency: wakeup -> switched in ------------------------------
// sched_wakeup(_new): pid_t pid @24.  sched_switch: pid_t prev_pid @24,
// long prev_state @32, pid_t next_pid @56.
struct tp_sched_wakeup {
	__u64 common;
	char comm[16];
	__s32 pid;
};

struct tp_sched_switch {
	__u64 common;
	char prev_comm[16];
	__s32 prev_pid;
	__s32 prev_prio;
	__s64 prev_state;
	char next_comm[16];
	__s32 next_pid;
};

MAP(runq_start, BPF_MAP_TYPE_HASH, __u32, __u64, 32768);
MAP(runq_hist, BPF_MAP_TYPE_ARRAY, __u32, struct hist, 1);

static __always_inline void runq_enqueue(__u32 pid)
{
	if (!pid)
		return;
	__u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&runq_start, &pid, &ts, BPF_ANY);
}

SEC("tracepoint/sched/sched_wakeup")
int sched_wakeup(struct tp_sched_wakeup *ctx)
{
	runq_enqueue(ctx->pid);
	return 0;
}

SEC("tracepoint/sched/sched_wakeup_new")
int sched_wakeup_new(struct tp_sched_wakeup *ctx)
{
	runq_enqueue(ctx->pid);
	return 0;
}

SEC("tracepoint/sched/sched_switch")
int sched_switch(struct tp_sched_switch *ctx)
{
	// A task preempted while still runnable (TASK_RUNNING == 0) waits again.
	if (ctx->prev_state == 0)
		runq_enqueue(ctx->prev_pid);
	__u32 next = ctx->next_pid;
	__u64 *ts = bpf_map_lookup_elem(&runq_start, &next);
	if (!ts)
		return 0;
	__u64 delta = bpf_ktime_get_ns() - *ts;
	bpf_map_delete_elem(&runq_start, &next);
	__u32 zero = 0;
	struct hist *h = bpf_map_lookup_elem(&runq_hist, &zero);
	if (h)
		hist_add(h, delta);
	return 0;
}

// ---- softirq time per vector -----------------------------------------------
// softirq_entry/exit: unsigned int vec @8.
struct tp_softirq {
	__u64 common;
	__u32 vec;
};

MAP(sirq_start, BPF_MAP_TYPE_PERCPU_ARRAY, __u32, __u64, 1);
MAP(sirq_time, BPF_MAP_TYPE_PERCPU_ARRAY, __u32, __u64, 16);

SEC("tracepoint/irq/softirq_entry")
int softirq_entry(struct tp_softirq *ctx)
{
	__u32 zero = 0;
	__u64 *s = bpf_map_lookup_elem(&sirq_start, &zero);
	if (s)
		*s = bpf_ktime_get_ns();
	return 0;
}

SEC("tracepoint/irq/softirq_exit")
int softirq_exit(struct tp_softirq *ctx)
{
	__u32 zero = 0, vec = ctx->vec;
	__u64 *s = bpf_map_lookup_elem(&sirq_start, &zero);
	if (!s || !*s)
		return 0;
	__u64 delta = bpf_ktime_get_ns() - *s;
	*s = 0;
	__u64 *t = bpf_map_lookup_elem(&sirq_time, &vec);
	if (t)
		*t += delta;
	return 0;
}

// ---- direct reclaim stalls ---------------------------------------------------
MAP(reclaim_start, BPF_MAP_TYPE_HASH, __u32, __u64, 16384);
MAP(reclaim_total, BPF_MAP_TYPE_ARRAY, __u32, struct hist, 1);

SEC("tracepoint/vmscan/mm_vmscan_direct_reclaim_begin")
int reclaim_begin(void *ctx)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	__u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&reclaim_start, &tid, &ts, BPF_ANY);
	return 0;
}

SEC("tracepoint/vmscan/mm_vmscan_direct_reclaim_end")
int reclaim_end(void *ctx)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	__u64 *ts = bpf_map_lookup_elem(&reclaim_start, &tid);
	if (!ts)
		return 0;
	__u64 delta = bpf_ktime_get_ns() - *ts;
	bpf_map_delete_elem(&reclaim_start, &tid);
	__u32 zero = 0;
	struct hist *h = bpf_map_lookup_elem(&reclaim_total, &zero);
	if (h)
		hist_add(h, delta);
	return 0;
}
