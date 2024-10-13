// SPDX-License-Identifier: GPL-2.0
// clang-format off
#include <vmlinux.h>
// clang-format on
#include <bpf_endian.h>
#include <bpf_helpers.h>

#include "../common/packet.h"

// Constants for TC hook
#define TC_ACT_UNSPEC (-1)
#define TC_ACT_OK 0
#define TC_ACT_RECLASSIFY 1
#define TC_ACT_SHOT 2
#define TC_ACT_PIPE 3
#define TC_ACT_STOLEN 4
#define TC_ACT_QUEUED 5
#define TC_ACT_REPEAT 6
#define TC_ACT_REDIRECT 7

#define ETH_ALEN \
	6 // not in vmlinux, asmtypes.h problem when importing linux \
		// headers

// keep track of position during parsing
struct hdr_cursor {
	void *pos;
};

struct {
	__uint(type, BPF_MAP_TYPE_CPUMAP);
	__type(key, __u32);
	__uint(value_size, sizeof(struct bpf_cpumap_val));
} cpu_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
} cpus_available SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} cpus_count SEC(".maps");

/* useful for iterating between CPUs */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} cpu_iter SEC(".maps");

/* port number that the benchmark listens on */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u16);
	__uint(max_entries, 1);
} port_num SEC(".maps");

/* will contain ifindex of interface packets arrived on */
struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__type(key, __u32);
	__type(value, struct bpf_devmap_val);
	__uint(max_entries, 1);
} devmap SEC(".maps");

/* counts packets per-cpu */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1); // number of packets sent per CPU
} tx_packet_ctr SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1); // number of packets received by all CPU
} rx_packet_ctr SEC(".maps");

/**
 * Maintains total service time from NIC interrupt to leaving server. Updated
 * on a per-cpu basis by the CPU that performs the redirect back out
 *
 * Intended to be used for computing average.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1);
} total_srv_time SEC(".maps");

/**
 * @brief empty function for bpf_loop call
 */
static __always_inline long _empty_loop_func(u32 idx, void *ctx)
{
	return 0;
}

// recomputes an ipv4 checksum. https://en.wikipedia.org/wiki/Internet_checksum
static void __always_inline recompute_iphdr_csum(struct iphdr *iphdr)
{
	iphdr->check = 0;

	u16 *short_words = (u16 *)iphdr;
	u32 csum = 0;

#pragma unroll
	for (int i = 0; i < 10; i++)
		csum += short_words[i];

	csum = (csum & 0xFFFF) + (csum >> 16);
	csum = (csum & 0xFFFF) + (csum >> 16);
	iphdr->check = (u16)(~csum);
}

/**
 * @brief parses all packet headers up to the `struct packet` defined for the
 * synthetic benchmark, and swaps direction for redirection back to sender.
 * Assumes `ethhdr | iphdr | udphdr | struct packet`
 *
 * @return 0 on success, -1 on failure
 */
static __always_inline int
bpfnic_benchmark_parse_and_swap(struct xdp_md *ctx, struct hdr_cursor *nh)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *ethhdr;
	struct iphdr *iphdr;
	struct udphdr *udphdr;

	int _failure = -1;
	int _success = 0;

	ethhdr = (struct ethhdr *)data;
	if (ethhdr + 1 > data_end)
		return _failure;

	iphdr = (struct iphdr *)(ethhdr + 1);
	if (iphdr + 1 > data_end)
		return _failure;

	if (iphdr->protocol != IPPROTO_UDP)
		return _failure;

	udphdr = (struct udphdr *)(iphdr + 1);
	if (udphdr + 1 > data_end)
		return _failure;

	// Once we have validated the headers, we can swap header dests and srcs.
	// We have to perform null-checks again because the eBPF verifier is needy.
	if (ethhdr + 1 > data_end)
		return _failure;

	// swap MACs
	__u8 h_tmp[ETH_ALEN];
	__builtin_memcpy(h_tmp, ethhdr->h_source, ETH_ALEN);
	__builtin_memcpy(ethhdr->h_source, ethhdr->h_dest, ETH_ALEN);
	__builtin_memcpy(ethhdr->h_dest, h_tmp, ETH_ALEN);

	if (iphdr + 1 > data_end)
		return _failure;
	// swap IPs
	__be32 ip_tmp = iphdr->saddr;
	iphdr->saddr = iphdr->daddr;
	iphdr->daddr = ip_tmp;
	recompute_iphdr_csum(iphdr);
	// ffkx_compute_ip_checksum(iphdr);

	if (udphdr + 1 > data_end)
		return _failure;
	// swap dest and source ports
	__be16 udp_tmp = udphdr->source;
	udphdr->source = udphdr->dest;
	udphdr->dest = udp_tmp;
	udphdr->check = 0;

	nh->pos = (void *)(udphdr + 1);
	return _success;
}

SEC("xdp")
int bpfnic_xdp(struct xdp_md *ctx)
{
	return XDP_PASS;
}

/**
 * BPF program run on a receiving CPU
 */
SEC("xdp/cpumap")
int bpfnic_benchmark_cpu_func(struct xdp_md *ctx)
{
	__u64 *tx_packets;
	__u64 *curr_total_queue_delay;
	__u32 key0 = 0;
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct hdr_cursor nh = { .pos = data };

	if (bpfnic_benchmark_parse_and_swap(ctx, &nh) < 0)
		return XDP_PASS;

	struct packet *packet = (struct packet *)(nh.pos);
	if (packet + 1 > data_end)
		return XDP_PASS;

	packet->leave_server_timestamp = bpf_ktime_get_ns();

	curr_total_queue_delay = bpf_map_lookup_elem(&total_srv_time, &key0);
	if (curr_total_queue_delay) {
		*curr_total_queue_delay += packet->leave_server_timestamp -
					   packet->reach_server_timestamp;
	}

	// loop for 10 times the data portion of the packet
	bpf_loop(((int)packet->data) * 10, _empty_loop_func, NULL, 0);

	tx_packets = bpf_map_lookup_elem(&tx_packet_ctr, &key0);
	if (tx_packets) {
		*tx_packets += 1;
	}

	// debug bpf_redirect_map
	long ret = bpf_redirect_map(&devmap, key0, 0);
	if (ret != XDP_REDIRECT)
		bpf_printk("bpf_redirect_map (devmap) failure: ret code = %d",
			   ret);
	return ret;
}

/**
 * Parses and timestamps packet with arrival time. Sets header cursor to the
 * beginning of the embedded `struct packet`
 *
 * @return `true` iff packet was going to/leaving benchmark program by reading
 * UDP port numbers
 */
static __always_inline int
bpfnic_benchmark_parse_and_timestamp_packet(struct xdp_md *ctx,
					    struct hdr_cursor *nh)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *ethhdr;
	struct iphdr *iphdr;
	struct udphdr *udphdr;
	struct packet *packet;
	__u16 *port;
	__u32 key0 = 0;

	ethhdr = (struct ethhdr *)data;
	if (ethhdr + 1 > data_end)
		return false;

	iphdr = (struct iphdr *)(ethhdr + 1);
	if (iphdr + 1 > data_end)
		return false;

	if (iphdr->protocol != IPPROTO_UDP)
		return false;

	udphdr = (struct udphdr *)(iphdr + 1);
	if (udphdr + 1 > data_end)
		return false;

	port = bpf_map_lookup_elem(&port_num, &key0);
	if (!port)
		return false;

	// packet is either being received or sent from benchmark hook
	if (bpf_ntohs(udphdr->dest) != *port &&
	    bpf_ntohs(udphdr->dest) != *port)
		return false;

	packet = (struct packet *)(udphdr + 1);
	if (packet + 1 > data_end)
		return false;
	nh->pos = packet;

	packet->reach_server_timestamp = bpf_ktime_get_ns();
	return true;
}

SEC("xdp")
int bpf_redirect_roundrobin(struct xdp_md *ctx)
{
	__u32 *cpu_selected, *cpu_iterator, *cpu_count;
	struct packet *packet;
	__u64 *rx_ctr;
	__u32 cpu_dest = 0;
	__u32 key0 = 0;
	__u32 cpu_idx;

	// increment received packets atomically
	rx_ctr = bpf_map_lookup_elem(&rx_packet_ctr, &key0);
	if (rx_ctr)
		__sync_fetch_and_add(rx_ctr, 1);

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data;
	struct hdr_cursor nh = { .pos = data };

	if (!bpfnic_benchmark_parse_and_timestamp_packet(ctx, &nh)) {
		bpf_printk("Passing packet - not destined for benchmark");
		return XDP_PASS;
	}

	// TODO: make redirection decision
	cpu_iterator = bpf_map_lookup_elem(&cpu_iter, &key0);
	if (!cpu_iterator)
		return XDP_DROP;
	cpu_count = bpf_map_lookup_elem(&cpus_count, &key0);
	if (!cpu_count)
		return XDP_DROP;

	cpu_idx = *cpu_iterator;
	if (cpu_idx + 1 >= *cpu_count){
		*cpu_iterator = 0;
	} else {
		*cpu_iterator = cpu_idx + 1;
	}
	//*cpu_id = (cpu_idx + 1) % *max_cpu ;
		

	__u32 *cpu_avail = bpf_map_lookup_elem(&cpus_available, &cpu_idx);
	if (!cpu_avail)
		return XDP_DROP;
	if (*cpu_avail == 0){
		bpf_printk("cpu%d not available", cpu_idx);
		return XDP_ABORTED;
	}


	long ret = bpf_redirect_map(&cpu_map, cpu_idx, 0);
	if (ret != XDP_REDIRECT){
		bpf_printk("bpf_redirect_map (devmap) failure: ret code = %d", ret);
		return XDP_DROP;
	}
	return ret;

}

/* array of cpus available for processing long requests */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
} cpus_available_long_reqs SEC(".maps");

/* list of cpus available for processing short requests */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
} cpus_available_short_reqs SEC(".maps");

// 0: short request iterator
// 1: long request iterator
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 2);
} cpu_iter_core_separated SEC(".maps");

// 0: number of cpus dedicated for short requests
// 1: number of cpus dedicated for long requests
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 2);
} cpu_count_core_separated SEC(".maps");

SEC("xdp")
int bpf_redirect_roundrobin_core_separated(struct xdp_md *ctx)
{
	__u32 *cpu_selected, *cpu_iterator_short, *cpu_iterator_long;
	__u32 *cpu_count_long, *cpu_count_short;
	struct packet *packet;
	void *selected_map;
	__u32 cpu_dest = 0;
	__u32 key0 = 0;
	__u32 key1 = 1;
	__u32 cpu_idx;
	__u64 *rx_ctr;

	rx_ctr = bpf_map_lookup_elem(&rx_packet_ctr, &key0);
	if (rx_ctr)
		__sync_fetch_and_add(rx_ctr, 1);

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct hdr_cursor nh = { .pos = data };

	if (!bpfnic_benchmark_parse_and_timestamp_packet(ctx, &nh))
		return XDP_PASS;

	// TODO: make redirection decision
	int is_short = 1;
	packet  = nh.pos;
	if (packet +1 > data_end ){
		return XDP_DROP;
	}
	cpu_count_short = bpf_map_lookup_elem(&cpu_count_core_separated, &key0);
	if (!cpu_count_short)
		return XDP_DROP;
	cpu_count_long = bpf_map_lookup_elem(&cpu_count_core_separated, &key1);
	if (!cpu_count_long)
		return XDP_DROP;
	if(packet->data < 10){
		selected_map = &cpus_available_short_reqs;
		cpu_iterator_short = bpf_map_lookup_elem(&cpu_iter_core_separated, &key0);
		if (!cpu_iterator_short)
			return XDP_DROP;

		cpu_idx = *cpu_iterator_short;
		if (cpu_idx + 1 >= *cpu_count_short){
			*cpu_iterator_short = 0;
		} else {
			*cpu_iterator_short = cpu_idx + 1;
		}
		bpf_printk("received short packet (data=%d), scheduled to run at cpu: %d", packet->data, cpu_idx);
	} else {
		is_short = 0;
		selected_map = &cpus_available_long_reqs;
		cpu_iterator_long = bpf_map_lookup_elem(&cpu_iter_core_separated, &key1);
		if (!cpu_iterator_long)
			return XDP_DROP;

		cpu_idx = *cpu_iterator_long;
		if (cpu_idx + 1 >= *cpu_count_long){
			*cpu_iterator_long = 0;
		} else {
			*cpu_iterator_long = cpu_idx + 1;
		}
		//cpu_idx += *cpu_count_short; //offset 
		bpf_printk("received long packet (data=%d), scheduled to run at cpu: %d", packet->data, cpu_idx);
	}

	__u32 *cpu_avail = bpf_map_lookup_elem(selected_map, &cpu_idx);
	if (!cpu_avail)
		return XDP_DROP;
	if (*cpu_avail == 0){
		bpf_printk("cpu%d not available, intended task is short?: %d", cpu_idx, is_short);
		return XDP_ABORTED;
	}

	if(is_short == 0){
		cpu_idx += *cpu_count_short;
	}
	long ret = bpf_redirect_map(&cpu_map, cpu_idx, 0);
	if (ret != XDP_REDIRECT){
		bpf_printk("bpf_redirect_map (devmap) failure: ret code = %d", ret);
		return XDP_DROP;
	}
	return ret;
	
}

SEC("tc")
int bpfnic_tc(struct __sk_buff *ctx)
{
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
