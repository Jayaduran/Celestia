// ebpf/xdp_filter.c
// -----------------------------------------------------------------------------
// ULPF Zero-Copy XDP Network Filter
// -----------------------------------------------------------------------------
// This eBPF program hooks directly into the Linux NIC driver.
// It parses the Ethernet -> IP -> UDP layers and inspects the raw payload.
// If the payload does not start with a valid Syslog '<' or 'CEF:' header,
// it instantly drops the packet, saving 100% of the host OS CPU.
// -----------------------------------------------------------------------------

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

#define UDP_SYSLOG_PORT 5140

// BPF Map for counting metrics (Passed vs Dropped)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} xdp_stats_map SEC(".maps");

static inline void record_metric(__u32 index) {
    __u64 *val = bpf_map_lookup_elem(&xdp_stats_map, &index);
    if (val) {
        *val += 1;
    }
}

SEC("xdp")
int xdp_drop_noise(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    // 1. Ethernet Header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // 2. IP Header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    // 3. UDP Header
    struct udphdr *udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    // 4. Port Filtering
    if (udp->dest == bpf_htons(UDP_SYSLOG_PORT)) {
        
        // 5. Payload Inspection (Deep Packet Inspection inside the NIC)
        char *payload = (char *)(udp + 1);
        
        // Ensure we have at least 4 bytes of payload to inspect safely
        if ((void *)(payload + 4) > data_end) {
            record_metric(1); // Dropped index
            return XDP_DROP; // Packet too small
        }
        
        // Validate Payload Signature
        // Syslog usually starts with '<' (e.g. <34>)
        // CEF starts with 'CEF:'
        
        if (payload[0] == '<') {
            record_metric(0); // Passed index
            return XDP_PASS;
        }
        
        if (payload[0] == 'C' && payload[1] == 'E' && payload[2] == 'F' && payload[3] == ':') {
            record_metric(0); // Passed index
            return XDP_PASS;
        }

        // It doesn't look like a valid log event. Drop it instantly.
        // This stops UDP Floods and random noise from reaching the Go/Python listener.
        record_metric(1); // Dropped index
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
