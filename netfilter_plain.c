#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/skbuff.h>
#include <linux/ktime.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/moduleparam.h>

static int target_port = 5500;
module_param(target_port, int, 0444);

static char *proto = "udp";
module_param(proto, charp, 0444);

#define MODULE_TAG "NF_LAT"

static DEFINE_SPINLOCK(lat_lock);

static ktime_t t0_stamp;
static bool t0_valid = false;

static ktime_t last_t1;
static bool last_t1_valid = false;

static atomic64_t pkt_count = ATOMIC64_INIT(0);
static atomic64_t jitter_warn = ATOMIC64_INIT(0);
static atomic64_t lat_sum_us = ATOMIC64_INIT(0);
static atomic64_t jitter_sum = ATOMIC64_INIT(0);

static bool packet_matches(struct sk_buff *skb)
{
    struct iphdr *iph = ip_hdr(skb);
    if (!iph)
        return false;

    if (proto[0] == 'i') {
        struct icmphdr *icmph;
        if (iph->protocol != IPPROTO_ICMP)
            return false;
        if (!skb_transport_header_was_set(skb))
            return false;
        icmph = icmp_hdr(skb);
        if (!icmph)
            return false;
        return (icmph->type == ICMP_ECHO);
    }

    if (iph->protocol != IPPROTO_UDP)
        return false;
    if (!skb_transport_header_was_set(skb))
        return false;

    {
        struct udphdr *udph = udp_hdr(skb);
        if (!udph)
            return false;
        return (ntohs(udph->dest) == (u16)target_port);
    }
}

static unsigned int hook_pre_routing(
    void *priv,
    struct sk_buff *skb,
    const struct nf_hook_state *state)
{
    unsigned long flags;

    if (!packet_matches(skb))
        return NF_ACCEPT;

    spin_lock_irqsave(&lat_lock, flags);
    t0_stamp = ktime_get();
    t0_valid = true;
    spin_unlock_irqrestore(&lat_lock, flags);

    pr_debug("[%s] PRE_ROUTING T0=%lld ns\n",
             MODULE_TAG, ktime_to_ns(t0_stamp));

    return NF_ACCEPT;
}

static unsigned int hook_local_in(
    void *priv,
    struct sk_buff *skb,
    const struct nf_hook_state *state)
{
    ktime_t t1, local_t0;
    s64 kernel_lat_us = -1;
    s64 inter_pkt_us = -1;
    u64 count;
    bool has_t0;
    unsigned long flags;

    if (!packet_matches(skb))
        return NF_ACCEPT;

    t1 = ktime_get();

    spin_lock_irqsave(&lat_lock, flags);
    has_t0 = t0_valid;
    local_t0 = t0_stamp;
    t0_valid = false;
    spin_unlock_irqrestore(&lat_lock, flags);

    if (has_t0) {
        kernel_lat_us = ktime_to_us(ktime_sub(t1, local_t0));
        atomic64_add(kernel_lat_us, &lat_sum_us);
    }

    spin_lock_irqsave(&lat_lock, flags);
    if (last_t1_valid) {
        inter_pkt_us = ktime_to_us(ktime_sub(t1, last_t1));
        atomic64_add(inter_pkt_us, &jitter_sum);
        if (inter_pkt_us > 2000000) {
            atomic64_inc(&jitter_warn);
            pr_warn("[%s] ANOMALY: inter_pkt=%lld us\n",
                    MODULE_TAG, inter_pkt_us);
        }
    }
    last_t1 = t1;
    last_t1_valid = true;
    spin_unlock_irqrestore(&lat_lock, flags);

    count = atomic64_inc_return(&pkt_count);

    pr_info("[%s] #%llu | kernel_lat=%lld us | inter_pkt=%lld us | anomalies=%llu\n",
            MODULE_TAG,
            count,
            kernel_lat_us,
            inter_pkt_us,
            atomic64_read(&jitter_warn));

    return NF_ACCEPT;
}

static struct nf_hook_ops lat_hooks[] = {
    {
        .hook = hook_pre_routing,
        .pf = PF_INET,
        .hooknum = NF_INET_PRE_ROUTING,
        .priority = NF_IP_PRI_FIRST,
    },
    {
        .hook = hook_local_in,
        .pf = PF_INET,
        .hooknum = NF_INET_LOCAL_IN,
        .priority = NF_IP_PRI_LAST,
    },
};

static int __init lat_init(void)
{
    int ret;

    ret = nf_register_net_hooks(&init_net, lat_hooks, ARRAY_SIZE(lat_hooks));
    if (ret < 0) {
        pr_err("[%s] Failed to register hooks: %d\n", MODULE_TAG, ret);
        return ret;
    }

    pr_info("[%s] ========== Latency Monitor Loaded ==========\n", MODULE_TAG);
    if (proto[0] == 'i') {
        pr_info("[%s] Mode: ICMP Echo Request\n", MODULE_TAG);
        pr_info("[%s] Test cmd: ping <IP_rpi4> -i 0.2\n", MODULE_TAG);
    } else {
        pr_info("[%s] Mode: UDP port %d\n", MODULE_TAG, target_port);
        pr_info("[%s] Test cmd: iperf3 -u -c <IP_rpi4> -p %d -b 100k\n",
                MODULE_TAG, target_port);
    }
    pr_info("[%s] Watch: sudo dmesg -w | grep NF_LAT\n", MODULE_TAG);

    return 0;
}

static void __exit lat_exit(void)
{
    u64 n = atomic64_read(&pkt_count);
    s64 avg_lat = 0;
    s64 avg_ipkt = 0;

    if (n > 0)
        avg_lat = atomic64_read(&lat_sum_us) / (s64)n;
    if (n > 1)
        avg_ipkt = atomic64_read(&jitter_sum) / (s64)(n - 1);

    nf_unregister_net_hooks(&init_net, lat_hooks, ARRAY_SIZE(lat_hooks));

    pr_info("[%s] ========== Latency Monitor Unloaded ==========\n", MODULE_TAG);
    pr_info("[%s] SUMMARY: packets=%llu | avg_kernel_lat=%lld us | avg_inter_pkt=%lld us | anomalies=%llu\n",
            MODULE_TAG, n, avg_lat, avg_ipkt, atomic64_read(&jitter_warn));
}

module_init(lat_init);
module_exit(lat_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dinh Vo Gia Huy - MSSV 24520656");
MODULE_DESCRIPTION("Netfilter latency monitor — plain UDP/ICMP");
MODULE_VERSION("2.0");

