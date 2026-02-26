/* ── stats.c — Atomic traffic counters ───────────────────────── */
#include "coke/stats.h"

coke_stats_t g_stats;

void stats_reset(void) {
  atomic_store(&g_stats.total, 0);
  atomic_store(&g_stats.tcp, 0);
  atomic_store(&g_stats.udp, 0);
  atomic_store(&g_stats.icmp, 0);
  atomic_store(&g_stats.arp, 0);
  atomic_store(&g_stats.other, 0);
}

void stats_record(coke_proto_t proto) {
  atomic_fetch_add(&g_stats.total, 1);
  switch (proto) {
  case PROTO_TCP:
    atomic_fetch_add(&g_stats.tcp, 1);
    break;
  case PROTO_UDP:
    atomic_fetch_add(&g_stats.udp, 1);
    break;
  case PROTO_ICMP:
    atomic_fetch_add(&g_stats.icmp, 1);
    break;
  case PROTO_ARP:
    atomic_fetch_add(&g_stats.arp, 1);
    break;
  default:
    atomic_fetch_add(&g_stats.other, 1);
    break;
  }
}
