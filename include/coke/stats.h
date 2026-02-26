#ifndef COKE_STATS_H
#define COKE_STATS_H

#include "types.h"
#include <stdatomic.h>

/* Live statistics counters */
typedef struct {
  atomic_uint total;
  atomic_uint tcp;
  atomic_uint udp;
  atomic_uint icmp;
  atomic_uint arp;
  atomic_uint other;
} coke_stats_t;

extern coke_stats_t g_stats;

void stats_reset(void);
void stats_record(coke_proto_t proto);

#endif /* COKE_STATS_H */
