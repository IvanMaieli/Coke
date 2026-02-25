#ifndef COCA_STATS_H
#define COCA_STATS_H

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
} coca_stats_t;

extern coca_stats_t g_stats;

void stats_reset(void);
void stats_record(coca_proto_t proto);

#endif /* COCA_STATS_H */
