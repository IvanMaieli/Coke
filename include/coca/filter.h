#ifndef COCA_FILTER_H
#define COCA_FILTER_H

#include "types.h"

/* Initialise the global filter to "accept everything" */
void filter_init(void);

/* Set the filter from a user string like "tcp", "udp", "icmp", "arp",
   an IP substring, or "all" / "" to clear. */
void filter_set(const char *expr);

/* Returns true if the packet passes the active filter */
bool filter_matches(const coca_packet_t *pkt);

/* Set the filter to show only the bidirectional conversation of the given
 * packet */
void filter_set_conversation(const coca_packet_t *pkt);

/* Get a human-readable description of the current filter */
const char *filter_describe(void);

#endif /* COCA_FILTER_H */
