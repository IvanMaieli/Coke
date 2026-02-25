#ifndef COCA_PACKET_STORE_H
#define COCA_PACKET_STORE_H

#include "types.h"

/* Initialise the ring buffer with the given capacity */
void store_init(int capacity);

/* Push a packet (thread-safe, overwrites oldest) */
void store_push(const coca_packet_t *pkt);

/* Get a packet by index (0 = oldest available).
   Returns a pointer to an internal copy — valid until next push.
   Returns NULL if idx is out of range. */
const coca_packet_t *store_get(int idx);

/* Number of packets currently stored */
int store_count(void);

/* Total packets ever captured (monotonic) */
uint32_t store_total(void);

/* Clear all stored packets */
void store_clear(void);

/* Free resources */
void store_destroy(void);

#endif /* COCA_PACKET_STORE_H */
