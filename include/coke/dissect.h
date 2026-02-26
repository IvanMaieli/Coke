#ifndef COKE_DISSECT_H
#define COKE_DISSECT_H

#include "types.h"

/* Dissect a raw Ethernet frame into a coke_packet_t.
   raw     – pointer to the captured frame
   raw_len – number of bytes captured
   out     – output struct to populate
   Returns 0 on success, -1 if the frame is too small / malformed. */
int dissect_packet(const uint8_t *raw, int raw_len, coke_packet_t *out);

/* Return a short human-readable label for a protocol enum */
const char *proto_label(coke_proto_t p);

#endif /* COKE_DISSECT_H */
