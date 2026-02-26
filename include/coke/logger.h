#ifndef COKE_LOGGER_H
#define COKE_LOGGER_H

#include "types.h"
#include <stdio.h>

/* Open a PCAP file for writing. Returns FILE* or NULL. */
FILE *logger_open(const char *filename);

/* Write a single packet record to the PCAP file */
void logger_write_packet(FILE *f, const coke_packet_t *pkt);

/* Flush and close the PCAP file */
void logger_close(FILE *f);

#endif /* COKE_LOGGER_H */
