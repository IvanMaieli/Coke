#ifndef LOGGER_H
#define LOGGER_H

#include <stdlib.h>
#include <stdint.h>

 // PCAP format header (Global Header)
 struct pcap_hdr {
     uint32_t magic_number;   /* magic number */
     uint16_t version_major;  /* major version number */
     uint16_t version_minor;  /* minor version number */
     int32_t  thiszone;       /* GMT to local correction */
     uint32_t sigfigs;        /* accuracy of timestamps */
     uint32_t snaplen;        /* max length of captured packets, in octets */
     uint32_t network;        /* data link type */
 };

FILE* pcap_init(const char* filename);

#endif
