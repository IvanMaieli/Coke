#include <stdio.h>
#include <stdint.h>
#include "../include/coke.h"

// Struttura standard PCAP File Header
struct pcap_hdr {
    uint32_t magic_number;   /* 0xa1b2c3d4 */
    uint16_t version_major;  /* 2 */
    uint16_t version_minor;  /* 4 */
    int32_t  thiszone;       /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets */
    uint32_t network;        /* data link type (1 = Ethernet) */
};

FILE* pcap_init(const char* filename) {
    FILE* f = fopen(filename, "wb");
    if (!f) return NULL;

    struct pcap_hdr header = {
        .magic_number = 0xa1b2c3d4,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = 65535,
        .network = 1 // LINKTYPE_ETHERNET
    };

    fwrite(&header, sizeof(header), 1, f);
    fflush(f);
    return f;
}





