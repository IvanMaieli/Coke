#ifndef COCA_TYPES_H
#define COCA_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <netinet/in.h>

/* ── Protocol Enum ─────────────────────────────────────────────── */
typedef enum {
    PROTO_UNKNOWN = 0,
    PROTO_TCP,
    PROTO_UDP,
    PROTO_ICMP,
    PROTO_ARP,
    PROTO_OTHER
} coca_proto_t;

/* ── Single captured packet ────────────────────────────────────── */
#define COCA_MAX_RAW   2048   /* bytes stored per packet          */
#define COCA_INFO_LEN   128   /* decoded one-liner info           */

typedef struct {
    uint32_t       id;                        /* monotonic index  */
    struct timespec ts;                       /* capture time     */
    coca_proto_t   proto;                     /* protocol enum    */
    char           src_ip[INET_ADDRSTRLEN];   /* source IP        */
    char           dst_ip[INET_ADDRSTRLEN];   /* destination IP   */
    uint16_t       src_port;                  /* 0 if N/A         */
    uint16_t       dst_port;
    uint8_t        ttl;
    uint16_t       raw_len;                   /* actual bytes     */
    uint8_t        raw[COCA_MAX_RAW];         /* raw frame        */
    char           info[COCA_INFO_LEN];       /* e.g. "SYN ACK"  */
} coca_packet_t;

/* ── Runtime configuration ─────────────────────────────────────── */
typedef struct {
    char          *interface;      /* NULL = all interfaces       */
    char          *output_file;    /* PCAP filename               */
    char          *filter_proto;   /* initial protocol filter     */
    bool           verbose;
    bool           hex_view;
    int            store_capacity; /* ring buffer size             */
} coca_config_t;

/* ── Filter criteria ───────────────────────────────────────────── */
typedef struct {
    coca_proto_t  proto;                       /* PROTO_UNKNOWN = all */
    char          ip_substr[INET_ADDRSTRLEN];  /* "" = no IP filter   */
} coca_filter_t;

#endif /* COCA_TYPES_H */
