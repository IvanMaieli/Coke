#ifndef COKE_TYPES_H
#define COKE_TYPES_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

/* ── Protocol Enum ─────────────────────────────────────────────── */
typedef enum {
  PROTO_UNKNOWN = 0,
  PROTO_TCP,
  PROTO_UDP,
  PROTO_ICMP,
  PROTO_ARP,
  PROTO_OTHER
} coke_proto_t;

/* ── Single captured packet ────────────────────────────────────── */
#define COKE_MAX_RAW 2048 /* bytes stored per packet          */
#define COKE_INFO_LEN 128 /* decoded one-liner info           */

typedef struct {
  uint32_t id;                  /* monotonic index  */
  struct timespec ts;           /* capture time     */
  coke_proto_t proto;           /* protocol enum    */
  char src_ip[INET_ADDRSTRLEN]; /* source IP        */
  char dst_ip[INET_ADDRSTRLEN]; /* destination IP   */
  uint16_t src_port;            /* 0 if N/A         */
  uint16_t dst_port;
  uint8_t ttl;
  uint16_t raw_len;          /* actual bytes     */
  uint8_t raw[COKE_MAX_RAW]; /* raw frame        */
  char info[COKE_INFO_LEN];  /* e.g. "SYN ACK"  */
} coke_packet_t;

/* ── Runtime configuration ─────────────────────────────────────── */
typedef struct {
  char *interface;    /* NULL = all interfaces       */
  char *output_file;  /* PCAP filename               */
  char *filter_proto; /* initial protocol filter     */
  bool verbose;
  bool hex_view;
  int store_capacity; /* ring buffer size             */
} coke_config_t;

/* ── Filter criteria ───────────────────────────────────────────── */
typedef struct {
  coke_proto_t proto;              /* PROTO_UNKNOWN = all */
  char ip_substr[INET_ADDRSTRLEN]; /* "" = no IP filter   */
  char src_ip[INET_ADDRSTRLEN];
  char dst_ip[INET_ADDRSTRLEN];
  int src_port; /* -1 = all */
  int dst_port; /* -1 = all */
  int port;     /* -1 = all */
  int min_len;  /* -1 = all */

  bool is_conv;
  char conv_ip1[INET_ADDRSTRLEN];
  char conv_ip2[INET_ADDRSTRLEN];
  int conv_port1;
  int conv_port2;
} coke_filter_t;

#endif /* COKE_TYPES_H */
