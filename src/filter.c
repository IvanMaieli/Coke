/* ── filter.c — Runtime packet filtering ─────────────────────── */
#include "coca/filter.h"
#include <stdio.h>
#include <string.h>
#include <strings.h>

static coca_filter_t g_filter;
static char g_desc[64];

void filter_init(void) {
  g_filter.proto = PROTO_UNKNOWN; /* accept all */
  g_filter.ip_substr[0] = '\0';
  snprintf(g_desc, sizeof(g_desc), "All Traffic");
}

void filter_set(const char *expr) {
  g_filter.proto = PROTO_UNKNOWN;
  g_filter.ip_substr[0] = '\0';

  if (!expr || expr[0] == '\0' || strcasecmp(expr, "all") == 0) {
    snprintf(g_desc, sizeof(g_desc), "All Traffic");
    return;
  }

  if (strcasecmp(expr, "tcp") == 0) {
    g_filter.proto = PROTO_TCP;
    snprintf(g_desc, sizeof(g_desc), "TCP Only");
    return;
  }
  if (strcasecmp(expr, "udp") == 0) {
    g_filter.proto = PROTO_UDP;
    snprintf(g_desc, sizeof(g_desc), "UDP Only");
    return;
  }
  if (strcasecmp(expr, "icmp") == 0) {
    g_filter.proto = PROTO_ICMP;
    snprintf(g_desc, sizeof(g_desc), "ICMP Only");
    return;
  }
  if (strcasecmp(expr, "arp") == 0) {
    g_filter.proto = PROTO_ARP;
    snprintf(g_desc, sizeof(g_desc), "ARP Only");
    return;
  }

  /* Otherwise treat it as an IP substring filter */
  strncpy(g_filter.ip_substr, expr, sizeof(g_filter.ip_substr) - 1);
  g_filter.ip_substr[sizeof(g_filter.ip_substr) - 1] = '\0';
  snprintf(g_desc, sizeof(g_desc), "IP ~ \"%s\"", g_filter.ip_substr);
}

bool filter_matches(const coca_packet_t *pkt) {
  if (g_filter.proto != PROTO_UNKNOWN && pkt->proto != g_filter.proto)
    return false;
  if (g_filter.ip_substr[0] != '\0') {
    if (strstr(pkt->src_ip, g_filter.ip_substr) == NULL &&
        strstr(pkt->dst_ip, g_filter.ip_substr) == NULL)
      return false;
  }
  return true;
}

const char *filter_describe(void) { return g_desc; }
