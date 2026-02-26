/* ── filter.c — Runtime packet filtering ─────────────────────── */
#include "coke/filter.h"
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "coke/filter.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static coke_filter_t g_filter;
static char g_desc[256];

void filter_init(void) {
  g_filter.proto = PROTO_UNKNOWN;
  g_filter.ip_substr[0] = '\0';
  g_filter.src_ip[0] = '\0';
  g_filter.dst_ip[0] = '\0';
  g_filter.src_port = -1;
  g_filter.dst_port = -1;
  g_filter.port = -1;
  g_filter.min_len = -1;
  g_filter.is_conv = false;
  snprintf(g_desc, sizeof(g_desc), "All Traffic");
}

void filter_set_conversation(const coke_packet_t *pkt) {
  filter_init();
  g_filter.is_conv = true;
  g_filter.proto = pkt->proto;
  strncpy(g_filter.conv_ip1, pkt->src_ip, sizeof(g_filter.conv_ip1) - 1);
  strncpy(g_filter.conv_ip2, pkt->dst_ip, sizeof(g_filter.conv_ip2) - 1);
  g_filter.conv_port1 = pkt->src_port;
  g_filter.conv_port2 = pkt->dst_port;

  snprintf(g_desc, sizeof(g_desc), "Conversation %s:%u <-> %s:%u", pkt->src_ip,
           pkt->src_port, pkt->dst_ip, pkt->dst_port);
}

void filter_set(const char *expr) {
  filter_init();
  if (!expr || expr[0] == '\0' || strcasecmp(expr, "all") == 0) {
    return;
  }

  snprintf(g_desc, sizeof(g_desc), "%s", expr);

  char buf[256];
  strncpy(buf, expr, sizeof(buf) - 1);
  buf[sizeof(buf) - 1] = '\0';

  char *saveptr;
  char *token = strtok_r(buf, " ", &saveptr);
  bool is_advanced = false;

  while (token) {
    char *colon = strchr(token, ':');
    if (colon) {
      is_advanced = true;
      *colon = '\0';
      char *key = token;
      char *val = colon + 1;

      if (strcasecmp(key, "proto") == 0) {
        if (strcasecmp(val, "tcp") == 0)
          g_filter.proto = PROTO_TCP;
        else if (strcasecmp(val, "udp") == 0)
          g_filter.proto = PROTO_UDP;
        else if (strcasecmp(val, "icmp") == 0)
          g_filter.proto = PROTO_ICMP;
        else if (strcasecmp(val, "arp") == 0)
          g_filter.proto = PROTO_ARP;
      } else if (strcasecmp(key, "src") == 0) {
        strncpy(g_filter.src_ip, val, sizeof(g_filter.src_ip) - 1);
      } else if (strcasecmp(key, "dst") == 0) {
        strncpy(g_filter.dst_ip, val, sizeof(g_filter.dst_ip) - 1);
      } else if (strcasecmp(key, "src_port") == 0) {
        g_filter.src_port = atoi(val);
      } else if (strcasecmp(key, "dst_port") == 0) {
        g_filter.dst_port = atoi(val);
      } else if (strcasecmp(key, "port") == 0) {
        g_filter.port = atoi(val);
      } else if (strcasecmp(key, "len") == 0) {
        if (val[0] == '>')
          g_filter.min_len = atoi(val + 1);
        else
          g_filter.min_len = atoi(val);
      }
    }
    token = strtok_r(NULL, " ", &saveptr);
  }

  if (!is_advanced) {
    if (strcasecmp(expr, "tcp") == 0)
      g_filter.proto = PROTO_TCP;
    else if (strcasecmp(expr, "udp") == 0)
      g_filter.proto = PROTO_UDP;
    else if (strcasecmp(expr, "icmp") == 0)
      g_filter.proto = PROTO_ICMP;
    else if (strcasecmp(expr, "arp") == 0)
      g_filter.proto = PROTO_ARP;
    else {
      strncpy(g_filter.ip_substr, expr, sizeof(g_filter.ip_substr) - 1);
      g_filter.ip_substr[sizeof(g_filter.ip_substr) - 1] = '\0';
    }
  }
}

bool filter_matches(const coke_packet_t *pkt) {
  if (g_filter.is_conv) {
    if (pkt->proto != g_filter.proto)
      return false;

    bool match1 = (strcmp(pkt->src_ip, g_filter.conv_ip1) == 0 &&
                   strcmp(pkt->dst_ip, g_filter.conv_ip2) == 0 &&
                   pkt->src_port == g_filter.conv_port1 &&
                   pkt->dst_port == g_filter.conv_port2);

    bool match2 = (strcmp(pkt->src_ip, g_filter.conv_ip2) == 0 &&
                   strcmp(pkt->dst_ip, g_filter.conv_ip1) == 0 &&
                   pkt->src_port == g_filter.conv_port2 &&
                   pkt->dst_port == g_filter.conv_port1);

    return (match1 || match2);
  }

  if (g_filter.proto != PROTO_UNKNOWN && pkt->proto != g_filter.proto)
    return false;

  if (g_filter.ip_substr[0] != '\0') {
    if (strstr(pkt->src_ip, g_filter.ip_substr) == NULL &&
        strstr(pkt->dst_ip, g_filter.ip_substr) == NULL)
      return false;
  }

  if (g_filter.src_ip[0] != '\0') {
    if (strstr(pkt->src_ip, g_filter.src_ip) == NULL)
      return false;
  }

  if (g_filter.dst_ip[0] != '\0') {
    if (strstr(pkt->dst_ip, g_filter.dst_ip) == NULL)
      return false;
  }

  if (g_filter.src_port != -1 && pkt->src_port != g_filter.src_port)
    return false;
  if (g_filter.dst_port != -1 && pkt->dst_port != g_filter.dst_port)
    return false;

  if (g_filter.port != -1) {
    if (pkt->src_port != g_filter.port && pkt->dst_port != g_filter.port)
      return false;
  }

  if (g_filter.min_len != -1 && pkt->raw_len < g_filter.min_len)
    return false;

  return true;
}

const char *filter_describe(void) { return g_desc; }
