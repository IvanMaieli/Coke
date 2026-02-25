
/* ── dissect.c — Protocol dissection ─────────────────────────── */
#include "coca/dissect.h"
#include <arpa/inet.h>
#include <linux/if_arp.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <string.h>

const char *proto_label(coca_proto_t p) {
  switch (p) {
  case PROTO_TCP:
    return "TCP";
  case PROTO_UDP:
    return "UDP";
  case PROTO_ICMP:
    return "ICMP";
  case PROTO_ARP:
    return "ARP";
  case PROTO_OTHER:
    return "OTHER";
  default:
    return "UNK";
  }
}

int dissect_packet(const uint8_t *raw, int raw_len, coca_packet_t *out) {
  memset(out, 0, sizeof(*out));
  clock_gettime(CLOCK_REALTIME, &out->ts);

  int copy_len = raw_len > COCA_MAX_RAW ? COCA_MAX_RAW : raw_len;
  memcpy(out->raw, raw, (size_t)copy_len);
  out->raw_len = (uint16_t)raw_len;

  if (raw_len < (int)sizeof(struct ethhdr))
    return -1;

  struct ethhdr *eth = (struct ethhdr *)raw;
  uint16_t eth_type = ntohs(eth->h_proto);

  /* ── ARP ────────────────────────────────────────────────── */
  if (eth_type == ETH_P_ARP) {
    out->proto = PROTO_ARP;
    /* ARP header sits right after Ethernet */
    if (raw_len >= (int)(sizeof(struct ethhdr) + 28)) {
      const uint8_t *arp = raw + sizeof(struct ethhdr);
      struct in_addr spa, tpa;
      memcpy(&spa, arp + 14, 4); /* sender protocol addr */
      memcpy(&tpa, arp + 24, 4); /* target protocol addr */
      inet_ntop(AF_INET, &spa, out->src_ip, sizeof(out->src_ip));
      inet_ntop(AF_INET, &tpa, out->dst_ip, sizeof(out->dst_ip));
      uint16_t op;
      memcpy(&op, arp + 6, 2);
      op = ntohs(op);
      snprintf(out->info, COCA_INFO_LEN,
               op == 1 ? "Who has %s? Tell %s" : "Reply: %s is at ...",
               out->dst_ip, out->src_ip);
    }
    return 0;
  }

  /* ── IPv4 ───────────────────────────────────────────────── */
  if (eth_type != ETH_P_IP) {
    out->proto = PROTO_OTHER;
    snprintf(out->info, COCA_INFO_LEN, "EtherType 0x%04X", eth_type);
    return 0;
  }

  if (raw_len < (int)(sizeof(struct ethhdr) + sizeof(struct iphdr)))
    return -1;

  struct iphdr *iph = (struct iphdr *)(raw + sizeof(struct ethhdr));
  struct in_addr sa, da;
  sa.s_addr = iph->saddr;
  da.s_addr = iph->daddr;
  inet_ntop(AF_INET, &sa, out->src_ip, sizeof(out->src_ip));
  inet_ntop(AF_INET, &da, out->dst_ip, sizeof(out->dst_ip));
  out->ttl = iph->ttl;

  int ip_hdr_len = iph->ihl * 4;

  switch (iph->protocol) {
  case IPPROTO_TCP: {
    out->proto = PROTO_TCP;
    if (raw_len >= (int)(sizeof(struct ethhdr) + ip_hdr_len +
                         (int)sizeof(struct tcphdr))) {
      struct tcphdr *tcp =
          (struct tcphdr *)(raw + sizeof(struct ethhdr) + ip_hdr_len);
      out->src_port = ntohs(tcp->source);
      out->dst_port = ntohs(tcp->dest);
      /* Decode flags */
      char flags[64] = "";
      if (tcp->syn)
        strcat(flags, "SYN ");
      if (tcp->ack)
        strcat(flags, "ACK ");
      if (tcp->fin)
        strcat(flags, "FIN ");
      if (tcp->rst)
        strcat(flags, "RST ");
      if (tcp->psh)
        strcat(flags, "PSH ");
      if (tcp->urg)
        strcat(flags, "URG ");
      snprintf(out->info, COCA_INFO_LEN, "%u -> %u  [%s] Seq=%u Win=%u",
               out->src_port, out->dst_port, flags, ntohl(tcp->seq),
               ntohs(tcp->window));
    }
    break;
  }
  case IPPROTO_UDP: {
    out->proto = PROTO_UDP;
    if (raw_len >= (int)(sizeof(struct ethhdr) + ip_hdr_len +
                         (int)sizeof(struct udphdr))) {
      struct udphdr *udp =
          (struct udphdr *)(raw + sizeof(struct ethhdr) + ip_hdr_len);
      out->src_port = ntohs(udp->source);
      out->dst_port = ntohs(udp->dest);
      snprintf(out->info, COCA_INFO_LEN, "%u -> %u  Len=%u", out->src_port,
               out->dst_port, ntohs(udp->len));
    }
    break;
  }
  case IPPROTO_ICMP: {
    out->proto = PROTO_ICMP;
    if (raw_len >= (int)(sizeof(struct ethhdr) + ip_hdr_len + 8)) {
      struct icmphdr *icmp =
          (struct icmphdr *)(raw + sizeof(struct ethhdr) + ip_hdr_len);
      const char *type_str = "Other";
      if (icmp->type == ICMP_ECHO)
        type_str = "Echo Request";
      else if (icmp->type == ICMP_ECHOREPLY)
        type_str = "Echo Reply";
      else if (icmp->type == ICMP_DEST_UNREACH)
        type_str = "Dest Unreachable";
      else if (icmp->type == ICMP_TIME_EXCEEDED)
        type_str = "Time Exceeded";
      snprintf(out->info, COCA_INFO_LEN, "%s  Code=%u  Id=%u  Seq=%u", type_str,
               icmp->code, ntohs(icmp->un.echo.id),
               ntohs(icmp->un.echo.sequence));
    }
    break;
  }
  default:
    out->proto = PROTO_OTHER;
    snprintf(out->info, COCA_INFO_LEN, "IP Proto %u", iph->protocol);
    break;
  }

  return 0;
}
