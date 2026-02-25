/* ── sniffer.c — Capture thread ──────────────────────────────── */
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "coca/config.h"
#include "coca/dissect.h"
#include "coca/logger.h"
#include "coca/packet_store.h"
#include "coca/sniffer.h"
#include "coca/stats.h"

volatile sig_atomic_t g_sniffing = 0;
static pthread_t s_thread;
static FILE *s_pcap = NULL;

static void *capture_loop(void *arg) {
  (void)arg;

  int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (sock < 0) {
    g_sniffing = 0;
    return NULL;
  }

  /* Non-blocking-ish: set a short receive timeout so we can
     check g_sniffing regularly instead of blocking forever. */
  struct timeval tv = {.tv_sec = 0, .tv_usec = 100000}; /* 100 ms */
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  unsigned char *buf = malloc(65536);
  if (!buf) {
    close(sock);
    g_sniffing = 0;
    return NULL;
  }

  struct sockaddr_storage saddr;
  socklen_t saddr_len = sizeof(saddr);

  /* Open PCAP file if configured */
  if (g_config.output_file)
    s_pcap = logger_open(g_config.output_file);

  while (g_sniffing) {
    int n =
        recvfrom(sock, buf, 65536, 0, (struct sockaddr *)&saddr, &saddr_len);
    if (n < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        continue; /* timeout — loop back and check flag */
      break;
    }
    if (n == 0)
      continue;

    coca_packet_t pkt;
    if (dissect_packet(buf, n, &pkt) == 0) {
      store_push(&pkt);
      stats_record(pkt.proto);
      if (s_pcap)
        logger_write_packet(s_pcap, &pkt);
    }
  }

  free(buf);
  close(sock);
  if (s_pcap) {
    logger_close(s_pcap);
    s_pcap = NULL;
  }
  return NULL;
}

int sniffer_start(void) {
  g_sniffing = 1;
  if (pthread_create(&s_thread, NULL, capture_loop, NULL) != 0) {
    g_sniffing = 0;
    return -1;
  }
  return 0;
}

void sniffer_stop(void) {
  g_sniffing = 0;
  pthread_join(s_thread, NULL);
}
