/* ── logger.c — PCAP file writer ─────────────────────────────── */
#include "coke/logger.h"
#include <string.h>

/* ── PCAP file header (libpcap format) ──────────────────────── */
struct pcap_file_hdr {
  uint32_t magic_number;  /* 0xa1b2c3d4 */
  uint16_t version_major; /* 2 */
  uint16_t version_minor; /* 4 */
  int32_t thiszone;
  uint32_t sigfigs;
  uint32_t snaplen;
  uint32_t network; /* 1 = LINKTYPE_ETHERNET */
};

/* ── PCAP per-packet record header ──────────────────────────── */
struct pcap_pkt_hdr {
  uint32_t ts_sec;
  uint32_t ts_usec;
  uint32_t incl_len; /* bytes stored in file */
  uint32_t orig_len; /* actual packet length */
};

FILE *logger_open(const char *filename) {
  if (!filename)
    return NULL;
  FILE *f = fopen(filename, "wb");
  if (!f)
    return NULL;

  struct pcap_file_hdr fh = {.magic_number = 0xa1b2c3d4,
                             .version_major = 2,
                             .version_minor = 4,
                             .thiszone = 0,
                             .sigfigs = 0,
                             .snaplen = 65535,
                             .network = 1};
  fwrite(&fh, sizeof(fh), 1, f);
  fflush(f);
  return f;
}

void logger_write_packet(FILE *f, const coke_packet_t *pkt) {
  if (!f || !pkt)
    return;

  uint32_t stored = pkt->raw_len > COKE_MAX_RAW ? COKE_MAX_RAW : pkt->raw_len;

  struct pcap_pkt_hdr ph = {.ts_sec = (uint32_t)pkt->ts.tv_sec,
                            .ts_usec = (uint32_t)(pkt->ts.tv_nsec / 1000),
                            .incl_len = stored,
                            .orig_len = pkt->raw_len};
  fwrite(&ph, sizeof(ph), 1, f);
  fwrite(pkt->raw, 1, stored, f);
  fflush(f);
}

void logger_close(FILE *f) {
  if (f)
    fclose(f);
}
