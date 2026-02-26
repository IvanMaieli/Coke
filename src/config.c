/* ── config.c — CLI argument parsing & defaults ──────────────── */
#include "coke/config.h"
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

coke_config_t g_config;

void config_init(void) {
  g_config.interface = NULL;
  g_config.output_file = NULL;
  g_config.filter_proto = NULL;
  g_config.verbose = false;
  g_config.hex_view = true;
  g_config.store_capacity = 10000;
}

void config_usage(const char *progname) {
  printf("Usage: %s [OPTIONS]\n"
         "\n"
         "Options:\n"
         "  -i, --interface <iface>   Listen on a specific interface\n"
         "  -f, --filter <proto>      Initial filter: tcp, udp, icmp, arp\n"
         "  -o, --output <file>       Write captured packets to PCAP file\n"
         "  -c, --capacity <N>        Ring buffer size (default: 10000)\n"
         "  -v, --verbose             Enable verbose mode\n"
         "  -h, --help                Show this help\n"
         "\n"
         "Requires root privileges (raw sockets).\n",
         progname);
}

int config_parse_args(int argc, char *argv[]) {
  static struct option long_opts[] = {
      {"interface", required_argument, NULL, 'i'},
      {"filter", required_argument, NULL, 'f'},
      {"output", required_argument, NULL, 'o'},
      {"capacity", required_argument, NULL, 'c'},
      {"verbose", no_argument, NULL, 'v'},
      {"help", no_argument, NULL, 'h'},
      {NULL, 0, NULL, 0}};

  int opt;
  while ((opt = getopt_long(argc, argv, "i:f:o:c:vh", long_opts, NULL)) != -1) {
    switch (opt) {
    case 'i':
      g_config.interface = optarg;
      break;
    case 'f':
      g_config.filter_proto = optarg;
      break;
    case 'o':
      g_config.output_file = optarg;
      break;
    case 'c':
      g_config.store_capacity = atoi(optarg);
      break;
    case 'v':
      g_config.verbose = true;
      break;
    case 'h':
      config_usage(argv[0]);
      return -1;
    default:
      config_usage(argv[0]);
      return -1;
    }
  }
  if (g_config.store_capacity < 100)
    g_config.store_capacity = 100;
  return 0;
}
