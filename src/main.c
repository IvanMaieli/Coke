/* ── main.c — Entry Point ────────────────────────────────────── */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "coke/config.h"
#include "coke/filter.h"
#include "coke/packet_store.h"
#include "coke/sniffer.h"
#include "coke/stats.h"
#include "coke/ui.h"

void handle_signal(int sig) {
  (void)sig;
  g_sniffing = 0;
}

int main(int argc, char *argv[]) {
  /* 1. Initialise globals */
  config_init();
  filter_init();
  stats_reset();

  /* 2. Parse arguments */
  if (config_parse_args(argc, argv) < 0) {
    return EXIT_FAILURE;
  }

  if (g_config.filter_proto) {
    filter_set(g_config.filter_proto);
  }

  /* 3. Setup packet store */
  store_init(g_config.store_capacity);

  /* 4. Setup signals */
  signal(SIGINT, handle_signal);
  signal(SIGTERM, handle_signal);

  /* 5. Start engine */
  if (sniffer_start() < 0) {
    fprintf(stderr, "[ERROR] Must run as root to open raw sockets!\n");
    fprintf(stderr, "Try: sudo %s\n", argv[0]);
    store_destroy();
    return EXIT_FAILURE;
  }

  /* 6. Run UI (blocks until quit) */
  ui_init();
  ui_run();
  ui_cleanup();

  /* 7. Shutdown */
  sniffer_stop();
  store_destroy();

  printf("\n Coke shutdown cleanly. Total packets captured: %u\n\n",
         g_stats.total);
  return EXIT_SUCCESS;
}
