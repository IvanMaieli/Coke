#ifndef COKE_SNIFFER_H
#define COKE_SNIFFER_H

#include "types.h"
#include <signal.h>

/* Volatile flag — set to 0 to stop the capture thread */
extern volatile sig_atomic_t g_sniffing;

/* Start the capture thread. Returns 0 on success. */
int sniffer_start(void);

/* Signal the capture thread to stop and join it */
void sniffer_stop(void);

#endif /* COKE_SNIFFER_H */
