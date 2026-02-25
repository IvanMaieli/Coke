#ifndef COCA_CONFIG_H
#define COCA_CONFIG_H

#include "types.h"

/* Global configuration – initialised in config_init() */
extern coca_config_t g_config;

/* Set defaults */
void config_init(void);

/* Parse argv; returns 0 on success, -1 on error / --help */
int config_parse_args(int argc, char *argv[]);

/* Print usage to stdout */
void config_usage(const char *progname);

#endif /* COCA_CONFIG_H */
