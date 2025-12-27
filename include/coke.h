#ifndef COKE_H
#define COKE_H

#include <stdint.h>
#include <stdbool.h>

// Global configuration
typedef struct {	
	char *output_file;	// output path
	char *filter_proto;	// flag to filter by packet's protocol
	bool verbose;		// verbose option to display anything
	bool automation_on;	// enable/disable automation sniffing
} coke_config_t;

void print_banner();			
void show_help();

#endif

