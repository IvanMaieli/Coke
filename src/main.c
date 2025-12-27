#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> 
#include <getopt.h>
#include "../include/coke.h"

// Colori ANSI per il terminale
#define COLOR_CYAN  "\033[1;36m"
#define COLOR_RESET "\033[0m"

void print_banner() {
    printf(COLOR_CYAN);
    printf("  ❄️    C O C A   ❄️\n");
    printf("  Network Analysis Tool\n");
    printf("-------------------------\n");
    printf("      \\  |  /      \n");
    printf("    --   * --    \n");
    printf("      /  |  \\      \n");
    printf("-------------------------\n");
    printf(COLOR_RESET);
}

void show_help() {
    printf("Usage: sudo ./coke [OPTIONS]\n");
    printf("Options:\n");
    printf("  -o <file>   Set output pcap file (default: capture.pcap)\n");
    printf("  -f <proto>  Filter protocol (tcp, udp, icmp)\n");
    printf("  -a          Enable automation tasks\n");
    printf("  -v          Verbose mode\n");
    printf("  -h          Show this help message\n");
}

int main(int argc, char *argv[]) {
    // 1. Configurazione di Default
    coke_config_t config;
    config.output_file = "capture.pcap";
    config.filter_proto = NULL;
    config.verbose = false;
    config.automation_on = false;

    // 2. Parsing degli Argomenti (Flags)
    int opt;
    while ((opt = getopt(argc, argv, "o:f:avh")) != -1) {
        switch (opt) {
            case 'o':
                config.output_file = optarg;
                break;
            case 'f':
                config.filter_proto = optarg;
                break;
            case 'a':
                config.automation_on = true;
                break;
            case 'v':
                config.verbose = true;
                break;
            case 'h':
                show_help();
                return 0;
            default:
                show_help();
                return 1;
        }
    }

    // 3. Avvio
    print_banner();
    printf("[*] Output File: %s\n", config.output_file);
    if (config.filter_proto) {
        printf("[*] Filter: Only %s\n", config.filter_proto);
    }
    if (config.automation_on) {
        printf("[!] Automation Module: ENABLED\n");
    }

    printf("\n[INFO] Starting Coke Engine... (Ctrl+C to stop)\n");
    
    // TODO: start_sniffer(&config);
    
    // Simulazione loop per ora
    while(1) {
        sleep(1); 
    }

    return 0;
}
