#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include "../include/coke.h"

volatile sig_atomic_t is_sniffing = 0;
coke_config_t config;
pthread_t sniffer_thread;

void handle_sigint(int sig) {
    (void)sig;
    if (is_sniffing) {
        printf("\n\033[1;31m[!] INTERRUPT RECEIVED. STOPPING SNIFFER...\033[0m\n");
        is_sniffing = 0;
    } else {
        printf("\n\nStay cold. ❄️\n");
        exit(0);
    }
}

int main(int argc, char *argv[]) {
    config.output_file = "capture.pcap";
    config.filter_proto = NULL;
    config.hex_view = true; 

    signal(SIGINT, handle_sigint);

    print_banner();

    char cmd[256];

    while (1) {
        if (is_sniffing) {
            pthread_join(sniffer_thread, NULL);
        }

        printf("\033[1;36mcoke > \033[0m");
        
        if (fgets(cmd, sizeof(cmd), stdin) == NULL) break;
        cmd[strcspn(cmd, "\n")] = 0;

        if (strcmp(cmd, "exit") == 0) {
            break;
        } 
        else if (strcmp(cmd, "start") == 0) {
            is_sniffing = 1;
            if (pthread_create(&sniffer_thread, NULL, sniffer_loop, NULL) != 0) {
                printf("[ERROR] Thread creation failed\n");
                is_sniffing = 0;
            }
        } 
        else if (strncmp(cmd, "hex", 3) == 0) {
            config.hex_view = !config.hex_view;
            printf("[Config] Hex Dump: %s\n", config.hex_view ? "ON" : "OFF");
        }
        else if (strcmp(cmd, "clear") == 0) {
            print_banner();
        }
        else if (strcmp(cmd, "help") == 0) {
            printf(" Commands:\n");
            printf("  start   -> Start sniffing (Ctrl+C to stop)\n");
            printf("  hex     -> Toggle Hex Dump view\n");
            printf("  clear   -> Clear screen\n");
            printf("  exit    -> Quit\n");
        }
        else if (strlen(cmd) > 0) {
            printf(" Unknown command: %s\n", cmd);
        }
    }

    return 0;
}
