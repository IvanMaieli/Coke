#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "../include/coke.h"

void* sniffer_loop(void* arg) {
    (void)arg;
    int sock_raw;
    unsigned char *buffer = (unsigned char *)malloc(65536);
    struct sockaddr_storage saddr;
    socklen_t saddr_size = sizeof(saddr);

    sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_raw < 0) {
        perror("\033[1;31m[ERROR] Socket access denied\033[0m");
        is_sniffing = 0;
        free(buffer);
        pthread_exit(NULL);
    }

    printf("\033[1;32m[*] GATEWAY OPENED. LISTENING...\033[0m\n");

    while (is_sniffing) {
        int data_size = recvfrom(sock_raw, buffer, 65536, 0, (struct sockaddr*)&saddr, &saddr_size);
        if (data_size < 0) continue;

        struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
        
        char *color = "\033[0m";
        char *proto_str = "UNK";
        
        if (iph->protocol == 6) { color = "\033[1;32m"; proto_str = "TCP"; }     // Green
        else if (iph->protocol == 17) { color = "\033[1;34m"; proto_str = "UDP"; } // Blue
        else { color = "\033[1;33m"; proto_str = "OTH"; }                          // Yellow

        struct sockaddr_in source, dest;
        source.sin_addr.s_addr = iph->saddr;
        dest.sin_addr.s_addr = iph->daddr;

        printf("%s[%s] %s -> %s | Len: %d\033[0m\n", 
               color, proto_str, inet_ntoa(source.sin_addr), inet_ntoa(dest.sin_addr), data_size);

        if (config.hex_view) {
            hex_dump(buffer, data_size > 64 ? 64 : data_size);
        }
    }

    close(sock_raw);
    free(buffer);
    pthread_exit(NULL);
}


