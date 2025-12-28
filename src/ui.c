#include <stdio.h>
#include <ctype.h>
#include "../include/coke.h"

void print_banner() {
    printf("\033[2J\033[H"); 
    printf("\033[1;36m");
    printf("   ❄️   C O C A   S H E L L   v1.0   ❄️\n");
    printf("   ------------------------------------\n");
    printf("   Raw Socket Engine | Ctrl+C to stop capture\n\n");
    printf("\033[0m");
}

void hex_dump(const unsigned char *data, int size) {
    char ascii[17];
    int i, j;
    ascii[16] = '\0';

    printf("\033[0;37m"); 
    for (i = 0; i < size; ++i) {
        if (i % 16 == 0) printf("   0x%04x: ", i);
        printf("%02X ", data[i]);
        if (isprint(data[i])) ascii[i % 16] = data[i];
        else ascii[i % 16] = '.';

        if ((i + 1) % 16 == 0) {
            printf("  |%s|\n", ascii);
        } else if (i + 1 == size) {
            ascii[(i + 1) % 16] = '\0';
            for (j = (i + 1) % 16; j < 16; ++j) printf("   ");
            printf("  |%s|\n", ascii);
        }
    }
    printf("\033[0m\n");
}
