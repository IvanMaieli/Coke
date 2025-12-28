#ifndef COKE_H
#define COKE_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <signal.h> // Fondamentale per il Ctrl+C

// Configurazione
typedef struct {
    char *output_file;
    char *filter_proto;
    bool verbose;
    bool hex_view;        // Nuova feature: vedere l'Hex Dump
} coke_config_t;

// Variabili Globali
extern volatile sig_atomic_t is_sniffing; // Volatile perché toccata dai segnali
extern coke_config_t config;

// Funzioni
void print_banner();
void hex_dump(const unsigned char *data, int size); // La funzione "Matrix"
void setup_signals();
void* sniffer_loop(void* arg);
FILE* pcap_init(const char* filename);

#endif
