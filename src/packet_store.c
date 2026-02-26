/* ── packet_store.c — Thread-safe ring buffer ────────────────── */
#include "coke/packet_store.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

static coke_packet_t *ring = NULL;
static int cap = 0;
static int head = 0; /* next write position */
static int count = 0;
static uint32_t total = 0;
static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;

void store_init(int capacity) {
  pthread_mutex_lock(&mtx);
  free(ring);
  cap = capacity;
  ring = calloc((size_t)cap, sizeof(coke_packet_t));
  head = 0;
  count = 0;
  total = 0;
  pthread_mutex_unlock(&mtx);
}

void store_push(const coke_packet_t *pkt) {
  pthread_mutex_lock(&mtx);
  if (!ring) {
    pthread_mutex_unlock(&mtx);
    return;
  }
  memcpy(&ring[head], pkt, sizeof(coke_packet_t));
  ring[head].id = total++;
  head = (head + 1) % cap;
  if (count < cap)
    count++;
  pthread_mutex_unlock(&mtx);
}

const coke_packet_t *store_get(int idx) {
  pthread_mutex_lock(&mtx);
  if (!ring || idx < 0 || idx >= count) {
    pthread_mutex_unlock(&mtx);
    return NULL;
  }
  /* oldest entry is at (head - count + cap) % cap */
  int real = (head - count + cap + idx) % cap;
  const coke_packet_t *p = &ring[real];
  pthread_mutex_unlock(&mtx);
  return p;
}

int store_count(void) {
  pthread_mutex_lock(&mtx);
  int c = count;
  pthread_mutex_unlock(&mtx);
  return c;
}

uint32_t store_total(void) {
  pthread_mutex_lock(&mtx);
  uint32_t t = total;
  pthread_mutex_unlock(&mtx);
  return t;
}

void store_clear(void) {
  pthread_mutex_lock(&mtx);
  head = 0;
  count = 0;
  total = 0;
  pthread_mutex_unlock(&mtx);
}

void store_destroy(void) {
  pthread_mutex_lock(&mtx);
  free(ring);
  ring = NULL;
  cap = 0;
  count = 0;
  pthread_mutex_unlock(&mtx);
}
