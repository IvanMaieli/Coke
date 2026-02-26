/* ── ui.c — ncurses dashboard ──────────────────────────────────── */
#include <ctype.h>
#include <ncurses.h>
#include <stdlib.h>
#include <string.h>

#include "coca/config.h"
#include "coca/dissect.h"
#include "coca/filter.h"
#include "coca/packet_store.h"
#include "coca/sniffer.h"
#include "coca/stats.h"
#include "coca/ui.h"

static int *s_map = NULL;
static int s_selected = 0;
static bool s_follow = true;
static bool s_show_graph = false;

/* Colours */
#define C_STATUS 1
#define C_TCP 2
#define C_UDP 3
#define C_ICMP 4
#define C_ARP 5
#define C_OTHER 6
#define C_SEL 7
#define C_HEADER 8

void ui_init(void) {
  initscr();
  cbreak();
  noecho();
  keypad(stdscr, TRUE);
  curs_set(0);
  halfdelay(2); /* 200 ms timeout for getch */

  if (has_colors()) {
    start_color();
    use_default_colors();
    init_pair(C_STATUS, COLOR_BLACK, COLOR_CYAN);
    init_pair(C_TCP, COLOR_CYAN, -1);
    init_pair(C_UDP, COLOR_BLUE, -1);
    init_pair(C_ICMP, COLOR_WHITE, -1);
    init_pair(C_ARP, COLOR_WHITE, -1);
    init_pair(C_OTHER, COLOR_WHITE, -1);
    init_pair(C_SEL, COLOR_WHITE, COLOR_BLUE);
    init_pair(C_HEADER, COLOR_CYAN, -1);
  }

  s_map = calloc((size_t)g_config.store_capacity, sizeof(int));
}

void ui_cleanup(void) {
  if (s_map) {
    free(s_map);
    s_map = NULL;
  }
  endwin();
}

static int get_color(coca_proto_t p) {
  switch (p) {
  case PROTO_TCP:
    return COLOR_PAIR(C_TCP);
  case PROTO_UDP:
    return COLOR_PAIR(C_UDP);
  case PROTO_ICMP:
    return COLOR_PAIR(C_ICMP);
  case PROTO_ARP:
    return COLOR_PAIR(C_ARP);
  default:
    return COLOR_PAIR(C_OTHER);
  }
}

static void draw_hex_dump(const uint8_t *data, int len, int start_y,
                          int start_x, int max_lines) {
  for (int line = 0; line < max_lines; line++) {
    int offset = line * 16;
    if (offset >= len)
      break;

    mvprintw(start_y + line, start_x, "  0x%04X: ", offset);

    /* Hex bytes */
    for (int i = 0; i < 16; i++) {
      if (offset + i < len)
        printw("%02X ", data[offset + i]);
      else
        printw("   ");
      if (i == 7)
        printw(" ");
    }

    printw(" │ ");
    /* ASCII */
    for (int i = 0; i < 16; i++) {
      if (offset + i < len) {
        char c = data[offset + i];
        printw("%c", isprint(c) ? c : '.');
      } else {
        printw(" ");
      }
    }
    printw(" │");
  }
}

void ui_run(void) {
  while (g_sniffing) {
    int rows, cols;
    getmaxyx(stdscr, rows, cols);

    /* Rebuild map */
    int total_store = store_count();
    int map_count = 0;
    for (int i = 0; i < total_store; i++) {
      const coca_packet_t *p = store_get(i);
      if (p && filter_matches(p)) {
        s_map[map_count++] = i;
      }
    }

    if (s_follow || map_count == 0) {
      s_selected = map_count > 0 ? map_count - 1 : 0;
    } else {
      if (s_selected >= map_count)
        s_selected = map_count - 1;
      if (s_selected < 0)
        s_selected = 0;
    }

    erase();

    /* Layout maths */
    int hex_lines = 10;
    int dtl_lines = 2;
    int list_y = 1;
    int list_lines = rows - 1 - 1 - hex_lines - dtl_lines -
                     1; /* top, header, hex, dtl, cmd */
    if (list_lines < 3)
      list_lines = 3;

    /* Draw Status Bar */
    attron(COLOR_PAIR(C_STATUS) | A_BOLD);
    mvhline(0, 0, ' ', cols);
    mvprintw(0, 1, " 🧊 COCA v2.0 | Filter: %s", filter_describe());

    coca_stats_t snap;
    snap.total = atomic_load(&g_stats.total);
    snap.tcp = atomic_load(&g_stats.tcp);
    snap.udp = atomic_load(&g_stats.udp);
    snap.icmp = atomic_load(&g_stats.icmp);
    snap.arp = atomic_load(&g_stats.arp);
    snap.other = atomic_load(&g_stats.other);

    char stats_buf[128];
    snprintf(stats_buf, sizeof(stats_buf),
             "Pkts: %u | TCP: %u UDP: %u ICMP: %u ARP: %u ", snap.total,
             snap.tcp, snap.udp, snap.icmp, snap.arp);
    mvprintw(0, cols - strlen(stats_buf) - 1, "%s", stats_buf);
    attroff(COLOR_PAIR(C_STATUS) | A_BOLD);

    /* Draw Packet List Header */
    attron(COLOR_PAIR(C_HEADER) | A_BOLD);
    mvhline(list_y, 0, ' ', cols);
    if (!s_show_graph) {
      mvprintw(
          list_y, 0,
          "   #     │ Proto │ Source               │ Dest                 │ "
          "Len  │ Info");
    } else {
      mvprintw(list_y, 0, "   Protocol Statistics Graph");
    }
    attroff(COLOR_PAIR(C_HEADER) | A_BOLD);

    if (s_show_graph) {
      unsigned int t = snap.total ? snap.total : 1;
      int max_w = cols - 30;
      if (max_w < 10)
        max_w = 10;

      int tcp_w = (int)((snap.tcp * (long long)max_w) / t);
      int udp_w = (int)((snap.udp * (long long)max_w) / t);
      int icmp_w = (int)((snap.icmp * (long long)max_w) / t);
      int arp_w = (int)((snap.arp * (long long)max_w) / t);
      int oth_w = (int)((snap.other * (long long)max_w) / t);

      int gy = list_y + 2;

      attron(COLOR_PAIR(C_TCP) | A_BOLD);
      mvprintw(gy++, 2, "TCP   [%5u] │ ", snap.tcp);
      for (int i = 0; i < tcp_w; i++)
        printw("█");
      attroff(COLOR_PAIR(C_TCP) | A_BOLD);

      gy++;
      attron(COLOR_PAIR(C_UDP) | A_BOLD);
      mvprintw(gy++, 2, "UDP   [%5u] │ ", snap.udp);
      for (int i = 0; i < udp_w; i++)
        printw("█");
      attroff(COLOR_PAIR(C_UDP) | A_BOLD);

      gy++;
      attron(COLOR_PAIR(C_ICMP) | A_BOLD);
      mvprintw(gy++, 2, "ICMP  [%5u] │ ", snap.icmp);
      for (int i = 0; i < icmp_w; i++)
        printw("█");
      attroff(COLOR_PAIR(C_ICMP) | A_BOLD);

      gy++;
      attron(COLOR_PAIR(C_ARP) | A_BOLD);
      mvprintw(gy++, 2, "ARP   [%5u] │ ", snap.arp);
      for (int i = 0; i < arp_w; i++)
        printw("█");
      attroff(COLOR_PAIR(C_ARP) | A_BOLD);

      gy++;
      attron(COLOR_PAIR(C_OTHER) | A_BOLD);
      mvprintw(gy++, 2, "OTHER [%5u] │ ", snap.other);
      for (int i = 0; i < oth_w; i++)
        printw("█");
      attroff(COLOR_PAIR(C_OTHER) | A_BOLD);

    } else {
      /* Draw Packet List */
      int print_start = 0;
      if (s_selected >= list_lines / 2) {
        print_start = s_selected - list_lines / 2;
      }
      if (print_start + list_lines > map_count) {
        print_start = map_count - list_lines;
      }
      if (print_start < 0)
        print_start = 0;

      for (int i = 0; i < list_lines; i++) {
        int map_idx = print_start + i;
        if (map_idx >= map_count)
          break;

        const coca_packet_t *p = store_get(s_map[map_idx]);
        if (!p)
          continue;

        int row_y = list_y + 1 + i;

        if (map_idx == s_selected) {
          attron(COLOR_PAIR(C_SEL) | A_BOLD);
          mvhline(row_y, 0, ' ', cols);
        } else {
          attron(get_color(p->proto));
        }

        mvprintw(row_y, 1, "%-6u │ %-5s │ %-20s │ %-20s │ %-4u │ %.*s", p->id,
                 proto_label(p->proto), p->src_ip, p->dst_ip, p->raw_len,
                 cols - 65, p->info);

        if (map_idx == s_selected) {
          attroff(COLOR_PAIR(C_SEL) | A_BOLD);
        } else {
          attroff(get_color(p->proto));
        }
      }
    }

    /* Outline & Draw Hex Dump + Details */
    int dtl_y = list_y + 1 + list_lines;
    attron(COLOR_PAIR(C_HEADER) | A_BOLD);
    mvhline(dtl_y, 0, ACS_HLINE, cols);
    if (map_count == 0) {
      mvprintw(dtl_y, 1, " Detail: [Waiting for packets...]");
    } else {
      const coca_packet_t *sp = store_get(s_map[s_selected]);
      if (sp) {
        mvprintw(dtl_y, 1, " Detail: %s  %s:%u -> %s:%u  [%d bytes]",
                 proto_label(sp->proto), sp->src_ip, sp->src_port, sp->dst_ip,
                 sp->dst_port, sp->raw_len);
        attroff(COLOR_PAIR(C_HEADER));

        mvprintw(dtl_y + 1, 1, "INFO: %s | TTL: %u | Captured TS: %ld.%09ld",
                 sp->info, sp->ttl, (long)sp->ts.tv_sec, (long)sp->ts.tv_nsec);

        draw_hex_dump(sp->raw, sp->raw_len, dtl_y + 2, 0, hex_lines);
      }
    }
    attroff(COLOR_PAIR(C_HEADER) | A_BOLD);

    /* Draw Command Bar */
    attron(COLOR_PAIR(C_STATUS) | A_BOLD);
    mvhline(rows - 1, 0, ' ', cols);
    mvprintw(rows - 1, 1,
             " [j/k/UP/DOWN] Scroll  [f] Filter  [v] Conversation  [g] Graph  "
             "[c] Clear  [q] Quit %s",
             s_follow ? "(FOLLOWING)" : "");
    attroff(COLOR_PAIR(C_STATUS) | A_BOLD);

    refresh();

    /* Input loop */
    int ch = getch();
    if (ch == ERR)
      continue; /* Timeout */

    switch (ch) {
    case 'q':
    case 'Q':
    case KEY_F(10):
      g_sniffing = 0;
      break;

    case KEY_UP:
    case 'k':
      if (s_selected > 0) {
        s_selected--;
        s_follow = false;
      }
      break;

    case KEY_DOWN:
    case 'j':
      if (s_selected < map_count - 1) {
        s_selected++;
        s_follow = false;
      }
      if (s_selected == map_count - 1) {
        s_follow = true;
      }
      break;

    case KEY_LEFT:
    case 'h': /* repurposed 'h' key for help or maybe 'H' */
      /* Help modal ? */
      break;

    case 'v':
    case 'V':
      if (map_count > 0 && s_selected >= 0 && s_selected < map_count) {
        const coca_packet_t *sp = store_get(s_map[s_selected]);
        if (sp && (sp->proto == PROTO_TCP || sp->proto == PROTO_UDP)) {
          filter_set_conversation(sp);
          s_selected = 0;
          s_follow = true;
        }
      }
      break;

    case 'f':
    case 'F':
    case KEY_F(2): {
      /* Input filter modal */
      char filt_str[64] = {0};
      attron(COLOR_PAIR(C_STATUS));
      mvprintw(rows - 1, 1,
               " Enter filter (e.g. proto:tcp src:10.0.0.1 port:80, or clear "
               "with 'all'): ");
      clrtoeol();
      echo();
      nocbreak();
      timeout(-1); /* block */
      getnstr(filt_str, sizeof(filt_str) - 1);
      cbreak();
      noecho();
      halfdelay(2);
      filter_set(filt_str);
      s_follow = true; /* jump to bottom */
      break;
    }

    case 'g':
    case 'G':
      s_show_graph = !s_show_graph;
      break;

    case 'c':
    case 'C':
    case KEY_F(5):
      store_clear();
      stats_reset();
      s_selected = 0;
      s_follow = true;
      break;
    }
  }
}
