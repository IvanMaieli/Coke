#ifndef COKE_UI_H
#define COKE_UI_H

/* Initialise ncurses and colour pairs */
void ui_init(void);

/* Main event loop — blocks until user quits */
void ui_run(void);

/* Tear down ncurses */
void ui_cleanup(void);

#endif /* COKE_UI_H */
