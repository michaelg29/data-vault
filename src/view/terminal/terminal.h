#ifndef TERMINAL_H
#define TERMINAL_H

#define DV_QUIT -1
#define DV_INVALID_CMD -2

// open a continuous terminal session
int terminal();

// run a single command with credentials
int singleCmd(int argc, char **argv);

#endif // TERMINAL_H