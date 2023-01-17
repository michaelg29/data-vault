#ifndef TERMINAL_H
#define TERMINAL_H

#define DV_QUIT -1
#define DV_INVALID_CMD -2

// open a continuous terminal session
int terminal();

// run a single command with credentials
/*
 * COMMAND FORMAT WITH PASSWORD:
 * dv.exe -p <USER_PWD> <COMMAND>
 *
 * COMMAND FORMAT WITHOUT PASSWORD, TRIGGERS A PROMPT:
 * dv.exe <COMMAND>
 *
 * IF CREATE ACCOUNT WITH PASSWORD:
 * dv.exe -p <NEW_PWD> createAct <COMMAND>
 *
 * IF CREATE ACCOUNT WITHOUT PASSWORD, TRIGGERS A PROMPT:
 * dv.exe createAct <COMMAND>
 */
int singleCmd(int argc, char **argv);

#endif // TERMINAL_H