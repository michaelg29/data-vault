#ifndef MEM_H
#define MEM_H

void conditionalFree(void *val, void (*freeFunc)(void *val));
void printHexString(char *array, int n, const char *title);

#endif // MEM_H