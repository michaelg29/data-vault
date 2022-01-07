#ifndef MEM_H
#define MEM_H

void conditionalFree(void *val, void (*freeFunc)(void *val));

#endif // MEM_H