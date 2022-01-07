#include "mem.h"

void conditionalFree(void *val, void (*freeFunc)(void *val))
{
    if (val)
    {
        freeFunc(val);
    }
}