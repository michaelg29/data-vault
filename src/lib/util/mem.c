#include "mem.h"
#include "../cmathematics/util/numio.h"

#include <stdlib.h>
#include <stdio.h>

void conditionalFree(void *val, void (*freeFunc)(void *val))
{
    if (val)
    {
        freeFunc(val);
    }
}

void printHexString(char *array, int n, const char *title)
{
    unsigned char *tmp = printByteArr(array, n, 0, 0, 0);
    printf("%s: %s\n", title, tmp);
    free(tmp);
}