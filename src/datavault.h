#include "lib/cmathematics/cmathematics.h"
#include "lib/cmathematics/data/encryption/aes.h"

#include "lib/ds/avl.h"
#include "lib/ds/btree.h"

#ifndef DATAVAULT_H
#define DATAVAULT_H

#define DV_KEYLEN 32

#define DV_SUCCESS 0
#define DV_MEM_ERR 1
#define DV_FILE_DNE 2
#define DV_INVALID_INPUT 3
#define DV_LOGGED_OUT 4

extern int DV_DEBUG;

typedef struct
{
    bool loggedIn;

    unsigned char dataKey[DV_KEYLEN];
    unsigned char aes_key_schedule[AES_256_NR + 1][AES_BLOCK_SIDE][AES_BLOCK_SIDE];

    unsigned char *random;

    avl *nameIdMap;
    btree idIdxMap;
    avl *catIdMap;

    unsigned int maxEntryId;
    unsigned char maxCatId;
} dv_app;

void dv_init(dv_app *dv);
void dv_kill(dv_app *dv);
void dv_log(dv_app *dv);

#endif // DATAVAULT_H