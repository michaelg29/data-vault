#include "datavault.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "lib/cmathematics/cmathematics.h"

#include "lib/util/mem.h"

void dv_init(dv_app *dv)
{
    // initialize state
    dv->loggedIn = false;

    // clear keys
    memset(dv->dataKey, 0, DV_KEYLEN);
    memset(dv->aes_key_schedule, 0, (AES_256_NR + 1) * AES_BLOCK_LEN);

    // initialize pointers
    dv->random = NULL;

    dv->nameIdMap = NULL;
    dv->idIdxMap.root = NULL;
    dv->catIdMap = NULL;

    dv->maxEntryId = 0;
    dv->maxCatId = 0;
}

void dv_kill(dv_app *dv)
{
    // reset state
    dv->loggedIn = false;

    // clear keys
    memset(dv->dataKey, 0, DV_KEYLEN);
    memset(dv->aes_key_schedule, 0, (AES_256_NR + 1) * AES_BLOCK_LEN);

    // free pointers
    conditionalFree(dv->random, free);
    dv->random = NULL;

    // free maps
    avl_freeKey(dv->nameIdMap);
    dv->nameIdMap = NULL;

    btree_free(&dv->idIdxMap);

    avl_freeKey(dv->catIdMap);
    dv->catIdMap = NULL;

    dv->maxEntryId = 0;
    dv->maxCatId = 0;
}

dv_app *logDv = NULL;
void printEntryId(avl *node)
{
    unsigned int idx = (unsigned int)btree_search(logDv->idIdxMap, (unsigned int)node->val);
    printf("%s --> %d --> %d\n", (const char *)node->key, (unsigned int)node->val, idx);
}

void printCategoryId(avl *node)
{
    printf("%s --> %d\n", (const char *)node->key, (unsigned int)node->val);
}

void dv_log(dv_app *dv)
{
    printf("Logged in: %s\n", dv->loggedIn ? "true" : "false");
    if (dv->loggedIn)
    {
        /*
avl *nameIdMap;
    btree idIdxMap;
    avl *catIdMap;
        */
       logDv = dv;

       printf("Entries==============\n");
       printf("Name --> id --> startIdx\n");
       avl_inorderTraverse(dv->nameIdMap, printEntryId);

       printf("Categories===========\n");
       printf("Name --> id\n");
       avl_inorderTraverse(dv->catIdMap, printCategoryId);

       logDv = NULL;
    }
}