#include "lib/cmathematics/cmathematics.h"
#include "lib/cmathematics/data/encryption/aes.h"

#include "lib/ds/avl.h"
#include "lib/ds/btree.h"

#ifndef DATAVAULT_H
#define DATAVAULT_H

// operating system detection
#ifdef DV_WINDOWS
    #undef DV_WINDOWS
#endif

#ifdef DV_UNIX
    #undef DV_UNIX
#endif

#ifdef DV_MACINTOSH
    #undef DV_MACINTOSH
#endif

#ifdef _WIN32
    #define DV_WINDOWS
#else
    #ifdef _WIN64
        #define DV_WINDOWS
    #else
        #ifdef __MACH__
            #define DV_MACINTOSH
        #else
            #define DV_UNIX
        #endif
    #endif
#endif

#ifdef DV_WINDOWS
    #define DV_CLEAR "cls"
    #define DV_CLIP  "clip.exe"
#else
    #define DV_CLEAR "clear"
    #ifndef DV_CLIP
        #define DV_CLIP "xclip"
    #endif
#endif

// parameters
#define DV_KEYLEN 32

// return codes
#define DV_SUCCESS 0
#define DV_MEM_ERR 1
#define DV_FILE_DNE 2
#define DV_INVALID_INPUT 3
#define DV_LOGGED_OUT 4

// run mode
extern int DV_DEBUG;

// application data
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

// application-level functions
int dv_init(dv_app *dv);
int dv_kill(dv_app *dv);
void dv_log(dv_app *dv);

#endif // DATAVAULT_H
