#include "dv_persistence.h"

#include "../lib/util/fileio.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

const char *iv_fp = "iv.dv";
const char *data_fp = "data.dv";
const char *data_tmp_fp = "data_tmp.dv";
const char *nameIdMap_fp = "nameIdMap.dv";
const char *idIdxMap_fp = "idIdxMap.dv";
const char *categoryIdMap_fp = "catIdMap.dv";
const char *pwd_fp = "pwd.dv";
const char *dk_fp = "dk.dv";

int dv_initFiles(unsigned char *random)
{
    // create files
    file_create(nameIdMap_fp);
    file_create(idIdxMap_fp);
    file_create(categoryIdMap_fp);

    // write into iv file
    file_writeContents(iv_fp, random, 7 << 4);

    // write dataIV into data.dv
    file_writeContents(data_fp, random, 16);
}

int dv_load(dv_app *dv)
{
}
int dv_save(dv_app *dv)
{
}