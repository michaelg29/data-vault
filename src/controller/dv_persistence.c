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
    bool ret = true;

    // create files
    ret = file_create(nameIdMap_fp);
    ret = file_create(idIdxMap_fp);
    ret = file_create(categoryIdMap_fp);

    // write into iv file
    ret = file_writeContents(iv_fp, random, 0x70);

    // write dataIV into data.dv
    ret = file_writeContents(data_fp, random, 16);

    return ret ? DV_SUCCESS : DV_FILE_DNE;
}

int dv_load(dv_app *dv)
{
}
int dv_save(dv_app *dv)
{
}