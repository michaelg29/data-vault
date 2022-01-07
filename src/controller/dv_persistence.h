#include "../datavault.h"

#ifndef DV_PERSISTENCE_H
#define DV_PERSISTENCE_H

extern const char *iv_fp;
extern const char *data_fp;
extern const char *data_tmp_fp;
extern const char *nameIdMap_fp;
extern const char *idIdxMap_fp;
extern const char *categoryIdMap_fp;
extern const char *pwd_fp;
extern const char *dk_fp;

int dv_initFiles(unsigned char *random);

int dv_load(dv_app *dv);
int dv_save(dv_app *dv);

#endif // DV_PERSISTENCE_H