#include "../datavault.h"

#ifndef DV_CONTROLLER_H
#define DV_CONTROLLER_H

extern const unsigned int userPwdSalt_offset;
extern const unsigned int kekSalt_offset;
extern const unsigned int dataKeyIV_offset;
extern const unsigned int dataIV_offset;
extern const unsigned int nameIdIV_offset;
extern const unsigned int idIdxIV_offset;
extern const unsigned int catIdIV_offset;

int dv_createAccount(dv_app *dv, unsigned char *userPwd, int n);
int dv_login(dv_app *dv, unsigned char *userPwd, int n);
int dv_logout(dv_app *dv);

int dv_createEntry(dv_app *dv, const char *name);
int dv_createEntryData(dv_app *dv, const char *name, const char *category, const char *data);
int dv_deleteEntryData(dv_app *dv, const char *name, const char *category);
int dv_setEntryData(dv_app *dv, const char *name, const char *category, const char *data);

int dv_accessEntryData(dv_app *dv, const char *name, const char *category, char **buffer);

void dv_advanceStartIdx(btree_node *root, unsigned int skipBlock);

#endif // DV_CONTROLLER_H