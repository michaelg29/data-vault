#include "../../lib/cmathematics/cmathematics.h"

bool createAccount(const char *pwd);
bool login(const char *pwd);
bool loginFail(const char *pwd);
bool logout();
bool createEntry(const char *entryName);
bool createData(const char *entryName, const char *categoryName, const char *data);
bool accessData(const char *entryName, const char *categoryName, const char *expected);
bool accessDataFailure(const char *entryName, const char *categoryName);
bool deleteData(const char *entryName, const char *categoryName);
bool modifyData(const char *entryName, const char *categoryName, const char *newData);
bool deleteDataFailure(const char *entryName, const char *categoryName);
void printMetrics();
void init();
void cleanup();
