#include "test.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#include "../../datavault.h"
#include "../../controller/dv_controller.h"

dv_app test_app;
int retCode = 0;
char *buf = NULL;
unsigned int noTests = 0;
unsigned int noSuccesses = 0;

bool logTest(bool success, const char *format, ...)
{
    char *totalFormat = malloc(5 + strlen(format) + 1);
    strcpy(totalFormat, success ? "(P) " : "(F) ");
    strcpy(totalFormat + 4, format);
    totalFormat[5 + strlen(format)] = 0;

    noTests++;
    noSuccesses += success;

    va_list args;
    va_start(args, format);
    vprintf(totalFormat, args);
    va_end(args);

    return success;
}

bool createAccount(const char *username, const char *pwd)
{
    retCode = dv_createAccount(&test_app, (unsigned char *)username, (unsigned char *)pwd, strlen(pwd));
    return logTest(retCode == DV_SUCCESS, "Create account with password %s: %d\n", pwd, retCode);
}

bool login(const char *username, const char *pwd)
{
    retCode = dv_login(&test_app, (unsigned char *)username, (unsigned char *)pwd, strlen(pwd));
    return logTest(retCode == DV_SUCCESS, "Login with password %s: %d\n", pwd, retCode);
}

bool loginFail(const char *username, const char *pwd)
{
    retCode = dv_login(&test_app, (unsigned char *)username, (unsigned char *)pwd, strlen(pwd));
    return logTest(retCode == DV_INVALID_INPUT, "Fail login with password %s: %d\n", pwd, retCode);
}

bool logout()
{
    retCode = dv_logout(&test_app);
    return logTest(retCode == DV_SUCCESS, "Logout: %d\n", retCode);
}

bool createEntry(const char *entryName)
{
    retCode = dv_createEntry(&test_app, entryName);
    return logTest(retCode == DV_SUCCESS, "Create entry with name %s: %d\n", entryName, retCode);
}

bool createData(const char *entryName, const char *categoryName, const char *data)
{
    retCode = dv_createEntryData(&test_app, entryName, categoryName, data);
    return logTest(retCode == DV_SUCCESS, "Create (%s) for entry %s under category %s: %d\n", data, entryName, categoryName, retCode);
}

bool accessData(const char *entryName, const char *categoryName, const char *expected)
{
    retCode = dv_accessEntryData(&test_app, entryName, categoryName, &buf);
    bool matches = !strcmp((const char *)buf, expected);
    bool ret = logTest(matches, "Access %s for entry %s: %s: %d\n", categoryName, entryName, buf, retCode);
    free(buf);
    return ret;
}

bool accessDataFailure(const char *entryName, const char *categoryName)
{
    retCode = dv_accessEntryData(&test_app, entryName, categoryName, &buf);
    bool ret = logTest(retCode == DV_INVALID_INPUT, "Access non-existent %s for entry %s: %d\n", categoryName, entryName, retCode);
    free(buf);
    return ret;
}

bool deleteData(const char *entryName, const char *categoryName)
{
    retCode = dv_deleteEntryData(&test_app, entryName, categoryName);
    return logTest(retCode == DV_SUCCESS, "Delete %s for entry %s: %d\n", categoryName, entryName, retCode);
}

bool modifyData(const char *entryName, const char *categoryName, const char *newData)
{
    retCode = dv_setEntryData(&test_app, entryName, categoryName, newData);
    return logTest(retCode == DV_SUCCESS, "Set (%s) for entry %s under category %s: %d\n", newData, entryName, categoryName, retCode);
}

bool deleteDataFailure(const char *entryName, const char *categoryName)
{
    retCode = dv_deleteEntryData(&test_app, entryName, categoryName);
    return logTest(retCode == DV_INVALID_INPUT, "Delete non-existent %s for entry %s: %d\n", categoryName, entryName);
}

void printMetrics()
{
    printf("%d tests run, %d successes: %.2f%%\n", noTests, noSuccesses, (float)noSuccesses / (float)noTests * 100.0f);
}

void init()
{
    dv_init(&test_app);
}

void cleanup()
{
    dv_kill(&test_app);
}
