#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/datavault.h"
#include "../src/controller/dv_controller.h"

int DV_DEBUG = 0;

dv_app app;
int retCode = 0;
char *buf = NULL;
unsigned int noTests = 0;
unsigned int noSuccesses = 0;

bool createAccount(const char *pwd)
{
    retCode = dv_createAccount(&app, (unsigned char*)pwd, strlen(pwd));
    printf("Create account with password %s: %d\n", pwd, retCode);
    noTests++;
    bool ret = retCode == DV_SUCCESS;
    noSuccesses += ret;
    return retCode;
}

bool login(const char *pwd)
{
    retCode = dv_login(&app, (unsigned char*)pwd, strlen(pwd));
    printf("Login with password %s: %d\n", pwd, retCode);
    noTests++;
    bool ret = retCode == DV_SUCCESS;
    noSuccesses += ret;
    return retCode;
}

bool loginFail(const char *pwd)
{
    retCode = dv_login(&app, (unsigned char*)pwd, strlen(pwd));
    printf("Fail login with password %s: %d\n", pwd, retCode);
    noTests++;
    bool ret = retCode == DV_INVALID_INPUT;
    noSuccesses += ret;
    return retCode;
}

bool logout()
{
    retCode = dv_logout(&app);
    printf("Logout: %d\n", retCode);
    noTests++;
    bool ret = retCode == DV_SUCCESS;
    noSuccesses += ret;
    return retCode;
}

bool createEntry(const char *entryName)
{
    retCode = dv_createEntry(&app, entryName);
    printf("Create entry with name %s: %d\n", entryName, retCode);
    noTests++;
    bool ret = retCode == DV_SUCCESS;
    noSuccesses += ret;
    return retCode;
}

bool createData(const char *entryName, const char *categoryName, const char *data)
{
    retCode = dv_createEntryData(&app, entryName, categoryName, data);
    printf("Create (%s) for entry %s under category %s: %d\n", data, entryName, categoryName, retCode);
    noTests++;
    bool ret = retCode == DV_SUCCESS;
    noSuccesses += ret;
    return retCode;
}

bool accessData(const char *entryName, const char *categoryName, const char *expected)
{
    retCode = dv_accessEntryData(&app, entryName, categoryName, &buf);
    bool matches = !strcmp((const char*)buf, expected);
    printf("Access %s for entry %s: %s: %d\n", categoryName, entryName, buf, retCode);
    free(buf);
    noTests++;
    bool ret = retCode == DV_SUCCESS && matches;
    noSuccesses += ret;
    return retCode;
}

bool accessDataFailure(const char *entryName, const char *categoryName)
{
    retCode = dv_accessEntryData(&app, entryName, categoryName, &buf);
    printf("Access non-existent %s for entry %s: %d\n", categoryName, entryName, retCode);
    free(buf);
    noTests++;
    bool ret = retCode == DV_SUCCESS;
    noSuccesses += ret;
    return retCode;
}

bool deleteData(const char *entryName, const char *categoryName)
{
    retCode = dv_deleteEntryData(&app, entryName, categoryName);
    printf("Delete %s for entry %s: %d\n", categoryName, entryName);
    noTests++;
    bool ret = retCode == DV_SUCCESS;
    noSuccesses += ret;
    return retCode;
}

bool deleteDataFailure(const char *entryName, const char *categoryName)
{
    retCode = dv_deleteEntryData(&app, entryName, categoryName);
    printf("Delete non-existent %s for entry %s: %d\n", categoryName, entryName);
    noTests++;
    bool ret = retCode == DV_SUCCESS;
    noSuccesses += ret;
    return retCode;
}

int main()
{
    printf("Hello, world!\n");

    dv_init(&app);

    createAccount("testPwd");
    loginFail("test");
    login("testPwd");
    logout();

    dv_kill(&app);

    printf("%d tests run, %d successes: %.2f%%\n", noTests, noSuccesses, (float)noSuccesses / (float)noTests * 100.0f);

    printf("Goodbye, world!\n");

    return 0;
}