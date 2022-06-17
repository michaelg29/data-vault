#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/datavault.h"
#include "../src/controller/dv_controller.h"

int DV_DEBUG = 0;
int retCode = 0;
dv_app app;
char *buf;

bool createAccount(const char *pwd)
{
    retCode = dv_createAccount(&app, pwd, strlen(pwd));
    printf("Create account: %d\n", retCode);
    return retCode == DV_SUCCESS;
}

bool login(const char *pwd)
{
    retCode = dv_login(&app, pwd, strlen(pwd));
    printf("Login with password %s: %d\n", pwd, retCode);
    return retCode == DV_SUCCESS;
}

bool logout()
{
    retCode = dv_logout(&app);
    printf("Logout: %d\n", retCode);
    return retCode == DV_SUCCESS;
}

bool createEntry(const char *entryName)
{
    retCode = dv_createEntry(&app, entryName);
    printf("Create entry with name %s: %d\n", entryName, retCode);
    return retCode == DV_SUCCESS;
}

bool createData(const char *entryName, const char *categoryName, const char *data)
{
    retCode = dv_createEntryData(&app, entryName, categoryName, data);
    printf("Create (%s) for entry %s under category %s: %d\n", data, entryName, categoryName, retCode);
    return retCode == DV_SUCCESS;
}

bool accessData(const char *entryName, const char *categoryName, const char *expected)
{
    retCode = dv_accessEntryData(&app, entryName, categoryName, &buf);
    bool matches = !strcmp((const char*)buf, expected);
    printf("Access %s for entry %s: %s: %d\n", categoryName, entryName, buf, retCode);
    free(buf);
    return retCode == DV_SUCCESS && matches;
}

bool accessDataFailure(const char *entryName, const char *categoryName)
{
    retCode = dv_accessEntryData(&app, entryName, categoryName, &buf);
    printf("Access non-existent %s for entry %s: %d\n", categoryName, entryName, retCode);
    free(buf);
    return retCode == DV_INVALID_INPUT;
}

bool deleteData(const char *entryName, const char *categoryName)
{
    retCode = dv_deleteEntryData(&app, entryName, categoryName);
    printf("Delete %s for entry %s: %d\n", categoryName, entryName);
    return retCode == DV_SUCCESS;
}

bool deleteDataFailure(const char *entryName, const char *categoryName)
{
    retCode = dv_deleteEntryData(&app, entryName, categoryName);
    printf("Delete non-existent %s for entry %s: %d\n", categoryName, entryName);
    return retCode == DV_INVALID_INPUT;
}

int main()
{
    printf("Hello, world!\n");

    dv_init(&app);

    dv_kill(&app);

    printf("Goodbye, world!\n");

    return 0;
}