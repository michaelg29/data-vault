#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "../src/datavault.h"
#include "../src/view/terminal/terminal.h"
#include "../src/controller/dv_controller.h"

int DV_TESTMODE = 0;

dv_app app;
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

bool createAccount(const char *pwd)
{
    retCode = dv_createAccount(&app, (unsigned char*)pwd, strlen(pwd));
    return logTest(retCode == DV_SUCCESS, "Create account with password %s: %d\n", pwd, retCode);
}

bool login(const char *pwd)
{
    retCode = dv_login(&app, (unsigned char*)pwd, strlen(pwd));
    return logTest(retCode == DV_SUCCESS, "Login with password %s: %d\n", pwd, retCode);
}

bool loginFail(const char *pwd)
{
    retCode = dv_login(&app, (unsigned char*)pwd, strlen(pwd));
    return logTest(retCode == DV_INVALID_INPUT, "Fail login with password %s: %d\n", pwd, retCode);
}

bool logout()
{
    retCode = dv_logout(&app);
    return logTest(retCode == DV_SUCCESS, "Logout: %d\n", retCode);
}

bool createEntry(const char *entryName)
{
    retCode = dv_createEntry(&app, entryName);
    return logTest(retCode == DV_SUCCESS, "Create entry with name %s: %d\n", entryName, retCode);
}

bool createData(const char *entryName, const char *categoryName, const char *data)
{
    retCode = dv_createEntryData(&app, entryName, categoryName, data);
    return logTest(retCode == DV_SUCCESS, "Create (%s) for entry %s under category %s: %d\n", data, entryName, categoryName, retCode);
}

bool accessData(const char *entryName, const char *categoryName, const char *expected)
{
    retCode = dv_accessEntryData(&app, entryName, categoryName, &buf);
    bool matches = !strcmp((const char*)buf, expected);
    bool ret =  logTest(matches, "Access %s for entry %s: %s: %d\n", categoryName, entryName, buf, retCode);
    free(buf);
    return ret;
}

bool accessDataFailure(const char *entryName, const char *categoryName)
{
    retCode = dv_accessEntryData(&app, entryName, categoryName, &buf);
    bool ret = logTest(retCode == DV_INVALID_INPUT, "Access non-existent %s for entry %s: %d\n", categoryName, entryName, retCode);
    free(buf);
    return ret;
}

bool deleteData(const char *entryName, const char *categoryName)
{
    retCode = dv_deleteEntryData(&app, entryName, categoryName);
    return logTest(retCode == DV_SUCCESS, "Delete %s for entry %s: %d\n", categoryName, entryName, retCode);
}

bool modifyData(const char *entryName, const char *categoryName, const char *newData)
{
    retCode = dv_setEntryData(&app, entryName, categoryName, newData);
    return logTest(retCode == DV_SUCCESS, "Set (%s) for entry %s under category %s: %d\n", newData, entryName, categoryName, retCode);
}

bool deleteDataFailure(const char *entryName, const char *categoryName)
{
    retCode = dv_deleteEntryData(&app, entryName, categoryName);
    return logTest(retCode == DV_INVALID_INPUT, "Delete non-existent %s for entry %s: %d\n", categoryName, entryName);
}

int main()
{
    printf("Hello, world!\n");

    if (DV_TESTMODE)
    {
        const char *GITHUB = "GitHub";
        const char *GOOGLE = "Google";
        const char *USERNAME = "Username";
        const char *PASSWORD = "Password";

        const char *GH_USER = "michaelg29";
        const char *GH_PWD = "gh_pwd";
        const char *GG_USER = "michaelgrieco27";
        const char *GG_PWD = "gg_pwd";
        const char *GG_PWD2 = "gg_pwd2";

        dv_init(&app);

        createAccount("testPwd");
        loginFail("test");

        if (login("testPwd"))
        {
            createEntry(GITHUB);
            accessDataFailure(GITHUB, PASSWORD);
            createData(GITHUB, PASSWORD, GH_PWD);
            accessData(GITHUB, PASSWORD, GH_PWD);
            createEntry(GOOGLE);
            accessDataFailure(GOOGLE, PASSWORD);
            accessData(GITHUB, PASSWORD, GH_PWD);
            createData(GOOGLE, PASSWORD, GG_PWD);
            createData(GOOGLE, USERNAME, GG_USER);
            accessDataFailure(GITHUB, USERNAME);
            createData(GITHUB, USERNAME, GH_USER);
            accessData(GOOGLE, PASSWORD, GG_PWD);
            accessData(GOOGLE, USERNAME, GG_USER);
            deleteData(GOOGLE, USERNAME);
            accessDataFailure(GOOGLE, USERNAME);
            modifyData(GOOGLE, PASSWORD, GG_PWD2);
            accessData(GOOGLE, PASSWORD, GG_PWD2);
            modifyData(GOOGLE, USERNAME, GG_USER);
            accessData(GOOGLE, USERNAME, GG_USER);

            logout();
        }

        dv_kill(&app);

        printf("%d tests run, %d successes: %.2f%%\n", noTests, noSuccesses, (float)noSuccesses / (float)noTests * 100.0f);
    }
    else
    {
        run();
    }

    printf("Goodbye, world!\n");

    return 0;
}