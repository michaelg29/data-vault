#include <stdio.h>
#include <stdlib.h>

#include "datavault.h"
#include "view/terminal/terminal.h"
#include "view/test/test.h"

int DV_TESTMODE = 0;

int main(int argc, char *argv[])
{
    int res = DV_SUCCESS;

    if (DV_TESTMODE)
    {
        printf("Testing");

        const char *GITHUB = "GitHub";
        const char *GOOGLE = "Google";
        const char *USERNAME = "Username";
        const char *PASSWORD = "Password";

        const char *GH_USER = "michaelg29";
        const char *GH_PWD = "gh_pwd";
        const char *GG_USER = "michaelgrieco27";
        const char *GG_PWD = "gg_pwd";
        const char *GG_PWD2 = "gg_pwd2";

        init();

        createAccount("test", "testPwd");
        loginFail("test", "test");

        if (login("test", "testPwd"))
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

        printMetrics();
        cleanup();

        res = DV_SUCCESS;
    }
    else if (argc > 1)
    {
        res = singleCmd(argc, argv);
    }
    else
    {
        res = terminal();
    }

    printf("Exiting with code %d\n", res);

    return res;
}