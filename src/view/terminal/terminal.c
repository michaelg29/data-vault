#include "terminal.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../../datavault.h"
#include "../../controller/dv_controller.h"
#include "../../lib/cmathematics/cmathematics.h"
#include "../../lib/ds/strstream.h"

dv_app app;
int DV_DEBUG = 0;

bool getConfirmation(const char *msg)
{
    char res = ' ';

    while (!(res == 'y' || res == 'n'))
    {
        printf("%s (y/n)> ", msg);
        res = getchar();
    }

    return res == 'y';
}

int processCommand(strstream *cmd)
{
    int retCode = DV_INVALID_CMD;

    do
    {
        if (!(cmd && cmd->str && cmd->size))
        {
            break;
        }

        // split command into keyword and arguments
        char **tokens = NULL;
        int n = strstream_split(cmd, ' ', &tokens, 2);
        if (!(n && tokens))
        {
            break;
        }

        strstream argstream;
        char **argTokens = NULL;
        int argN = 0;
        if (n > 1)
        {
            // parse arguments
            argstream = strstream_fromStr(tokens[1]);
            argN = strstream_split(&argstream, ' ', &argTokens, 3);
        }

#define STREQ(cmd) !strcmp(tokens[0], cmd)

        retCode = DV_SUCCESS;

        // commands with no arguments
        if (STREQ("quit"))
        {
            if (!getConfirmation("Are you sure you want to quit?"))
            {
                break;
            }

            if (app.loggedIn)
            {
                dv_logout(&app);
            }
            retCode = DV_QUIT;
        }
        else if (STREQ("cls"))
        {
            system("cls");
        }
        else if (STREQ("debug"))
        {
            DV_DEBUG = !DV_DEBUG;
            if (DV_DEBUG)
            {
                printf("Turned on debugging\n");
            }
            else
            {
                printf("Turned off debugging\n");
            }
        }
        else if (STREQ("logout"))
        {
            printf("Logging out\n");
            retCode = dv_logout(&app);
        }
        else if (STREQ("log"))
        {
            dv_log(&app);
        }
        else if (STREQ("print"))
        {
            dv_printDataFile(&app);
        }

        // commands with one argument
        else if (n < 2)
        {
            retCode = DV_INVALID_CMD;
        }
        else if (STREQ("createAct"))
        {
            printf("Create account with password (%d): \"%s\"\n", strlen(tokens[1]), tokens[1]);
            retCode = dv_createAccount(&app, tokens[1], strlen(tokens[1]));
        }
        else if (STREQ("login"))
        {
            printf("Logging in with password (%d): \"%s\"\n", strlen(tokens[1]), tokens[1]);
            retCode = dv_login(&app, tokens[1], strlen(tokens[1]));
        }
        else if (STREQ("create"))
        {
            printf("Create entry with name (%d): \"%s\"\n", strlen(tokens[1]), tokens[1]);
            retCode = dv_createEntry(&app, tokens[1]);
        }

        // commands with two arguments
        else if (argN < 2)
        {
            retCode = DV_INVALID_CMD;
        }
        else if (STREQ("get"))
        {
            printf("Accessing data for %s under %s\n", argTokens[0], argTokens[1]);
            char *out = NULL;
            retCode = dv_accessEntryData(&app, argTokens[0], argTokens[1], &out);
            printf("Retrieved: %s\n", out);
            free(out);
        }
        else if (STREQ("del"))
        {
            printf("Deleting data for %s under %s\n", argTokens[0], argTokens[1]);
            retCode = dv_deleteEntryData(&app, argTokens[0], argTokens[1]);
        }

        // commands with three arguments
        else if (argN < 3)
        {
            retCode = DV_INVALID_CMD;
        }
        else if (STREQ("set"))
        {
            printf("Setting data for %s under %s: %s\n", argTokens[0], argTokens[1], argTokens[2]);
            retCode = dv_setEntryData(&app, argTokens[0], argTokens[1], argTokens[2]);
        }

        freeStringList(tokens, n);
        if (argTokens)
        {
            freeStringList(argTokens, argN);
            if (argstream.str)
            {
                strstream_clear(&argstream);
            }
        }
    } while (false);

    return retCode;
}

void terminal()
{
    printf("Hello, terminal\n");
    system("cls");

    dv_init(&app);

    strstream cmd;
    int res = DV_SUCCESS;

    while (res != DV_QUIT)
    {
        printf("> ");

        // get command
        cmd = strstream_allocDefault();
        char ch;
        while ((ch = getchar()) != '\n')
        {
            strstream_concat(&cmd, "%c", ch);
        }

        // process command
        res = processCommand(&cmd);

        // prepare for next command
        switch (res)
        {
        case DV_INVALID_CMD:
            printf("Invalid command\n");
            break;
        case DV_SUCCESS:
            printf("Success\n");
            break;
        case DV_INVALID_INPUT:
            printf("Invalid input\n");
            break;
        default:
            printf("Error code: %d\n", res);
            break;
        }
        strstream_clear(&cmd);
    }

    dv_kill(&app);
}

void singleCmd(int argc, char **argv)
{
    printf("Hello, terminal\n");
    system("cls");

    dv_init(&app);

    strstream cmd;
    int res = DV_SUCCESS;

    do
    {
        // construct login command
        cmd = strstream_fromStr("login ");
        strstream_concat(&cmd, "%s", argv[1]);
        // process command
        res = processCommand(&cmd);
        if (res)
        {
            printf("Could not login\n");
            break;
        }

        printf("Logged in\n");

        // construct data command
        strstream_clear(&cmd);
        cmd = strstream_fromStr(argv[2]);
        for (int i = 3; i < argc; i++)
        {
            strstream_concat(&cmd, " %s", argv[i]);
        }
        printf("Executing command: %s\n", cmd.str);
        res = processCommand(&cmd);
        // prepare for next command
        switch (res)
        {
        case DV_INVALID_CMD:
            printf("Invalid command\n");
            break;
        case DV_SUCCESS:
            printf("Success\n");
            break;
        case DV_INVALID_INPUT:
            printf("Invalid input\n");
            break;
        default:
            printf("Error code: %d\n", res);
            break;
        }

        // construct logout command
        strstream_clear(&cmd);
        cmd = strstream_fromStr("logout");
        // process command
        res = processCommand(&cmd);
    } while (false);
    strstream_clear(&cmd);

    dv_kill(&app);
}