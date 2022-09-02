#include "terminal.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../../datavault.h"
#include "../../controller/dv_controller.h"
#include "../../controller/dv_persistence.h"
#include "../../lib/cmathematics/cmathematics.h"
#include "../../lib/ds/strstream.h"
#include "../../lib/util/consoleio.h"
#include "../../lib/util/fileio.h"

dv_app app;
int DV_DEBUG = 0;

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
        else if (STREQ("createAct"))
        {
            char *pwd = getMaskedInput("PASSWORD> ");
            retCode = dv_createAccount(&app, pwd, strlen(pwd));
            free(pwd);
        }
        else if (STREQ("login"))
        {
            char *pwd = getMaskedInput("PASSWORD> ");
            retCode = dv_login(&app, pwd, strlen(pwd));
            free(pwd);
        }

        // commands with one argument
        else if (n < 2)
        {
            retCode = DV_INVALID_CMD;
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
        else if (STREQ("set") && argN == 2)
        {
            // set data as masked input
            char *data = getMaskedInput("ENTER DATA> ");
            retCode = dv_setEntryData(&app, argTokens[0], argTokens[1], data);
            free(data);
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
    dv_init(&app);

    strstream cmd;
    int res = DV_SUCCESS;

    char *user = NULL;
    strstream userDir = strstream_fromStr("./");

    do
    {
        int i = 1;

        // find username
        bool freeUser = false;
        if (i >= argc || strcmp(argv[i], "-u"))
        {
            // did not enter username
            user = getMaskedInput("USERNAME> ");
            freeUser = true;
        }
        else
        {
            // username in command
            user = argv[i + 1];
            i += 2;
        }

        // copy files to main directory
        bool forceCreate = false;
        strstream_concat(&userDir, user);
        if (directoryExists(userDir.str))
        {
            dv_copyFiles(NULL, user);
        }
        else
        {
            printf("Could not find user\n");
            
            if (getConfirmation("Would you like to create a directory for this user?"))
            {
                forceCreate = true;
                strstream dirCmd = strstream_fromStr("mkdir ");
                strstream_concat(&dirCmd, user);
                system(dirCmd.str);
            }
            else
            {
                break;
            }
        }

        // find password
        char *pwd = NULL;
        bool freePwd = false;
        if (i < argc)
        {
            if (i < argc - 1 && !strcmp(argv[i], "-p"))
            {
                // password in command
                pwd = argv[i + 1];
                i += 2; // command starts after password
            }
            if (!strcmp(argv[i], "-penv"))
            {
                // get password through environment variable
                pwd = getenv(argv[i + 1]);
                i += 2;
            }
        }
        if (i >= argc || !pwd)
        {
            // did not enter password
            pwd = getMaskedInput("PASSWORD> ");
            freePwd = true;
        }

        // determine if we want to create an account
        if (forceCreate || !strcmp(argv[i], "createAct"))
        {
            printf("Creating account\n");
            res = dv_createAccount(&app, pwd, strlen(pwd));
            if (res)
            {
                printf("Could not create account\n");
                break;
            }
            if (!forceCreate)
            {
                ++i;
            }
        }

        // determine if there is in fact a command
        if (i >= argc)
        {
            break;
        }

        // construct login command
        res = dv_login(&app, pwd, strlen(pwd));
        if (freePwd)
        {
            free(pwd);
        }
        if (res)
        {
            printf("Could not login\n");
            break;
        }

        printf("Logged in\n");

        // construct data command
        strstream_clear(&cmd);
        cmd = strstream_fromStr(argv[i++]);
        for (; i < argc; i++)
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

    // copy files back to user directory
    if (user)
    {
        dv_copyFiles(user, NULL);
        dv_deleteFiles();
    }

    dv_kill(&app);
}