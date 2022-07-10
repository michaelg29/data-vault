#include "terminal.h"

#include "../../datavault.h"
#include "../../controller/dv_controller.h"
#include "../../lib/cmathematics/cmathematics.h"
#include "../../lib/ds/strstream.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

dv_app app;

bool getConfirmation(const char *msg)
{
    char res = ' ';

    while (!(res == 'y' || res == 'n' || res == 'N' || res == 'Y'))
    {
        printf("%s (Y/N)> ", msg);
        res = getchar();
    }

    return res == 'y' || res == 'Y';
}

const char *CMD_LOG = "log";
const char *CMD_QUIT = "quit";
const char *CMD_CREATE_ACCOUNT = "createAccount";
const char *CMD_LOGIN = "login";
const char *CMD_LOGOUT = "logout";
const char *CMD_CREATE_ENTRY = "create";
const char *CMD_SET = "set";
const char *CMD_GET = "get";
const char *CMD_DELETE = "del";

int processCommand(strstream *cmd)
{
    if (!(cmd && cmd->str && cmd->size))
    {
        return DV_INVALID_CMD;
    }

    // find initial word
    char **tokens = NULL;
    int n = strstream_split(cmd, ' ', &tokens, 2);
    if (!n || !tokens)
    {
        return DV_INVALID_CMD;
    }

    int retCode = DV_INVALID_CMD;

    // execute this block once but skip if needed
    do {
        // test first token
        if (!strcmp(tokens[0], CMD_QUIT))
        {
            if (getConfirmation("Are you sure you want to quit?")) {
                if (app.loggedIn) {
                    dv_logout(&app);
                }

                retCode = DV_QUIT;
            }
            else {
                retCode = DV_SUCCESS;
            }
        }
        else if (!strcmp(tokens[0], CMD_LOG))
        {
            dv_log(&app);
            retCode = DV_SUCCESS;
        }
        else if (!strcmp(tokens[0], CMD_CREATE_ACCOUNT))
        {
            if (n < 2)
            {
                // require password
                retCode = DV_INVALID_CMD;
                break;
            }

            printf("Create account with password (%d): \"%s\"\n", strlen(tokens[1]), tokens[1]);
            retCode = dv_createAccount(&app, tokens[1], strlen(tokens[1]));
        }
        else if (!strcmp(tokens[0], CMD_LOGIN))
        {
            if (n < 2)
            {
                // require password
                retCode = DV_INVALID_CMD;
                break;
            }

            printf("Login with password (%d): \"%s\"\n", strlen(tokens[1]), tokens[1]);
            retCode = dv_login(&app, tokens[1], strlen(tokens[1]));
        }
        else if (!strcmp(tokens[0], CMD_LOGOUT))
        {
            printf("Logging out\n");
            retCode = dv_logout(&app);
            printf("Done\n");
        }
        else if (!strcmp(tokens[0], CMD_CREATE_ENTRY))
        {
            if (n < 2)
            {
                // require name
                retCode = DV_INVALID_CMD;
                break;
            }

            printf("Create entry with name (%d): \"%s\"\n", strlen(tokens[1]), tokens[1]);
            retCode = dv_createEntry(&app, tokens[1]);
        }
        else if (!strcmp(tokens[0], CMD_SET))
        {
            if (n < 2)
            {
                // require more arguments
                retCode = DV_INVALID_CMD;
                break;
            }

            // split second token into: {name, category, data}
            char **args = NULL;
            strstream argstream = strstream_fromStr(tokens[1]);
            int argN = strstream_split(&argstream, ' ', &args, 3);

            if (argN < 3)
            {
                // require more arguments
                retCode = DV_INVALID_CMD;
            }
            else
            {
                printf("Setting data for %s under %s (%d): %s\n", args[0], args[1], strlen(args[2]), args[2]);
                retCode = dv_setEntryData(&app, args[0], args[1], args[2]);
            }

            strstream_clear(&argstream);
            freeStringList(args, argN);
        }
        else if (!strcmp(tokens[0], CMD_GET) || !strcmp(tokens[0], CMD_DELETE))
        {
            if (n < 2)
            {
                // require more arguments
                retCode = DV_INVALID_CMD;
                break;
            }

            // split second token into: {name, category}
            char **args = NULL;
            strstream argstream = strstream_fromStr(tokens[1]);
            int argN = strstream_split(&argstream, ' ', &args, 2);

            if (argN < 2)
            {
                // require more arguments
                retCode = DV_INVALID_CMD;
            }
            else if (!strcmp(tokens[0], CMD_GET))
            {
                printf("Accessing data for %s under %s\n", args[0], args[1]);
                char *out = NULL;
                retCode = dv_accessEntryData(&app, args[0], args[1], &out);
                printf("Retrieved: %s\n", out);
            }
            else
            {
                printf("Deleting data for %s under %s\n", args[0], args[1]);
                retCode = dv_deleteEntryData(&app, args[0], args[1]);
                printf("Deleted\n");
            }
        }
    } while (false);

    freeStringList(tokens, n);

    printf("Returns %d\n", retCode);

    return retCode;
}

void run()
{
    dv_init(&app);

    strstream cmd;
    int res = DV_SUCCESS;
    //DV_DEBUG = 1;

    while (res != DV_QUIT)
    {
        printf("> ");

        cmd = strstream_allocDefault();

        char ch;
        while ((ch = getchar()) != '\n')
        {
            strstream_concat(&cmd, "%c", ch);
        }

        res = processCommand(&cmd);
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
        };

        strstream_clear(&cmd);
    }

    strstream_clear(&cmd);

    if (app.loggedIn)
    {
        dv_logout(&app);
        printf("Logging out\n");
    }

    dv_kill(&app);
}