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

void printHelp()
{
    printf("Data Vault.\n");

    printf("\nUsage:\n");
    printf("  dv\n");
    printf("  dv -h | --help\n");
    printf("  dv [-u <USERNAME>] [-penv <PASSWORD_ENV_NAME>] createAct\n");
    printf("  dv [-u <USERNAME>] [-penv <PASSWORD_ENV_NAME>] <DATA_COMMAND>\n");

    printf("\nOptions:\n");
    printf("  -h --help   Show this screen.\n");
    printf("  -u          Username of existing account. Prompted if not entered.\n");
    printf("  -penv       Name of environment variable containing the password. Prompted for password if not entered.\n");
    printf("  createAct   Create an account.\n");
    printf("  If no options specified, opens a continuous terminal session.\n");

    printf("\nData commands:\n");
    printf("  exit                             Quit the application.\n");
    printf("  clear|cls                        Clear the terminal screen.\n");
    printf("  debug                            Switch on debugging information.\n");
    printf("  logout                           Logout the current user.\n");
    printf("  log                              Print all the entries and categories for the current user.\n");
    printf("  print                            Print the encrypted and decrypted data file contents.\n");
    printf("  createAct                        Create an account. Prompted for username and password.\n");
    printf("  login                            Login to an existing account. Prompted for username and password.\n");
    printf("  create <entry>                   Create an entry.\n");
    printf("  get <entry> <category>           Get the data for an entry under a category.\n");
    printf("  copy <entry> <category>          Put the data for an entry under a category onto the clipboard.\n");
    printf("  del <entry> <category>           Delete the data for an entry under a category.\n");
    printf("  set <entry> <category> [<data>]  Set the data for an entry under a category. Prompted for data if not entered in the command.\n");
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

#define TOKEN_EQ(cmd) !strcmp(tokens[0], cmd)

        retCode = DV_SUCCESS;

        // commands with no arguments
        if (TOKEN_EQ("-h") || TOKEN_EQ("--help"))
        {
            printHelp();
        }
        else if (TOKEN_EQ("exit"))
        {
            if (!getConfirmation("Are you sure you want to quit?"))
            {
                break;
            }

            if (app.loggedIn)
            {
                dv_logout(&app);
            }

            retCode = DV_EXIT;
        }
        else if (TOKEN_EQ("cls") || TOKEN_EQ("clear"))
        {
            system("cls");
        }
        else if (TOKEN_EQ("debug"))
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
        else if (TOKEN_EQ("logout"))
        {
            printf("Logging out\n");
            retCode = dv_logout(&app);
        }
        else if (TOKEN_EQ("log"))
        {
            dv_log(&app);
        }
        else if (TOKEN_EQ("print"))
        {
            dv_printDataFile(&app);
        }
        else if (TOKEN_EQ("createAct"))
        {
            char *user = getMaskedInput("USERNAME> ");
            char *pwd = getMaskedInput("PASSWORD> ");
            retCode = dv_createAccount(&app, user, pwd, strlen(pwd));
            free(pwd);
        }
        else if (TOKEN_EQ("login"))
        {
            char *user = getMaskedInput("USERNAME> ");
            char *pwd = getMaskedInput("PASSWORD> ");
            retCode = dv_login(&app, user, pwd, strlen(pwd));
            free(pwd);
        }

        // commands with one argument
        else if (n < 2)
        {
            retCode = DV_INVALID_CMD;
        }
        else if (TOKEN_EQ("create"))
        {
            printf("Create entry with name (%d): \"%s\"\n", strlen(tokens[1]), tokens[1]);
            retCode = dv_createEntry(&app, tokens[1]);
        }

        // commands with two arguments
        else if (argN < 2)
        {
            retCode = DV_INVALID_CMD;
        }
        else if (TOKEN_EQ("get"))
        {
            printf("Accessing data for %s under %s\n", argTokens[0], argTokens[1]);
            char *out = NULL;
            retCode = dv_accessEntryData(&app, argTokens[0], argTokens[1], &out);
            printf("Retrieved: %s\n", out);
            free(out);
        }
        else if (TOKEN_EQ("copy"))
        {
            printf("Copy data for %s under %s\n", argTokens[0], argTokens[1]);
            char *out = NULL;
            retCode = dv_accessEntryData(&app, argTokens[0], argTokens[1], &out);

            if (!retCode)
            {
                strstream envStream = strstream_fromStr("dv-env=");

                // set environment variable
                strstream_concat(&envStream, out);
                putenv(envStream.str);
                strstream_clear(&envStream);

                // copy to clipboard
                char cmd[28];
                sprintf(cmd, "echo|set /p=\"%%dv-env%%\"|clip");
                system((const char*)cmd);

                // clear environment variable
                putenv("dv-env=");

                free(out);
            }
        }
        else if (TOKEN_EQ("del"))
        {
            printf("Deleting data for %s under %s\n", argTokens[0], argTokens[1]);
            retCode = dv_deleteEntryData(&app, argTokens[0], argTokens[1]);
        }
        else if (TOKEN_EQ("set") && argN == 2)
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
        else if (TOKEN_EQ("set"))
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

int terminal()
{
    printf("Hello, terminal\n");
    system("cls");

    dv_init(&app);

    strstream cmd;
    int res = DV_SUCCESS;

    while (res != DV_EXIT)
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

    return dv_kill(&app);
}

int singleCmd(int argc, char **argv)
{
    strstream cmd;
    int res = DV_SUCCESS;

    bool freeUser = false;
    char *user = NULL;
    char *pwd = NULL;

    do
    {
        int i = 1;
#define ARGV_EQ(cmd) !strcmp(argv[i], cmd)

        if (i < argc && (ARGV_EQ("-h") || ARGV_EQ("--help")))
        {
            printHelp();
            break;
        }

        dv_init(&app);

        // find username
        if (i < argc - 1 && ARGV_EQ("-u"))
        {
            // username in command
            user = argv[i + 1];
            i += 2;
        }
        else
        {
            // did not enter username
            user = getMaskedInput("USERNAME> ");
            freeUser = true;
        }

        // find password
        if (i < argc - 1 && ARGV_EQ("-penv"))
        {
            // get password through environment variable
            pwd = getenv(argv[i + 1]);
            i += 2;
        }
        if (!pwd)
        {
            // did not enter password
            pwd = getMaskedInput("PASSWORD> ");
        }

        // determine if we want to create an account
        if (ARGV_EQ("-createAct"))
        {
            res = dv_createAccount(&app, user, pwd, strlen(pwd));
            if (res)
            {
                printf("Could not create account\n");
                break;
            }
            ++i;
        }

        // determine if there is in fact a command
        if (i >= argc)
        {
            break;
        }

        // construct login command
        res = dv_login(&app, user, pwd, strlen(pwd));
        free(pwd);
        if (res)
        {
            printf("Could not login\n");
            break;
        }

        printf("Logged in\n");

        // construct data command
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

    res = dv_kill(&app);

    return res;
}