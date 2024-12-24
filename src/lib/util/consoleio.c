#include "consoleio.h"

#include "../../datavault.h"

#include <stdio.h>
#ifdef DV_WINDOWS
    #include <conio.h>
#else
    #include <termios.h>
#endif

#include "../ds/strstream.h"

char getConfirmation(const char *prompt)
{
    char res = ' ';

    while (!(res == 'y' || res == 'n'))
    {
        printf("%s (y/n)> ", prompt);
        res = getchar();
    }

    return res == 'y';
}

#ifdef DV_WINDOWS
char *getMaskedInput(const char *prompt)
{
    strstream input = strstream_allocDefault();
    strstream masked = strstream_fromStr((char *)prompt);

    printf("%s", masked.str);

    char ch = getch();
    while (ch != 13 && ch != 3) // end when the character is a end of line
    {
        // backspace
        if (ch == 8 && input.size)
        {
            strstream_retreat(&input, 1);
            strstream_concat(&masked, "\b \b");
        }
        else if (ch >= 32 && ch <= 126)
        {
            strstream_concat(&input, "%c", ch);
            strstream_concat(&masked, "*");
        }

        printf("\r%s", masked.str);

        ch = getch();
    }

    strstream_clear(&masked);

    printf("\n");
    return input.str;
}

#else

//////////////////////////////
///// Control stdin echo /////
//////////////////////////////

struct termios oldt;
struct termios newt;
char newTermiosReset = 1;

void turnStdinEchoOff() {
    if (newTermiosReset) {
        // get current settings
        tcgetattr(0, &oldt);
        newt = oldt;

        // turn off echo
        newt.c_lflag &= ~(ICANON | ECHO);

        newTermiosReset = 0;
    }

    tcsetattr(0, TCSANOW, &newt);
}

void turnStdinEchoOn() {
    tcsetattr(0, TCSANOW, &oldt);
}

char *getMaskedInput(const char *prompt)
{
    strstream input = strstream_allocDefault();
    strstream masked = strstream_fromStr((char *)prompt);

    printf("%s", masked.str);
    fflush(stdout);
    fflush(stdin);

    turnStdinEchoOff();
    char ch = getchar();
    while (!(ch == 13 || ch == 3 || ch == 10)) // end when the character is a end of line
    {
        //printf("Character %d\n", ch);
        // backspace
        if (ch == 8 && input.size)
        {
            strstream_retreat(&input, 1);
            strstream_concat(&masked, "\b \b");
        }
        else if (ch >= 32 && ch <= 126)
        {
            strstream_concat(&input, "%c", ch);
            strstream_concat(&masked, "*");
        }

        printf("\r%s", masked.str);
        fflush(stdout);
        fflush(stdin);

        ch = getchar();
        fflush(stdout);
        fflush(stdin);
    }

    strstream_clear(&masked);
    turnStdinEchoOn();

    printf("\n");
    return input.str;
}
#endif
