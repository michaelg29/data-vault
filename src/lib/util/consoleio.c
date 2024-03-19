#include "consoleio.h"

#include <conio.h>
#include <stdio.h>

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

char *getMaskedInput(const char *prompt)
{
    strstream input = strstream_allocDefault();
    strstream masked = strstream_fromStr((char *)prompt);

    printf(masked.str);

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
