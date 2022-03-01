#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/datavault.h"
#include "../src/controller/dv_controller.h"

int DV_DEBUG = 1;

int main()
{
    printf("Hello, world!\n");

    dv_app app;

    dv_init(&app);

    printf("=====CREATE ACCOUNT=====\n");
    dv_createAccount(&app, "test", 4);

    printf("=====LOGIN=====\n");
    dv_login(&app, "test", 4);

    printf("=====CREATE ENTRY=====\n");
    dv_createEntry(&app, "GitHub");

    printf("=====CREATE DATA1=====\n");
    dv_createEntryData(&app, "GitHub", "username", "micha");

    printf("=====CREATE DATA2=====\n");
    dv_createEntryData(&app, "GitHub", "password", "micha");

    printf("=====LOGOUT=====\n");
    dv_logout(&app);

    dv_kill(&app);

    printf("Goodbye, world!\n");

    return 0;
}