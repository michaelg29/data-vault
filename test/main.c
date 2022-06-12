#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/datavault.h"
#include "../src/controller/dv_controller.h"

int DV_DEBUG = 0;

int main()
{
    printf("Hello, world!\n");

    dv_app app;
    char *buf;
    int retCode;

    dv_init(&app);

    // printf("=====CREATE ACCOUNT=====\n");
    // retCode = dv_createAccount(&app, "test", 4);
    // printf("return %d\n", retCode);

    printf("=====LOGIN=====\n");
    retCode = dv_login(&app, "test", 4);
    printf("return %d\n", retCode);

    // printf("=====CREATE ENTRY=====\n");
    // retCode = dv_createEntry(&app, "GitHub");
    // printf("return %d\n", retCode);

    // printf("=====CREATE DATA1=====\n");
    // retCode = dv_createEntryData(&app, "GitHub", "username", "micha");
    // printf("return %d\n", retCode);

    // printf("=====CREATE DATA2=====\n");
    // retCode = dv_createEntryData(&app, "GitHub", "password", "micha2");
    // printf("return %d\n", retCode);

    DV_DEBUG = 1;
    printf("=====ACCESS DATA1=====\n");
    retCode = dv_accessEntryData(&app, "GitHub", "username", &buf);
    printf("return %d\n", retCode);
    if (!retCode)
        printf("%s\n", buf);

    printf("=====ACCESS DATA2=====\n");
    retCode = dv_accessEntryData(&app, "GitHub", "password", &buf);
    printf("return %d\n", retCode);
    if (!retCode)
        printf("%s\n", buf);

    printf("=====LOGOUT=====\n");
    retCode = dv_logout(&app);

    dv_kill(&app);

    printf("Goodbye, world!\n");

    return 0;
}