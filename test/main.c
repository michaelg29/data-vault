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

    dv_createAccount(&app, "test", 4);

    dv_kill(&app);

    return 0;
}