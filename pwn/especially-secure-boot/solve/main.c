#include <stdio.h>
#include "esp_spi_flash.h"

void app_main()
{
    printf("secure boot bypassed!\n");

    char flag[0x100];
    spi_flash_read(0x133370, flag, 0x100);
    printf("Flag: %s\n", flag);

    fflush(stdout);
}
