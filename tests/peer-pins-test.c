/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "peer-pins.h"
#include <stdio.h>
int main(int argc, char **argv)
{
    char identifier[65], fingerprint[72];
    int status;
    if (argc != 4 && argc != 6) return 2;
    status = argc == 6 ? barev_pin_save(argv[1], argv[2], argv[3], argv[4], argv[5])
        : barev_pin_load(argv[1], argv[2], argv[3], identifier, fingerprint);
    printf("%d\n", status);
    if (argc == 4 && status == BAREV_PIN_OK) printf("%s\n%s\n", identifier, fingerprint);
    return 0;
}
