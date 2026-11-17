/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "identity.h"
#include <stdio.h>

int main(int argc, char **argv)
{
    BarevIdentity identity;
    char identifier[65], fingerprint[72];
    int result;
    if (argc != 4) return 2;
    result = barev_identity_open(argv[1], argv[2], argv[3], &identity);
    printf("%d\n", result);
    if (!result) {
        if (!barev_identity_identifier(&identity, identifier) ||
            !barev_identity_fingerprint(&identity, fingerprint)) return 3;
        printf("%s\n%s\n", identifier, fingerprint);
    }
    barev_identity_clear(&identity);
    if (barev_identity_identifier(&identity, identifier) ||
        barev_identity_fingerprint(&identity, fingerprint)) return 4;
    return 0;
}
