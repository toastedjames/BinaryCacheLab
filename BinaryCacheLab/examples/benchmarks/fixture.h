#ifndef BCL_FIXTURE_H
#define BCL_FIXTURE_H
#include <stdint.h>
#include <stdio.h>
static int read_secret(int argc, char **argv) {
    if (argc != 2 || (argv[1][0] != '0' && argv[1][0] != '1') || argv[1][1] != '\0') {
        fputs("secret must be 0 or 1\n", stderr);
        return -1;
    }
    return argv[1][0] - '0';
}
#endif
