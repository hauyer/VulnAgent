#include <stdio.h>

static int systematic_report(const char *value) {
    return printf("systematic-result:%s\n", value);
}

int main(int argc, char **argv) {
    return systematic_report(argc > 1 ? argv[1] : "none") < 0 ? 2 : 0;
}
