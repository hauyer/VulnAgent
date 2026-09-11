#include <stdio.h>

int main(int argc, char **argv) {
    char buffer[16];
    if (argc > 1) {
        sprintf(buffer, "%s", argv[1]);
        return buffer[0];
    }
    return 0;
}
