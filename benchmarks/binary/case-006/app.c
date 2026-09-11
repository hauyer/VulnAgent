#include <stdio.h>

int main(int argc, char **argv) {
    char buffer[16];
    if (argc > 1) {
        int written = snprintf(buffer, sizeof(buffer), "%s", argv[1]);
        return written < 0 ? 3 : 0;
    }
    return 0;
}
