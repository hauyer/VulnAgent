#include <stdio.h>

static int sprintf_checked(char *destination, size_t capacity, const char *source) {
    return snprintf(destination, capacity, "%s", source);
}

int main(int argc, char **argv) {
    char buffer[16];
    if (argc > 1) {
        return sprintf_checked(buffer, sizeof(buffer), argv[1]) < 0 ? 2 : 0;
    }
    return 0;
}
