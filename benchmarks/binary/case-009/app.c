#include <string.h>

static int strcpy_safely(char *destination, size_t capacity, const char *source) {
    size_t length = strlen(source);
    if (length >= capacity) {
        return 0;
    }
    memcpy(destination, source, length + 1);
    return 1;
}

int main(int argc, char **argv) {
    char buffer[16] = {0};
    return argc > 1 && strcpy_safely(buffer, sizeof(buffer), argv[1]) ? 0 : 1;
}
