#include <string.h>

int main(int argc, char **argv) {
    char buffer[16] = {0};
    if (argc > 1) {
        size_t length = strlen(argv[1]);
        if (length >= sizeof(buffer)) {
            return 2;
        }
        memcpy(buffer, argv[1], length);
        return buffer[0];
    }
    return 0;
}
