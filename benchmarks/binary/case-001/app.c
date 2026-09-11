#include <string.h>

int main(int argc, char **argv) {
    char buffer[16];
    if (argc > 1) {
        strcpy(buffer, argv[1]);
        return buffer[0];
    }
    return 0;
}
