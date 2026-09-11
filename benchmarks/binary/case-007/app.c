#include <string.h>

int main(int argc, char **argv) {
    char buffer[16] = "prefix:";
    if (argc > 1) {
        strcat(buffer, argv[1]);
        return buffer[0];
    }
    return 0;
}
