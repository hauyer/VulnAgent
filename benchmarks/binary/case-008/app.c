#include <stdio.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        return 0;
    }
    FILE *stream = popen(argv[1], "r");
    if (stream == NULL) {
        return 2;
    }
    return pclose(stream);
}
