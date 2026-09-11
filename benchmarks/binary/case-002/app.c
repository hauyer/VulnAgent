#include <stdlib.h>

int main(int argc, char **argv) {
    return argc > 1 ? system(argv[1]) : 0;
}
