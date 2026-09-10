/* Local teaching sample. Build it only in an isolated course environment. */
#include <stdio.h>
#include <string.h>

int copy_name(const char *input) {
    char name[16];
    strcpy(name, input); /* intentionally unsafe for static inspection */
    return (int)name[0];
}

int main(int argc, char **argv) {
    return argc > 1 ? copy_name(argv[1]) : 0;
}
