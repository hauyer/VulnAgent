#include <stdio.h>

typedef int (*format_function)(char *, const char *, ...);

static format_function choose_formatter(void) {
    return sprintf;
}

int main(int argc, char **argv) {
    char buffer[16];
    if (argc > 1) {
        format_function formatter = choose_formatter();
        return formatter(buffer, "%s", argv[1]) < 0 ? 2 : buffer[0];
    }
    return 0;
}
