#include <stdarg.h>
#include <stdio.h>

static int relay_format(char *destination, const char *format, ...) {
    va_list arguments;
    int written;
    va_start(arguments, format);
    written = vsprintf(destination, format, arguments);
    va_end(arguments);
    return written;
}

int main(int argc, char **argv) {
    char buffer[16];
    if (argc > 1) {
        return relay_format(buffer, "%s", argv[1]) < 0 ? 2 : buffer[0];
    }
    return 0;
}
