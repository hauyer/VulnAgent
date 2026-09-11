#include <stdarg.h>
#include <stdio.h>

static int relay_format_bounded(
    char *destination,
    size_t capacity,
    const char *format,
    ...
) {
    va_list arguments;
    int written;
    va_start(arguments, format);
    written = vsnprintf(destination, capacity, format, arguments);
    va_end(arguments);
    return written;
}

int main(int argc, char **argv) {
    char buffer[16];
    if (argc > 1) {
        return relay_format_bounded(buffer, sizeof(buffer), "%s", argv[1]) < 0 ? 2 : 0;
    }
    return 0;
}
