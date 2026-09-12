/*
 * VulnAgent local-course adapter for google/fuzzing's fuzz_me.cc tutorial.
 *
 * The upstream function is included unchanged.  This small driver accepts the
 * bytes that VulnAgent sends on stdin and turns the tutorial predicate into a
 * controlled non-zero-exit oracle.  A raw abort can open Windows Error
 * Reporting and be misclassified as a timeout.  The strcpy call is
 * intentionally retained as a static audit signal; the course seed is short
 * and does not overflow this buffer.
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "fuzz_me.cc"

static volatile int audit_sink;

static void retain_static_audit_signal(const unsigned char *data, size_t size) {
    char source[64] = {0};
    char destination[64] = {0};
    size_t bounded = size < sizeof(source) - 1 ? size : sizeof(source) - 1;
    memcpy(source, data, bounded);
    source[bounded] = '\0';
    strcpy(destination, source);
    audit_sink = destination[0];
}

int main(void) {
    unsigned char input[4096] = {0};
    size_t size = fread(input, 1, sizeof(input), stdin);
    retain_static_audit_signal(input, size);

    if (FuzzMe(input, size)) {
        return 7;
    }
    return 0;
}
