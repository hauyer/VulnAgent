#include <stdint.h>
#include <stdio.h>
#include <string.h>

/*
 * Benign, deterministic fixture for packer detection and unpacking tests.
 * It performs no file, process, registry, or network operations.
 */
static uint32_t rolling_checksum(const unsigned char *data, size_t length) {
    uint32_t state = 0x13579bdfu;
    size_t i;

    for (i = 0; i < length; ++i) {
        state ^= (uint32_t)data[i];
        state = (state << 5) | (state >> 27);
        state += 0x9e3779b9u;
    }
    return state;
}

int main(int argc, char **argv) {
    const char *text = argc > 1 ? argv[1] : "VulnAgent-baseline-fixture";
    uint32_t value = rolling_checksum((const unsigned char *)text, strlen(text));

    printf("benign-fixture checksum=%08x\n", value);
    return 0;
}
