/*
 * cp_parse — fixed variant (same interface, bounds check added).
 *
 * parse_message() rejects payloads longer than the destination buffer.
 * Used as the paired fixed build for the WP4 crash/fixed-outcome contrast.
 */
#include <stdint.h>
#include <stddef.h>

int parse_message(const uint8_t *data, size_t size) {
    if (size < 2) {
        return -1;
    }
    uint16_t len = (uint16_t)(data[0] | ((uint16_t)data[1] << 8));
    char out[8];
    if (len > sizeof(out)) {  /* FIX: bound the copy before writing */
        return -2;
    }
    for (size_t i = 0; i < len; i++) {
        uint8_t value = (size >= 3 + i) ? data[2 + i] : 0;
        out[i] = (char)value;
    }
    return (int)(unsigned char)out[0] + (int)len;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    (void)parse_message(data, size);
    return 0;
}
