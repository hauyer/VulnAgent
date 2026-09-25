/*
 * cp_parse — vulnerable variant (CWE-121 stack-based buffer overflow).
 *
 * parse_message() reads a 16-bit length prefix and copies that many bytes
 * into a fixed 8-byte stack buffer. The copy loop does not depend on the
 * input size, so a single mutated length byte immediately overflows.
 *
 * Only for authorized local dynamic analysis in the VulnAgent sandbox.
 */
#include <stdint.h>
#include <stddef.h>

int parse_message(const uint8_t *data, size_t size) {
    if (size < 2) {
        return -1;
    }
    uint16_t len = (uint16_t)(data[0] | ((uint16_t)data[1] << 8));
    char out[8];
    /* VULN: loop writes out[i] with i up to len-1; len may exceed 8 */
    for (size_t i = 0; i < len; i++) {
        uint8_t value = (size >= 3 + i) ? data[2 + i] : 0;
        out[i] = (char)value;  /* unbounded write -> stack-buffer-overflow */
    }
    return (int)(unsigned char)out[0] + (int)len;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    (void)parse_message(data, size);
    return 0;
}
