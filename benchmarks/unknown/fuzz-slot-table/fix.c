/*
 * slot_table — fixed variant (same interface as vuln.c).
 *
 * The compaction copy now respects the slot width (8 bytes per record),
 * so writes never straddle the slot boundary.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint32_t count;
    uint8_t *slots;
} table_t;

static int parse_table(const uint8_t *data, size_t size, table_t *t) {
    if (size < 2) {
        return -1;
    }
    t->count = (uint32_t)(data[0] | ((uint32_t)data[1] << 8));
    if (t->count > 4096) {
        t->count = 4096;
    }
    size_t cap = (size_t)t->count * 8;
    t->slots = (uint8_t *)malloc(cap);
    if (!t->slots) {
        return -1;
    }
    size_t off = 2;
    for (uint32_t i = 0; i < t->count; i++) {
        if (off + 8 > size) {
            break;
        }
        memcpy(t->slots + (size_t)i * 8, data + off, 8);
        off += 8;
    }
    return 0;
}

static void free_table(table_t *t) {
    free(t->slots);
    t->slots = NULL;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    table_t t = {0, NULL};
    if (parse_table(data, size, &t) == 0) {
        (void)t.count;
    }
    free_table(&t);
    return 0;
}
