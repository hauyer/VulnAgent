#include <stdint.h>
#include <stdio.h>

/*
 * One source builds both the plain and the virtualized teaching fixtures.
 * The VM accepts only the fixed bytecode below: there is no external bytecode
 * input, code loading, anti-debugging, persistence, or network behavior.
 */

static uint32_t rotate_right(uint32_t value, unsigned int count) {
    count &= 31u;
    return (value >> count) | (value << ((32u - count) & 31u));
}

#if defined(USE_TEACHING_VM)

enum vm_opcode {
    VM_LOAD_IMMEDIATE = 0x10,
    VM_MULTIPLY_IMMEDIATE = 0x20,
    VM_XOR_IMMEDIATE = 0x30,
    VM_ROTATE_RIGHT = 0x40,
    VM_HALT = 0xff
};

__attribute__((used, section(".vmdata")))
static const char vm_identity[] = "VulnAgent Teaching VM";

__attribute__((used, section(".vmdata")))
static const char vm_dispatch_marker[] = "vm_dispatch";

__attribute__((used, section(".vcode")))
static const uint8_t vm_program[] = {
    VM_LOAD_IMMEDIATE, 0xea, 0x07, 0x00, 0x00,
    VM_MULTIPLY_IMMEDIATE, 0x21, 0x00, 0x00, 0x00,
    VM_XOR_IMMEDIATE, 0xa5, 0xa5, 0xa5, 0xa5,
    VM_ROTATE_RIGHT, 0x07,
    VM_HALT
};

static uint32_t read_u32(const uint8_t *program, size_t *pc) {
    uint32_t value = (uint32_t)program[*pc]
        | ((uint32_t)program[*pc + 1u] << 8u)
        | ((uint32_t)program[*pc + 2u] << 16u)
        | ((uint32_t)program[*pc + 3u] << 24u);
    *pc += 4u;
    return value;
}

__attribute__((noinline, section(".vdispat")))
static uint32_t vm_dispatch(void) {
    uint32_t accumulator = 0u;
    size_t pc = 0u;

    for (;;) {
        uint8_t opcode = vm_program[pc++];
        switch (opcode) {
            case VM_LOAD_IMMEDIATE:
                accumulator = read_u32(vm_program, &pc);
                break;
            case VM_MULTIPLY_IMMEDIATE:
                accumulator *= read_u32(vm_program, &pc);
                break;
            case VM_XOR_IMMEDIATE:
                accumulator ^= read_u32(vm_program, &pc);
                break;
            case VM_ROTATE_RIGHT:
                accumulator = rotate_right(accumulator, vm_program[pc++]);
                break;
            case VM_HALT:
                return accumulator;
            default:
                return 0u;
        }
    }
}

static uint32_t protected_score(void) {
    return vm_dispatch();
}

#else

static uint32_t protected_score(void) {
    uint32_t value = 2026u;
    value *= 33u;
    value ^= 0xa5a5a5a5u;
    return rotate_right(value, 7u);
}

#endif

int main(void) {
    printf("teaching-fixture score=%08x\n", protected_score());
    return 0;
}
