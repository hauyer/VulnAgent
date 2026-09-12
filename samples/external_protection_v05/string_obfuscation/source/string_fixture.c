#include <stdint.h>
#include <stdio.h>

/*
 * Same-source string recovery fixture. The protected build keeps a Base64
 * ground-truth string for deterministic static recovery and an XOR-encrypted
 * byte array for a genuine runtime-decode example. No external input is used.
 */

#if defined(USE_STRING_OBFUSCATION)

__attribute__((used, section(".obfstr")))
static const char encoded_ground_truth[] =
    "VnVsbkFnZW50IGRldGVybWluaXN0aWMgc3RyaW5nIHJlY292ZXJ5IGZpeHR1cmUgMjAyNg==";

__attribute__((used, section(".obfstr")))
static const uint8_t encrypted_message[] = {
    0x0c, 0x2f, 0x36, 0x34, 0x1b, 0x3d, 0x3f, 0x34,
    0x2e, 0x7a, 0x3e, 0x3f, 0x2e, 0x3f, 0x28, 0x37,
    0x33, 0x34, 0x33, 0x29, 0x2e, 0x33, 0x39, 0x7a,
    0x29, 0x2e, 0x28, 0x33, 0x34, 0x3d, 0x7a, 0x28,
    0x3f, 0x39, 0x35, 0x2c, 0x3f, 0x28, 0x23, 0x7a,
    0x3c, 0x33, 0x22, 0x2e, 0x2f, 0x28, 0x3f, 0x7a,
    0x68, 0x6a, 0x68, 0x6c
};

__attribute__((used, section(".obfstr")))
static const char decoder_metadata[] = "xor_key=0x5a; algorithm=xor; purpose=teaching";

static void print_fixture_message(void) {
    char clear[sizeof(encrypted_message) + 1u];
    size_t index;

    for (index = 0u; index < sizeof(encrypted_message); ++index) {
        clear[index] = (char)(encrypted_message[index] ^ 0x5au);
    }
    clear[sizeof(encrypted_message)] = '\0';
    puts(clear);
}

#else

static void print_fixture_message(void) {
    puts("VulnAgent deterministic string recovery fixture 2026");
}

#endif

int main(void) {
    print_fixture_message();
    return 0;
}
