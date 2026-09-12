/*
 * VulnAgent local-course adapter for the upstream AFL training quickstart.
 *
 * The upstream source is included unchanged.  Its main function is renamed so
 * this adapter can normalize ordinary parser errors to exit code 0.  That is
 * important because VulnAgent V0.4 currently treats every non-zero process
 * exit as an abnormal-exit signal.  The upstream "surprise!" condition is
 * converted to a controlled exit code so Windows Error Reporting cannot turn
 * the classroom demonstration into a timeout or an interactive crash dialog.
 */

#define main afl_training_upstream_main
#include "vulnerable.c"
#undef main

int main(void) {
    char input[INPUTSIZE] = {0};
    size_t length = fread(input, 1, INPUTSIZE - 2, stdin);

    /* The browser field is single-line, while the upstream oracle expects LF. */
    if (length > 0 && input[length - 1] != '\n') {
        input[length++] = '\n';
        input[length] = '\0';
    }

    if (strcmp(input, "surprise!\n") == 0) {
        return 7;
    }

    (void)process(input);
    return 0;
}
