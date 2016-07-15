#include <stdio.h>
#include <stdint.h>

/*
 * I'm too lazy to write yet another hexdump function, so I took this 
 * function from stackoverflow:
 *
 * https://stackoverflow.com/questions/7775991/how-to-get-hexdump-of-a-structure-data
 */

void hexdump (const char *desc, const void *addr, unsigned int len) {
    unsigned int i;
    char buff[17] = "";
    uint8_t *pc = (uint8_t*)addr;

    // Output description if given.
    if (desc != NULL)
        printf ("%s:\n", desc);

    if (len == 0) {
        printf("  ZERO LENGTH\n");
        return;
    }

    for (i = 0; i < len; i++) {
        if ((i % 16) == 0) {
            if (i != 0)
                printf ("  %s\n", buff);

            printf ("  %04x ", i);
        }

        printf (" %02x", (unsigned int)pc[i]);

        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = (char)pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }

    printf ("  %s\n", buff);
}
