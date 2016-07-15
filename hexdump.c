/*

	Copyright (C) 2015 by Wilco Baan Hofman <wilco@baanhofman.nl>

	The hexdump function originated from
    https://stackoverflow.com/questions/7775991/how-to-get-hexdump-of-a-structure-data
	(Originally licensed WTFPL. Copyright (C) 2015 by paxdiablo).

    This file is part of Abusir

    Abusir is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Abusir is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Abusir.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdio.h>
#include <stdint.h>


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
