/*
    Copyright (C) 2016 by Wilco Baan Hofman <wilco@baanhofman.nl>

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

#define _GNU_SOURCE
#include <stddef.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/if_ether.h>
#include <linux/filter.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <stdbool.h>
int open_icmpv6_socket(void) {
	int sock;
	int err;
	struct sock_fprog fprog;

	/*
	   IPv6 BPF with Hop-by-Hop, destination and routing options, mobility,
       authentication headers and fragmentation support

	   For BPF, see the FreeBSD manpage at
       https://www.freebsd.org/cgi/man.cgi?query=bpf&sektion=4&manpath=FreeBSD+4.7-RELEASE

     */

	/* Because loops are not supported, I need to get router advertisements, plus all
       fragments, authentication headers, routing, destination options, hop options and
       mobility headers, which I need to filter in the application.
     */
	static const struct sock_filter filter[] = {
		BPF_STMT(BPF_LD|BPF_B|BPF_ABS, offsetof(struct ip6_hdr, ip6_nxt)),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, IPPROTO_ICMPV6, 6, 0),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, IPPROTO_FRAGMENT, 7, 0),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, IPPROTO_AH, 6, 0),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, IPPROTO_ROUTING, 5, 0),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, IPPROTO_DSTOPTS, 4, 0),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, IPPROTO_HOPOPTS, 3, 0),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, IPPROTO_MH, 2, 3),

		// If ICMPv6 without extension headers, grab only router advertisements
		BPF_STMT(BPF_LD|BPF_B|BPF_ABS, sizeof(struct ip6_hdr)),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, ND_ROUTER_ADVERT, 0, 1),
		// accept
		BPF_STMT(BPF_RET|BPF_K, 0xffffffff),
		// drop
		BPF_STMT(BPF_RET|BPF_K, 0),
	};

/* Not supported because backward jumps are not accepted by the kernel.
   Otherwise a good implementation for IPv6 in BPF.
   For now, this is disabled until a eBPF is extended with an opcode that would work for this.
 */
#if 0
	static const struct sock_filter filter[] = {
		// Load the next header type in a
		BPF_STMT(BPF_LD|BPF_B|BPF_ABS, offsetof(struct ip6_hdr, ip6_nxt)),

		// Initialize the memory M[1]: is_fragment (2 instructions)
		BPF_STMT(BPF_LD|BPF_IMM, false),
		BPF_STMT(BPF_ST|BPF_K, 1),

		// Load the next header offset in x (1 instruction)
		BPF_STMT(BPF_LDX|BPF_IMM, sizeof(struct ip6_hdr)),

		// Jump table, relative offsets (number of instructions to jump) (8 instructions)
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, IPPROTO_ICMPV6, 34, 0),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, IPPROTO_NONE, 38, 0),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, IPPROTO_FRAGMENT, 23, 0),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, IPPROTO_AH, 13, 0),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, IPPROTO_ROUTING, 3, 0),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, IPPROTO_DSTOPTS, 2, 0),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, IPPROTO_HOPOPTS, 1, 0),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, IPPROTO_MH, 0, 32), // False jumps straight to ret #0

		// Hop-by-Hop Options / Destination / Routing / Mobility headers (9 instructions)
		BPF_STMT(BPF_LD|BPF_B|BPF_IND, 0),             // ldb [x+0]
		BPF_STMT(BPF_ST|BPF_K, 0),                     // st M[0]
		BPF_STMT(BPF_LD|BPF_B|BPF_IND, 1),             // ldb [x+1]
		BPF_STMT(BPF_ALU|BPF_ADD|BPF_K, 1),            // add #1
		BPF_STMT(BPF_ALU|BPF_MUL|BPF_K, 8),            // mul #8
		BPF_STMT(BPF_ALU|BPF_ADD|BPF_X, 0),            // add x
		BPF_STMT(BPF_MISC|BPF_TAX, 0),                 // tax
		BPF_STMT(BPF_LD|BPF_MEM, 0),                   // ld M[0]
		BPF_STMT(BPF_JMP|BPF_JA, -17),                 // ja 4 (to jump table)

		// Authentication header (9 instructions)
		BPF_STMT(BPF_LD|BPF_B|BPF_IND, 0),             // ldb [x+0]
		BPF_STMT(BPF_ST|BPF_K, 0),                     // st M[0]
		BPF_STMT(BPF_LD|BPF_B|BPF_IND, 1),             // ldb [x+1]
		BPF_STMT(BPF_ALU|BPF_ADD|BPF_K, 2),            // add #2
		BPF_STMT(BPF_ALU|BPF_MUL|BPF_K, 4),            // mul #4
		BPF_STMT(BPF_ALU|BPF_ADD|BPF_X, 0),            // add x
		BPF_STMT(BPF_MISC|BPF_TAX, 0),                 // tax
		BPF_STMT(BPF_LD|BPF_MEM, 0),                   // ld M[0]
		BPF_STMT(BPF_JMP|BPF_JA, -26),                 // ja 4 (to jump table)

		// Fragment (9 instructions)
		BPF_STMT(BPF_LD|BPF_B|BPF_IND, 0),             // ldb [x+0]
		BPF_STMT(BPF_ST|BPF_K, 0),                     // st M[0]
		BPF_STMT(BPF_LD|BPF_IMM, 8),                   // ldb #8
		BPF_STMT(BPF_ALU|BPF_ADD|BPF_X, 0),            // add x
		BPF_STMT(BPF_MISC|BPF_TAX, 0),                 // tax
		BPF_STMT(BPF_LD|BPF_IMM, true),                // ld #1
		BPF_STMT(BPF_ST|BPF_K, 1),                     // st M[1] (set is_fragment to true)
		BPF_STMT(BPF_LD|BPF_MEM, 0),                   // ld M[0]
		BPF_STMT(BPF_JMP|BPF_JA, -35),                 // ja 4 (to jump table, hopefully)

		// ICMP Type selection (4 instructions)
		BPF_STMT(BPF_LD|BPF_B|BPF_IND, 0),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, ND_ROUTER_ADVERT, 2, 0), // If router advertisement jump to accept
		BPF_STMT(BPF_LD|BPF_MEM, 1),                   // ld M[1]
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, true, 0, 1),   // if is_fragment == true, jump to accept

		// accept
		BPF_STMT(BPF_RET|BPF_K, 0xffffffff),
		// reject
		BPF_STMT(BPF_RET|BPF_K, 0),
	};
	fprog.filter = (struct sock_filter *)filter;
	fprog.len = 45;
#endif
	fprog.filter = (struct sock_filter *)filter;
	fprog.len = 12;
	sock = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IPV6));
	if (sock < 0) {
		fprintf(stderr, "Can't create socket(PF_PACKET). %d: %s\n", errno, strerror(errno));
		syslog(LOG_ERR, "Can't create socket(PF_PACKET). %d: %s\n", errno, strerror(errno));
		return -1;
	}
	err = setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog));
	if (err < 0) {
		fprintf(stderr, "Can't attach filter to socket. %d: %s\n", errno, strerror(errno));
		syslog(LOG_ERR, "Can't attach filter to socket. %d: %s\n", errno, strerror(errno));
		return -1;
	}

	return sock;
}

