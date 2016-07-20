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
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <signal.h>
#include <libconfig.h>
#include <uthash.h>
#include <unistd.h>

#include "hexdump.h"
#include "conf.h"
#include "sock.h"
#include "ra.h"

#define IP6_HDRLEN 40
/* TODO:
 * - DNSSL handling 
 * - High priority: move arrays to the heap to not stack overflow when max size is moved to 65535
 * - High priority: valgrind complains about unitialized bytes when sending, investigate
 * - Guard reachable time and retransmit time
 * - Guard managed and other configuration flags (necessary?)
 * - Add getopt
 */

uint16_t icmp6_checksum(
                        const struct in6_addr *source_addr,
                        const struct in6_addr *dest_addr,
                        const uint8_t *payload,
                        const size_t length) {
	/* Construct a pseudoheader */
	buf_t *buf = malloc(sizeof(buf_t));
	memset(buf, 0, sizeof(buf_t));

	memcpy(&buf->uint8[0], source_addr, sizeof(struct in6_addr));
	memcpy(&buf->uint8[16], dest_addr, sizeof(struct in6_addr));
	buf->uint32[32/4] = htonl(length);
	buf->uint8[39] = IPPROTO_ICMPV6;
	memcpy(&buf->uint8[IP6_HDRLEN], payload, length);

	uint32_t total = 0;
	uint16_t *ptr   = &buf->uint16[0];
	int words = (length + IP6_HDRLEN + 1) / 2; // +1 & truncation on / handles any odd byte at end

	/*
	*   As we're using a 32 bit int to calculate 16 bit checksum
	*   we can accumulate carries in top half of DWORD and fold them in later
	*/
	while (words--) total += *ptr++;

	/*
	*   Fold in any carries
	*   - the addition may cause another carry so we loop
	*/
	while (total & 0xffff0000) total = (total >> 16) + (total & 0xffff);
	free(buf);
	return (uint16_t) ~total;
}

static void send_countermeasure_ra(
                                   const struct ra *ra_out,
                                   const struct ra *ra,
                                   const struct in6_addr *source_addr,
                                   const struct in6_pktinfo *pkt_info) {
	buf_t *buf = malloc(sizeof(buf_t));
	memset(buf, 0, sizeof(buf_t));
	int offset = IP6_HDRLEN;


	/* Fill the buffer with the router advertisement header */
	buf->uint8[offset] = ND_ROUTER_ADVERT; /* type */
	buf->uint8[offset+1] = 0; /* code */
	buf->uint16[(offset+2)/2] = htons(0); /* checksum */
	buf->uint8[offset+4] = 64; /* Current hop limit */

	/* Do not send out managed/other flags. FIXME: Do lots of testing */
	buf->uint8[offset+5] = 0; /* Flags reserved */


	buf->uint16[(offset+6)/2] = htons(0); /* Router lifetime */

	/* FIXME Make reachable time and retrans timer configurable */
	buf->uint32[(offset+8)/4] = htonl(30000); /* Reachable time 30 seconds */
	buf->uint32[(offset+12)/4] = htonl(1000); /* Retrans timer 1000ms */

	offset += 16;

	uint8_t compare[ETH_ALEN] = {0};
	if (memcmp(ra->source_lladdr, compare, ETH_ALEN) != 0 && offset + 8 < IP_MAXPACKET) {
		buf->uint8[offset] = ND_OPT_SOURCE_LINKADDR;
		buf->uint8[offset+1] = 8/8; // Off by factor of 8
		memcpy(&buf->uint8[offset+2], ra->source_lladdr, ETH_ALEN);
		offset += 8;
	}

	if (ra_out->mtu && offset + 8 < IP_MAXPACKET) {
		buf->uint8[offset] = ND_OPT_MTU;
		buf->uint8[offset+1] = 8/8; // Off by factor of 8
		buf->uint16[(offset+2)/2] = 0; /* reserved */
		buf->uint32[(offset+4)/4] = htonl(ra_out->mtu); /* MTU */
		offset += 8;
	}

	for (int i = 0; i < ra_out->prefix_count && offset + 32 < IP_MAXPACKET; i++) {
		buf->uint8[offset] = ND_OPT_PREFIX_INFORMATION;
		buf->uint8[offset+1] = 32/8; // Off by factor of 8
		buf->uint8[offset+2] = ra_out->prefix_info[i].nd_opt_pi_prefix_len;
		buf->uint8[offset+3] = ra->prefix_info[i].nd_opt_pi_flags_reserved;
		buf->uint32[(offset+4)/4] = 0; // Valid time 0
		buf->uint32[(offset+8)/4] = 0; // Prefered time 0
		buf->uint32[(offset+12)/4] = 0; // Reserved 0
		memcpy(&buf->uint8[offset+16], &ra->prefix_info[i].nd_opt_pi_prefix, sizeof(struct in6_addr));
		offset += 32;
	}

	if (ra_out->rdnss_count && offset + 8 < IP_MAXPACKET) {
		buf->uint8[offset] = ND_OPT_RDNSS;
		buf->uint8[offset+1] = (8 + ra_out->rdnss_count * sizeof(struct in6_addr)) /8; /* Off by factor 8 */
		buf->uint16[(offset+2)/2] = 0; /* reserved */
		buf->uint32[(offset+4)/4] = 0; /* lifetime 0 */
		offset += 8;
		for (int i = 0; i < ra_out->rdnss_count && offset + sizeof(struct in6_addr) < IP_MAXPACKET; i++) {
			memcpy(&buf->uint8[offset], &ra_out->rdnss[i], sizeof(struct in6_addr));
			offset += sizeof(struct in6_addr);
		}
	}
	/* TODO counteract DNSSL */


	/*
	 * All this for sending a raw frame with spoofed source IP, need to construct all headers..
	 */

	/* Set the IPv6 header */

	/* IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits) */
	buf->uint32[0] = htonl ((6 << 28) | (0 << 20) | 0);
	buf->uint16[4/2] = htons(offset - IP6_HDRLEN); /* IP6 Payload length */
	buf->uint8[6] = IPPROTO_ICMPV6; /* ip6 next header */
	buf->uint8[7] = 255; /* maximum hops */
	memcpy(&buf->uint8[8], source_addr, sizeof(struct in6_addr));
	static const struct in6_addr dest_addr = {0xff,0x02,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0x01};
	memcpy(&buf->uint8[24], &dest_addr, sizeof(struct in6_addr));
	uint16_t checksum = icmp6_checksum(source_addr, &dest_addr, &buf->uint8[IP6_HDRLEN], offset-IP6_HDRLEN);
	buf->uint16[(IP6_HDRLEN+2)/2] = checksum;

	struct sockaddr_ll lladdr = {0};
	lladdr.sll_ifindex = pkt_info->ipi6_ifindex;
	lladdr.sll_family = AF_PACKET;
	lladdr.sll_protocol = htons(ETH_P_IPV6);
	lladdr.sll_addr[0] = 0x33;
	lladdr.sll_addr[1] = 0x33;
	lladdr.sll_addr[2] = 0x00;
	lladdr.sll_addr[3] = 0x00;
	lladdr.sll_addr[4] = 0x00;
	lladdr.sll_addr[5] = 0x01;
	lladdr.sll_halen = ETH_ALEN;

	int sock;
	if ((sock = socket (PF_PACKET, SOCK_DGRAM, htons (ETH_P_ALL))) < 0) {
		fprintf(stderr, "socket() failed. %d: %s", errno, strerror(errno));
		free(buf);
		return;
	}

	// Send ethernet frame to socket.
	ssize_t bytes_sent = sendto (sock, &buf->uint8, offset, 0, (struct sockaddr *) &lladdr, sizeof (lladdr));
	if (bytes_sent <= 0) {
		fprintf(stderr, "sendto() failed. %d: %s", errno, strerror(errno));
		close(sock);
		free(buf);
		return;
	}
	close (sock);
	free(buf);
}

static void handle_router_advertisement(
                                        const struct ra *ra,
                                        const struct in6_addr *source_addr,
                                        const struct in6_pktinfo *pkt_info) {
	char ifname[IF_NAMESIZE];
	struct cf_interface *iface = NULL;
	struct ra ra_out = {0};

	char *rv_char = if_indextoname(pkt_info->ipi6_ifindex, ifname);
	if (rv_char == NULL) {
		fprintf(stderr, "Error getting index name: %d: %s\n", errno, strerror(errno));
		return;
	}

	for (int i = 0; i < state.iface_count; i++) {
		if (strcmp(ifname, state.interfaces[i].ifname) == 0) {
			iface = &state.interfaces[i];
			break;
		}
	}

	if (iface == NULL) {
		fprintf(stderr, "Interface not found in configuration. Not doing anything.\n");
		return;
	}

	for (int i = 0; i < ra->prefix_count; i++) {
		/* Match this prefix against the allowed prefixes. */
		bool prefix_good = false;
		for (int j = 0; j < iface->prefix_count; j++) {
			if (memcmp(&ra->prefix_info[i].nd_opt_pi_prefix, &iface->prefix[j], sizeof(struct in6_addr)) == 0 &&
					iface->prefix_len[j] == ra->prefix_info[i].nd_opt_pi_prefix_len) {
				fprintf(stderr, "Prefix is valid, yay!\n");
				prefix_good = true;
				break;
			}
		}
		if (!prefix_good && ra->prefix_info[i].nd_opt_pi_valid_time != 0) {
			fprintf(stderr, "Found bad prefix. Need to kill it with fire!\n");
			/* Bad prefixes are countermeasured by sending the specific prefix with lifetime 0 */
			memcpy(&ra_out.prefix_info[ra_out.prefix_count], &ra->prefix_info[i], sizeof(struct nd_opt_prefix_info));
			ra_out.prefix_count++;
		}
	}
	for (int i = 0; i < ra->rdnss_count; i++) {
		/* Match this RDNSS against the allowed RDNSS for this interface. */
		bool rdnss_good = false;
		for (int j = 0; j < iface->rdnss_count; j++) {
			if (memcmp(&ra->rdnss[i], &iface->rdnss[j], sizeof(struct in6_addr)) == 0) {
				fprintf(stderr, "RDNSS is valid, yay!\n");
				rdnss_good = true;
				break;
			}
		}
		if (!rdnss_good && ra->rdnss_lifetime[i] != 0) {
			fprintf(stderr, "Found bad RDNSS. Need to kill it with fire!\n");
			/* RDNSS abuse is countermeasured by sending the specific prefix with lifetime 0 */
			memcpy(&ra_out.rdnss[ra_out.rdnss_count], &ra->rdnss[i], sizeof(struct in6_addr));
			ra_out.rdnss_count++;
		}
	}
	for (int i = 0; i < ra->dnssl_count; i++) {
		/* Match this DNSSL against the allowed DNSSL for this interface. */
		bool dnssl_good = false;
		for (int j = 0; j < iface->dnssl_count; j++) {
			if (strncmp(ra->dnssl[i], iface->dnssl[j], IF_NAMESIZE) == 0) {
				fprintf(stderr, "DNSSL is valid, yay!\n");
				dnssl_good = true;
				break;
			}
		}
		if (!dnssl_good && ra->rdnss_lifetime[i] != 0) {
			fprintf(stderr, "Found bad DNSSL. Need to kill it with fire!\n");
			/* DNSSL is countermeasured by sending the specific prefix with lifetime 0 */
			strncpy(ra_out.dnssl[ra_out.dnssl_count], ra->dnssl[i], HOST_NAME_MAX);
			ra_out.dnssl[ra_out.dnssl_count][HOST_NAME_MAX] = '\0';
			ra_out.dnssl_count++;
		}
	}
	if (ra->mtu && ra->mtu != iface->allowed_mtu) {
		fprintf(stderr, "Found bad MTU. Need to kill it with fire!\n");
		/* MTU abuse is countermeasured by sending the correct MTU for the interface */
		ra_out.mtu = iface->allowed_mtu;
	}

	if (ra_out.mtu != 0 || ra_out.prefix_count != 0 || ra_out.rdnss_count != 0 ||
			ra_out.dnssl_count != 0) {
		send_countermeasure_ra(&ra_out, ra, source_addr, pkt_info);
	}
}

static void debug_router_advertisement(const struct ra *ra,
                                       const struct in6_addr *source_addr,
                                       const struct in6_pktinfo *pkt_info) {
	char addr_str[INET6_ADDRSTRLEN];
	printf("Got router advertisement from ");
	inet_ntop(AF_INET6, source_addr, addr_str, INET6_ADDRSTRLEN);
	printf("%s\n", addr_str);

	printf("Router Lifetime: %d\n", ra->advert.nd_ra_router_lifetime);
	printf("MTU: %d\n", ra->mtu);
	printf("Prefix count: %d\n", ra->prefix_count);
	printf("RDNSS count: %d\n", ra->rdnss_count);
	printf("DNSSL count: %d\n", ra->dnssl_count);
	hexdump("Source Link address", &ra->source_lladdr, ETH_ALEN);

	inet_ntop(AF_INET6, source_addr, addr_str, INET6_ADDRSTRLEN);
	printf("Source address: %s\n", addr_str);
	inet_ntop(AF_INET6, &pkt_info->ipi6_addr, addr_str, INET6_ADDRSTRLEN);
	printf("Destination address: %s\n", addr_str);

	char interface[IF_NAMESIZE];
	printf("Interface index: %d: %s\n", pkt_info->ipi6_ifindex, if_indextoname(pkt_info->ipi6_ifindex, interface));

	for (int i = 0; i < ra->prefix_count; i++) {
		char addr[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &ra->prefix_info[i].nd_opt_pi_prefix, addr, INET6_ADDRSTRLEN);
		printf("Prefix: %s/%d\n", addr, ra->prefix_info[i].nd_opt_pi_prefix_len);
	}
	for (int i = 0; i < ra->rdnss_count; i++) {
		char addr[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &ra->rdnss[i], addr, INET6_ADDRSTRLEN);
		printf("Nameserver: %s\n", addr);
	}
	for (int i = 0; i < ra->dnssl_count; i++) {
		printf("DNSSL: %s\n", ra->dnssl[i]);
	}
}


static int parse_router_solicitation(const uint8_t *buf,
                                     const size_t len) {
	if (len < 8) {
		fprintf(stderr, "Packet too short for router solicitation.\n");
		return 0;
	}
	struct nd_router_solicit solicit;
	solicit.nd_rs_type = buf[0];
	solicit.nd_rs_code = buf[1];
	PARSE_INT(solicit.nd_rs_cksum, &buf[2], sizeof(uint16_t));
	solicit.nd_rs_cksum = ntohs(solicit.nd_rs_cksum);
	fprintf(stderr, "Got solicitation with checksum 0x%04X\n", solicit.nd_rs_cksum);
	return 1;
}

static int parse_router_advertisement(struct ra *ra,
                                      const uint8_t *buf,
                                      const size_t len) {
	if (len < 16) {
		fprintf(stderr, "Packet too short for router advertisement.\n");
		return 0;
	}

	struct nd_router_advert *advert = &ra->advert;
	advert->nd_ra_type = buf[0];
	advert->nd_ra_code = buf[1];
	PARSE_INT(advert->nd_ra_cksum, &buf[2], sizeof(uint16_t))
	advert->nd_ra_curhoplimit = buf[4];
	advert->nd_ra_flags_reserved = buf[5];
	PARSE_INT(advert->nd_ra_router_lifetime, &buf[6], sizeof(uint16_t));
	PARSE_INT(advert->nd_ra_reachable, &buf[8], sizeof(uint32_t));
	PARSE_INT(advert->nd_ra_retransmit, &buf[12], sizeof(uint32_t));

	/* Read all options.
	 * Note that all option lengths are off by a factor of 8. We fix this in the structs.
	 */
	for (size_t nread = 16;nread < len; nread += buf[nread + 1] * 8) {
		if (buf[nread + 1] == 0) {
			fprintf(stderr, "Error: zero length in router advertisement option\n");
			break;
		}
		switch(buf[nread]) {
		case ND_OPT_SOURCE_LINKADDR:		/* RFC4861, section 4.6.1 */
			memcpy(&ra->source_lladdr, &buf[nread+2], ETH_ALEN);
			break;
		case ND_OPT_PREFIX_INFORMATION: {	/* RFC4861, section 4.6.2 */
			if (buf[nread+1]*8 < 32) {
				fprintf(stderr, "Error: Incorrect length in prefix information RA option.\n");
				break;
			}
			struct nd_opt_prefix_info *prefix_info = &ra->prefix_info[ra->prefix_count];
			prefix_info->nd_opt_pi_type = buf[nread];
			prefix_info->nd_opt_pi_len = buf[nread+1] * 8; /* Off by a factor of 8 */
			prefix_info->nd_opt_pi_prefix_len = buf[nread+2];
			prefix_info->nd_opt_pi_flags_reserved = buf[nread+3];
			PARSE_INT(prefix_info->nd_opt_pi_valid_time, &buf[nread+4], sizeof(uint32_t));
			PARSE_INT(prefix_info->nd_opt_pi_preferred_time, &buf[nread+8], sizeof(uint32_t));
			PARSE_INT(prefix_info->nd_opt_pi_reserved2, &buf[nread+12], sizeof(uint32_t));
			memcpy(&prefix_info->nd_opt_pi_prefix, &buf[nread+16], 16);

			char addr[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, &prefix_info->nd_opt_pi_prefix, addr, INET6_ADDRSTRLEN);
			ra->prefix_count++;
			break;
		}
		case ND_OPT_MTU: {					/* RFC4861, section 4.6.4 */
			struct nd_opt_mtu mtu;
			mtu.nd_opt_mtu_type =  buf[nread];
			mtu.nd_opt_mtu_len = buf[nread+1];
			PARSE_INT(mtu.nd_opt_mtu_reserved, &buf[nread+2], sizeof(uint16_t));
			PARSE_INT(mtu.nd_opt_mtu_mtu, &buf[nread+4], sizeof(uint32_t));
			if (!ra->mtu) {
				ra->mtu = mtu.nd_opt_mtu_mtu;
			} else {
				/* Bad value, IPv6 min mtu -1. Why?: We got multiple MTUs and we
                 * need to reset the MTU to a proper value anyway as we have no way
                 * of knowing which one the client set (first one? last one?) */
				ra->mtu = 1279;
			}
			break;
		}
		case ND_OPT_RDNSS: {				/* RFC6106, section 5.1 */
			if (buf[nread+1]*8 < 2 || buf[nread+1] * 8 % 16 != 8) {
				fprintf(stderr, "Incorrect length for RDNSS option\n");
				break;
			}
			struct nd_opt_rdnss rdnss;
			rdnss.nd_opt_rdnss_type = buf[nread];
			rdnss.nd_opt_rdnss_len = buf[nread+1] * 8; /* Off by a factor of 8 */
			PARSE_INT(rdnss.nd_opt_rdnss_reserved, &buf[nread+2], sizeof(uint16_t));
			PARSE_INT(rdnss.nd_opt_rdnss_lifetime, &buf[nread+4], sizeof(uint32_t));
			rdnss.nd_opt_rdnss_lifetime = ntohl(rdnss.nd_opt_rdnss_lifetime);

			/* Read all RDNSS entries */
			for (int i = 0; ra->rdnss_count < MAX_RDNSS && i < (rdnss.nd_opt_rdnss_len-8)/16; i++) {
				memcpy(&ra->rdnss[ra->rdnss_count], &buf[nread+8+i*16], 16);
				ra->rdnss_lifetime[ra->rdnss_count] = rdnss.nd_opt_rdnss_lifetime;
				ra->rdnss_count++;
			}

			break;
		}
		case ND_OPT_DNSSL: {				/* RFC6106, section 5.2 */
			if (buf[nread + 1] * 8 < 2 || nread + buf[nread+1] * 8 > len) {
				fprintf(stderr, "Incorrect length for DNSSL option\n");
				break;
			}
			struct nd_opt_dnssl dnssl;
			dnssl.nd_opt_dnssl_type = buf[nread];
			dnssl.nd_opt_dnssl_len = buf[nread+1] * 8; /* Off by a factor of 8 */
			PARSE_INT(dnssl.nd_opt_dnssl_reserved, &buf[nread+2], sizeof(uint16_t));
			PARSE_INT(dnssl.nd_opt_dnssl_lifetime, &buf[nread+4], sizeof(uint32_t));

			/* Read all DNSSL entries */
			uint32_t offset = 8;
			while (ra->dnssl_count < MAX_DNSSL &&
				   offset < dnssl.nd_opt_dnssl_len &&
				   buf[nread + offset] != '\0') {
				char *tmp = ra->dnssl[ra->dnssl_count];
				int tmp_off = 0;

				/* Read every sequence label, e.g. \x06bitlair\x02nl\x00 for "bitlair.nl".
				 * See RFC1035, section 3.1 */
				uint32_t label_offset = offset;
				while (label_offset < dnssl.nd_opt_dnssl_len && tmp_off <= HOST_NAME_MAX) {
					uint32_t length = buf[nread +  label_offset];

					if (label_offset + length > dnssl.nd_opt_dnssl_len) {
						fprintf(stderr, "Warning, want to read out of bounds!\n");
						break;
					}

					/* Add the sequence label to the list */
					memcpy(&tmp[tmp_off], &buf[nread + label_offset + 1], length);
					tmp_off += length;

					/* Increment the label offset to the next length byte */
					label_offset += length + 1;
					if (buf[nread + label_offset] == '\0') {
						offset += label_offset + 1;
						break;
					}

					/* Add a dot between sequence labels. */
					tmp[tmp_off] = '.';
					tmp_off++;
				}
				ra->dnssl_lifetime[ra->dnssl_count] = dnssl.nd_opt_dnssl_lifetime;
				ra->dnssl_count++;
			}

			break;
		}
		/* Unhandled stuff */
		case ND_OPT_TARGET_LINKADDR:	/* Not allowed, not a problem either */
		case ND_OPT_REDIRECTED_HEADER:	/* Not allowed, not a problem either */
		case ND_OPT_RTR_ADV_INTERVAL:	/* Mobile IPv6, irrelevant for security */
		case ND_OPT_HOME_AGENT_INFO:	/* Mobile IPv6, FIXME unsure what to do here */
			fprintf(stderr, "Unexpected option type %d received. Ignoring\n", buf[nread]);
			break;
		default:
			fprintf(stderr, "Unknown option type %d\n", buf[nread]);
		}

	}
	return 0;
}


static inline void handle_packet(
                         const uint8_t *buf,
                         const size_t len,
                         const struct in6_addr *source_addr,
                         const struct in6_pktinfo *pkt_info) {
	switch (buf[0]) {
	case ND_ROUTER_SOLICIT:
		parse_router_solicitation(buf, len);
		break;
	case ND_ROUTER_ADVERT: {
		struct ra ra = {0};
		parse_router_advertisement(&ra, buf, len);
		debug_router_advertisement(&ra, source_addr, pkt_info);
		handle_router_advertisement(&ra, source_addr, pkt_info);
		break;
    }
	default:
		fprintf(stderr, "Unknown message type: %d\n", buf[0]);	/* Should not be hit with our interface filters */
		return;
	}
}


int main (int argc, char *argv[]) {
	UNUSED(argc);
	UNUSED(argv);
	struct sockaddr_in6 source_addr;
	struct in6_pktinfo pkt_info = {0};
	unsigned char chdr[CMSG_SPACE(sizeof(struct in6_pktinfo)) + CMSG_SPACE(sizeof(int))];

	int sock = open_icmpv6_socket();
	if (sock < 0) {
		fprintf(stderr, "Sorry, no.\n");
		return 1;
	}

	/* TODO: Add getopt for getting a non-default configuration file location */
	read_configuration(0);
	if (signal(SIGHUP, read_configuration) == SIG_ERR) {
		fprintf(stderr, "An error occurred while setting a signal handler.\n");
        return EXIT_FAILURE;
    }

	buf_t *msg = malloc(sizeof(buf_t));
	memset(msg, 0, sizeof(buf_t));
	for (;;) {

		struct iovec iov;
		iov.iov_len = sizeof(buf_t);
		iov.iov_base = msg->uint8;

		struct msghdr mhdr;
		memset(&mhdr, 0, sizeof(mhdr));
		mhdr.msg_name = &source_addr;
		mhdr.msg_namelen = sizeof(source_addr);
		mhdr.msg_iov = &iov;
		mhdr.msg_iovlen = 1;
		mhdr.msg_control = chdr;
		mhdr.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo)) + CMSG_SPACE(sizeof(int));

		int len = recvmsg(sock, &mhdr, 0);
		printf("%d\n", len);
		for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&mhdr); cmsg != NULL; cmsg = CMSG_NXTHDR(&mhdr, cmsg)) {
			if (cmsg->cmsg_level != IPPROTO_IPV6) { /* Should never happen with our interface filters */
				continue;
			}

			switch (cmsg->cmsg_type) {
			case IPV6_PKTINFO:
				if (cmsg->cmsg_len == CMSG_LEN(sizeof(struct in6_pktinfo))) {
					memcpy(&pkt_info, CMSG_DATA(cmsg), sizeof(struct in6_pktinfo));;
				}
				if (pkt_info.ipi6_ifindex == 0) {
					fprintf(stderr, "Received a bogus IPV6_PKTINFO from the kernel! len=%d\n",
							(int)cmsg->cmsg_len);
					free(msg);
					return EXIT_FAILURE;
				}
				break;
			}
		}
		if (pkt_info.ipi6_ifindex == 0) {
			fprintf(stderr, "Packet info structure is missing or invalid. No way to check which interface is used. Stopping");
			continue;
		}
		printf("Executing parse function.\n");
		handle_packet(msg->uint8, len, &source_addr.sin6_addr, &pkt_info);
	}
	free(msg);
	return EXIT_SUCCESS;
}
