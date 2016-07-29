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
#include <ctype.h>
#include <syslog.h>
#include <sys/file.h>

#include "hexdump.h"
#include "conf.h"
#include "sock.h"
#include "ra.h"

/* TODO:
 * - Fragmentation handling + also sending when packet length exceeds interface MTU
 * - Thread for repeating invalidated prefixes and clean ups of fragments hash map 
 * - Guard reachable time and retransmit time (configurable)
 * - Guard managed and other configuration flags (necessary?)
 */

#define IP6_HDRLEN 40

uint16_t icmp6_checksum(
                        const struct in6_addr *source_addr,
                        const struct in6_addr *dest_addr,
                        const uint8_t *payload,
                        const size_t length) {
	buf_t *buf = malloc(sizeof(buf_t));
	if (buf == NULL) {
		syslog(LOG_ERR, "MEMORY ALLOCATION ERROR at %s:%d", __FILE__ , __LINE__);
		exit(EXIT_FAILURE);
	}
	memset(buf, 0, sizeof(buf_t));

	/* Construct a pseudoheader */
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
                                   const struct ra *ra) {
	buf_t *buf = malloc(sizeof(buf_t));
	if (buf == NULL) {
		syslog(LOG_ERR, "MEMORY ALLOCATION ERROR at %s:%d", __FILE__ , __LINE__);
		exit(EXIT_FAILURE);
	}
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

	/* FIXME Make reachable time and retrans timer configurable per interface */
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
		memcpy(&buf->uint8[offset+16], &ra_out->prefix_info[i].nd_opt_pi_prefix, sizeof(struct in6_addr));
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
	if (ra_out->dnssl_count && offset + 8 < IP_MAXPACKET) {
		uint8_t *size = &buf->uint8[offset+1];
		uint32_t start_offset = offset;
		buf->uint8[offset] = ND_OPT_DNSSL;
		buf->uint16[(offset+2)/2] = 0; /* reserved */
		buf->uint32[(offset+4)/4] = 0; /* lifetime 0 */
		offset += 8;
		/* See RFC1035 section 3.1 for information about this format:
		   nuldelimited and terminated list of addresses, with label size prepended.
		   bitlair.nl -> \x06bitlair\x02nl\x00 */
		for (int i = 0; i < ra_out->dnssl_count && offset + strlen(ra_out->dnssl[i]) + 2 < IP_MAXPACKET; i++) {
			int start_of_label = 0;
			for (int j = 0; offset + j - start_of_label + 1 < IP_MAXPACKET; j++) {
				if (ra_out->dnssl[i][j] == '.' || ra_out->dnssl[i][j] == '\0') {
					/* Write the size */
					buf->uint8[offset] = j - start_of_label;
					/* Write the label */
					memcpy(&buf->uint8[offset + 1], &ra_out->dnssl[i][start_of_label], j - start_of_label);

					offset += j - start_of_label + 1;
					start_of_label = j+1;

					if (ra_out->dnssl[i][j] == '\0') {
						break;
					}
				}
			}
			if (offset < IP_MAXPACKET) {
				buf->uint8[offset] = '\0';
				offset++;
			}
		}
		/* Pad to 8 bytes */
		if ((offset - start_offset) % 8 != 0) {
			offset += 8 - ((offset - start_offset) % 8);
		}
		*size = (offset - start_offset + 7) / 8 ; /* off by a factor 8 */

		/* Prevent assigning more bytes than we can send out.. */
		if (offset > IP_MAXPACKET) {
			offset = IP_MAXPACKET;
			syslog(LOG_ERR, "Error: Tried sending more bytes than IP_MAXPACKET.");
		}
	}


	/*
	 * All this for sending a raw frame with spoofed source IP, need to construct all headers..
	 */

	/* Set the IPv6 header */

	/* IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits) */
	buf->uint32[0] = htonl ((6 << 28) | (0 << 20) | 0);
	buf->uint16[4/2] = htons(offset - IP6_HDRLEN); /* IP6 Payload length */
	buf->uint8[6] = IPPROTO_ICMPV6; /* ip6 next header */
	buf->uint8[7] = 255; /* maximum hops */
	memcpy(&buf->uint8[8], &ra->source_addr, sizeof(struct in6_addr));
	static const struct in6_addr dest_addr = {0xff,0x02,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0x01};
	memcpy(&buf->uint8[24], &dest_addr, sizeof(struct in6_addr));
	uint16_t checksum = icmp6_checksum(&ra->source_addr, &dest_addr, &buf->uint8[IP6_HDRLEN], offset-IP6_HDRLEN);
	buf->uint16[(IP6_HDRLEN+2)/2] = checksum;

	struct sockaddr_ll lladdr = {0};
	lladdr.sll_ifindex = ra->lladdr.sll_ifindex;
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
		syslog(LOG_ERR, "socket() failed. %d: %s", errno, strerror(errno));
		free(buf);
		return;
	}

	// Send ethernet frame to socket.
	ssize_t bytes_sent = sendto(sock, &buf->uint8, offset, 0, (struct sockaddr *) &lladdr, sizeof (lladdr));
	if (bytes_sent <= 0) {
		syslog(LOG_ERR, "sendto() failed. %d: %s", errno, strerror(errno));
		close(sock);
		free(buf);
		return;
	}
	close (sock);
	free(buf);
}

static void handle_router_advertisement(const struct ra *ra) {
	char ifname[IF_NAMESIZE];
	struct cf_interface *iface = NULL;
	struct ra *ra_out = malloc(sizeof(struct ra));
	if (!ra_out) {
		syslog(LOG_ERR, "MEMORY ALLOCATION ERROR at %s:%d", __FILE__ , __LINE__);
		exit(EXIT_FAILURE);
	}
	memset(ra_out, 0, sizeof(struct ra));

	char *rv_char = if_indextoname(ra->lladdr.sll_ifindex, ifname);
	if (rv_char == NULL) {
		syslog(LOG_ERR, "Error getting index name: %d: %s\n", errno, strerror(errno));
		free(ra_out);
		return;
	}

	for (int i = 0; i < state.iface_count; i++) {
		if (strcmp(ifname, state.interfaces[i].ifname) == 0) {
			iface = &state.interfaces[i];
			break;
		}
	}

	if (iface == NULL) {
		syslog(LOG_ERR, "Interface not found in configuration. Not doing anything.\n");
		free(ra_out);
		return;
	}

	char macaddr[MAC_MAXSTR];
	snprintf(macaddr, MAC_MAXSTR, "%02X:%02X:%02X:%02X:%02X:%02X",
						  ra->lladdr.sll_addr[0],
						  ra->lladdr.sll_addr[1],
						  ra->lladdr.sll_addr[2],
						  ra->lladdr.sll_addr[3],
						  ra->lladdr.sll_addr[4],
						  ra->lladdr.sll_addr[5]);

	for (int i = 0; i < ra->prefix_count; i++) {
		/* Match this prefix against the allowed prefixes. */
		bool prefix_good = false;
		for (int j = 0; j < iface->prefix_count; j++) {
			if (memcmp(&ra->prefix_info[i].nd_opt_pi_prefix, &iface->prefix[j], sizeof(struct in6_addr)) == 0 &&
					iface->prefix_len[j] == ra->prefix_info[i].nd_opt_pi_prefix_len) {
				prefix_good = true;
				break;
			}
		}
		if (!prefix_good && ra->prefix_info[i].nd_opt_pi_valid_time != 0) {
			char addr[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, &ra->prefix_info[i].nd_opt_pi_prefix, addr, INET6_ADDRSTRLEN);
			syslog(LOG_ALERT, "Found advertised bad prefix %s/%d from %s on %s. Taking countermeasures!\n", 
			                  addr, ra->prefix_info[i].nd_opt_pi_prefix_len, macaddr, ifname);

			/* Bad prefixes are countermeasured by sending the specific prefix with lifetime 0 */
			memcpy(&ra_out->prefix_info[ra_out->prefix_count], &ra->prefix_info[i], sizeof(struct nd_opt_prefix_info));
			ra_out->prefix_count++;
		}
	}
	for (int i = 0; i < ra->rdnss_count; i++) {
		/* Match this RDNSS against the allowed RDNSS for this interface. */
		bool rdnss_good = false;
		for (int j = 0; j < iface->rdnss_count; j++) {
			if (memcmp(&ra->rdnss[i], &iface->rdnss[j], sizeof(struct in6_addr)) == 0) {
				rdnss_good = true;
				break;
			}
		}
		if (!rdnss_good && ra->rdnss_lifetime[i] != 0) {
			char addr[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, &ra->rdnss[i], addr, INET6_ADDRSTRLEN);
			syslog(LOG_ALERT, "Found advertised bad RDNSS %s from %s on %s. Taking countermeasures!\n",
			                  addr, macaddr, ifname);

			/* RDNSS abuse is countermeasured by sending the RDNSS with lifetime 0 */
			memcpy(&ra_out->rdnss[ra_out->rdnss_count], &ra->rdnss[i], sizeof(struct in6_addr));
			ra_out->rdnss_count++;
		}
	}
	for (int i = 0; i < ra->dnssl_count; i++) {
		/* Match this DNSSL against the allowed DNSSL for this interface. */
		bool dnssl_good = false;
		for (int j = 0; j < iface->dnssl_count; j++) {
			if (strncmp(ra->dnssl[i], iface->dnssl[j], IF_NAMESIZE) == 0) {
				dnssl_good = true;
				break;
			}
		}
		if (!dnssl_good && ra->rdnss_lifetime[i] != 0) {
			syslog(LOG_ALERT, "Found advertised bad DNSSL %s from %s on %s. Taking countermeasures!\n",
			                  ra->dnssl[i], macaddr, ifname);
			/* DNSSL is countermeasured by sending the DNSSL with lifetime 0 */
			strncpy(ra_out->dnssl[ra_out->dnssl_count], ra->dnssl[i], HOST_NAME_MAX);
			ra_out->dnssl[ra_out->dnssl_count][HOST_NAME_MAX] = '\0';
			ra_out->dnssl_count++;
		}
	}
	if (ra->mtu && ra->mtu != iface->allowed_mtu) {
		syslog(LOG_ALERT, "Found advertised bad MTU %d from %s on %s. Needs to be %d. Taking countermeasures!\n",
		                  ra->mtu, macaddr, ifname, iface->allowed_mtu);

		/* MTU abuse is countermeasured by sending the correct MTU for the interface */
		ra_out->mtu = iface->allowed_mtu;
	}

	if (ra_out->mtu != 0 || ra_out->prefix_count != 0 || ra_out->rdnss_count != 0 ||
			ra_out->dnssl_count != 0) {
		send_countermeasure_ra(ra_out, ra);
	}
	free(ra_out);
}

static void debug_router_advertisement(const struct ra *ra) {
	syslog(LOG_DEBUG, "Got router advertisement from %02X:%02X:%02X:%02X:%02X:%02X\n", 
		ra->lladdr.sll_addr[0],
		ra->lladdr.sll_addr[1],
		ra->lladdr.sll_addr[2],
		ra->lladdr.sll_addr[3],
		ra->lladdr.sll_addr[4],
		ra->lladdr.sll_addr[5]);

	syslog(LOG_DEBUG, "Router Lifetime: %d\n", ra->advert.nd_ra_router_lifetime);
	syslog(LOG_DEBUG, "MTU: %d\n", ra->mtu);
	syslog(LOG_DEBUG, "Prefix count: %d\n", ra->prefix_count);
	syslog(LOG_DEBUG, "RDNSS count: %d\n", ra->rdnss_count);
	syslog(LOG_DEBUG, "DNSSL count: %d\n", ra->dnssl_count);

	char addr_str[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &ra->source_addr, addr_str, INET6_ADDRSTRLEN);
	syslog(LOG_DEBUG, "Source address: %s\n", addr_str);

	char interface[IF_NAMESIZE];
	syslog(LOG_DEBUG, "Interface index: %d: %s\n", ra->lladdr.sll_ifindex, if_indextoname(ra->lladdr.sll_ifindex, interface));

	for (int i = 0; i < ra->prefix_count; i++) {
		char addr[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &ra->prefix_info[i].nd_opt_pi_prefix, addr, INET6_ADDRSTRLEN);
		syslog(LOG_DEBUG, "Prefix: %s/%d\n", addr, ra->prefix_info[i].nd_opt_pi_prefix_len);
	}
	for (int i = 0; i < ra->rdnss_count; i++) {
		char addr[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &ra->rdnss[i], addr, INET6_ADDRSTRLEN);
		syslog(LOG_DEBUG, "Nameserver: %s\n", addr);
	}
	for (int i = 0; i < ra->dnssl_count; i++) {
		syslog(LOG_DEBUG, "DNSSL: %s\n", ra->dnssl[i]);
	}
}

static int parse_ipv6_headers(const uint8_t *buf, 
                              const size_t len,
                              struct in6_addr *source_addr,
                              const uint8_t **payload_out,
                              size_t *payload_len) {
	size_t hdr_offset = sizeof(struct ip6_hdr);
	uint8_t next_header = buf[offsetof(struct ip6_hdr, ip6_nxt)];
	bool is_fragment = false;
	bool more_fragments = false;
	uint16_t fragment_offset = 0;
	uint32_t fragment_ident;

	/* Handle all extension headers */
	for (uint32_t i = 0; i < (IP_MAXPACKET - sizeof(struct ip6_hdr)) / 8; i++) {
		switch (next_header) {
		case IPPROTO_ICMPV6:
			goto ICMPv6_or_frag_found; // break twice
		case IPPROTO_FRAGMENT:
			next_header = buf[hdr_offset];
			PARSE_INT(fragment_offset, &buf[hdr_offset+2], sizeof(uint16_t));
			more_fragments = fragment_offset & IP6F_MORE_FRAG >> 0;
			fragment_offset = (fragment_offset & 0xFFF8) >> 3;
			PARSE_INT(fragment_ident, &buf[hdr_offset+4], sizeof(uint32_t));
			hdr_offset += 8;
			is_fragment = true;
			break;
		case IPPROTO_AH:
			next_header = buf[hdr_offset];
			hdr_offset += buf[hdr_offset+1] + 2 * 4;
			break;
		case IPPROTO_ROUTING:
		case IPPROTO_DSTOPTS:
		case IPPROTO_HOPOPTS:
		case IPPROTO_MH:
			next_header = buf[hdr_offset];
			hdr_offset += buf[hdr_offset+1] + 1 * 8;
			break;
		default:
			if (is_fragment && fragment_offset != 0) {
				goto ICMPv6_or_frag_found;
			}
			syslog(LOG_ERR, "Dropping packet with next header %d\n", next_header);
			return 0;
		}
	}
	ICMPv6_or_frag_found:


	if (is_fragment) {
		/* FIXME: If this is a fragment, we need to wait and find other fragments. */
		// - If offset == 0 and ICMPv6 and more fragments: Add packet + fragmentation ident to hash map
        // - else if offset != 0 and in hash map: append to packet in hash map
		// - If no more fragments, continue
        // - else: return
		syslog(LOG_ERR, "Oh boy, fragmented packet... \n");
		if (more_fragments) {
			syslog(LOG_ERR, "More fragments are coming, ignoring the whole thing for now.");
			return 0;
		}
	}
	/* Get the source address from the packet */
	memcpy(source_addr, &buf[offsetof(struct ip6_hdr, ip6_src)], sizeof(struct in6_addr));

	/* Single packet payload */
	*payload_out = &buf[hdr_offset];
	*payload_len = len - hdr_offset;
	return 1;
}

static int parse_router_advertisement(struct ra *ra,
                                      const uint8_t *buf,
                                      const size_t len,
                                      const struct sockaddr_ll *lladdr) {
	if (len < 16) {
		syslog(LOG_ERR, "Packet too short for router advertisement.\n");
		return 0;
	}
	if (buf[0] != ND_ROUTER_ADVERT) {
		syslog(LOG_DEBUG, "Got unexpected non-router advertisement.\n");
		return 0;
	}

	/* Get the lladdr from sockaddr_ll */
	memcpy(&ra->lladdr, lladdr, sizeof(struct sockaddr_ll));

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
			syslog(LOG_ERR, "Error: zero length in router advertisement option\n");
			break;
		}
		switch(buf[nread]) {
		case ND_OPT_SOURCE_LINKADDR:		/* RFC4861, section 4.6.1 */
			memcpy(&ra->source_lladdr, &buf[nread+2], ETH_ALEN);
			break;
		case ND_OPT_PREFIX_INFORMATION: {	/* RFC4861, section 4.6.2 */
			if (buf[nread+1]*8 < 32) {
				syslog(LOG_ERR, "Error: Incorrect length in prefix information RA option.\n");
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
				syslog(LOG_ERR, "Incorrect length for RDNSS option\n");
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
				syslog(LOG_ERR, "Incorrect length for DNSSL option\n");
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
						syslog(LOG_ERR, "Warning, want to read out of bounds!\n");
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
			syslog(LOG_ERR, "Unexpected option type %d received. Ignoring\n", buf[nread]);
			break;
		default:
			syslog(LOG_ERR, "Unknown option type %d\n", buf[nread]);
		}

	}
	return 1;
}


static inline void handle_packet(
                                 const uint8_t *buf,
                                 const size_t len,
                                 const struct sockaddr_ll *lladdr) {
	struct ra *ra = malloc(sizeof(struct ra));
	if (ra == NULL) {
		syslog(LOG_ERR, "MEMORY ALLOCATION ERROR at %s:%d", __FILE__ , __LINE__);
		exit(EXIT_FAILURE);
	}
	memset(ra, 0, sizeof(struct ra));

	const uint8_t *payload;
	size_t payload_len;
	int parsed_correctly = parse_ipv6_headers(buf, len, &ra->source_addr, &payload, &payload_len);
	if (!parsed_correctly) {
		free(ra);
		return;
	}
	parsed_correctly = parse_router_advertisement(ra, payload, payload_len, lladdr);
	if (!parsed_correctly) {
		free(ra);
		return;
	}
	debug_router_advertisement(ra);
	handle_router_advertisement(ra);
	free(ra);
}


static void child_handler(int signum) {
    switch(signum) {
    case SIGALRM:
		exit(EXIT_FAILURE);
		break;
    case SIGUSR1:
		exit(EXIT_SUCCESS);
		break;
    case SIGCHLD:
		exit(EXIT_FAILURE);
		break;
    }
}

void daemonise(const char *pid_file) {
	sighandler_t handler;
	handler = signal(SIGCHLD, child_handler);
	if (handler == SIG_ERR) {
		fprintf(stderr, "Error setting signal handler CHLD: %d: %s\n", errno, strerror(errno));
		syslog(LOG_ERR, "Error setting signal handler CHLD: %d: %s\n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	handler = signal(SIGUSR1, child_handler);
	if (handler == SIG_ERR) {
		fprintf(stderr, "Error setting signal handler USR1: %d: %s\n", errno, strerror(errno));
		syslog(LOG_ERR, "Error setting signal handler USR1: %d: %s\n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	handler = signal(SIGALRM, child_handler);
	if (handler == SIG_ERR) {
		fprintf(stderr, "Error setting signal handler ALRM: %d: %s\n", errno, strerror(errno));
		syslog(LOG_ERR, "Error setting signal handler ALRM: %d: %s\n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	int pidfd = open(pid_file, O_WRONLY | O_CREAT, 0755);
	if (pidfd < 0) {
		fprintf(stderr, "Unable to open pid file %s: %d: %s\n", pid_file, errno, strerror(errno));
		syslog(LOG_ERR, "Unable to open pid file %s: %d: %s\n", pid_file, errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	int rv = flock(pidfd, LOCK_EX | LOCK_NB);
	if (rv < 0) {
		fprintf(stderr, "Unable to lock pid file: %s: %d: %s\n", pid_file, errno, strerror(errno));
		syslog(LOG_ERR, "Unable to lock pid file: %s: %d: %s\n", pid_file, errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	pid_t pid = fork();
	if (pid < 0) {
		fprintf(stderr, "Unable to fork(): %d: %s\n", errno, strerror(errno));
		syslog(LOG_ERR, "Unable to fork(): %d: %s\n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Parent */
	if (pid > 0) {
		close(pidfd);
		alarm(2);
		pause();
		exit(EXIT_SUCCESS);
	}

	/* Child */
	/* Lock the PID file exclusively */
	flock(pidfd, LOCK_EX);

	pid = getpid();
	char pidbuf[12];
	rv = snprintf(pidbuf, sizeof(pidbuf),  "%d\n", pid);
	if (rv > (signed)sizeof(pidbuf) - 1) {
		syslog(LOG_ERR, "Pid number larger than 11 digits");
		exit(EXIT_FAILURE);
	}
	if (rv <= 0) {
		syslog(LOG_ERR, "Unable to snprintf to pid buffer. %d: %s\n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	ssize_t writerv = write(pidfd, pidbuf, strlen(pidbuf));
	if (writerv < 0) {
		syslog(LOG_ERR, "Error writing to pid file %s: %d: %s\n", pid_file, errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Reset signals */
    handler = signal(SIGCHLD,SIG_DFL);
	if (handler == SIG_ERR) {
		syslog(LOG_ERR, "Error resetting signal handler CHLD: %d: %s\n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
    handler = signal(SIGALRM,SIG_DFL);
	if (handler == SIG_ERR) {
		syslog(LOG_ERR, "Error resetting signal handler ALRM: %d: %s\n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Ignore TTY signals */
    handler = signal(SIGTSTP,SIG_IGN);
	if (handler == SIG_ERR) {
		syslog(LOG_ERR, "Error setting signal handler TSTP: %d: %s\n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
    handler = signal(SIGTTOU,SIG_IGN);
	if (handler == SIG_ERR) {
		syslog(LOG_ERR, "Error setting signal handler TTOU: %d: %s\n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
    handler = signal(SIGTTIN,SIG_IGN);
	if (handler == SIG_ERR) {
		syslog(LOG_ERR, "Error setting signal handler TTIN: %d: %s\n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}



	pid_t sid = setsid();
	if (sid < 0) {
		syslog(LOG_ERR, "setsid failure %d: %s\n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	int chdir_rv = chdir("/");
	if (chdir_rv < 0) {
		syslog(LOG_ERR, "Can chdir to /: %d: %s\n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	FILE *fd;
	fd = freopen( "/dev/null", "r", stdin);
	if (fd == NULL) {
		syslog(LOG_ERR, "Unable to close stdin: %d: %s\n", errno, strerror(errno));
	}
	fd = freopen( "/dev/null", "w", stdout);
	if (fd == NULL) {
		syslog(LOG_ERR, "Unable to close stdout: %d: %s\n", errno, strerror(errno));
	}
	fd = freopen( "/dev/null", "w", stderr);
	if (fd == NULL) {
		syslog(LOG_ERR, "Unable to close stderr: %d: %s\n", errno, strerror(errno));
	}
	pid_t parent = getppid();
	kill(parent, SIGUSR1);
}

void help(const char *name) {
	fprintf(stderr, "Syntax: %s [-d] [-c conf_file] [-p pid_file]\n", name);
}

int main (int argc, char *argv[]) {
	const char *pid_file;
	sighandler_t handler;
	bool debug = false;
	bool foreground_mode = false;
	int sock = open_icmpv6_socket();
	if (sock < 0) {
		syslog(LOG_ERR, "Sorry, can't open the socket (Are you root?).\n");
		exit(EXIT_FAILURE);
	}

	int c;
	opterr = 0;
	conf_file = "/etc/abusir.conf";
	pid_file = "/var/run/abusir.pid";
	while ((c = getopt (argc, argv, "c:p:dF")) != -1) {
		switch (c) {
		case 'c':
			conf_file = optarg;
			break;
		case 'p':
			pid_file = optarg;
			break;
		case 'd':
			debug = true;
			break;
		case 'F':
			foreground_mode = true;
			break;
		case '?':
			if (optopt == 'c' || optopt == 'p') {
				fprintf(stderr, "Option -%c requires an argument.\n", optopt);
			} else if (isprint (optopt)) {
				fprintf(stderr, "Unknown option `-%c'.\n", optopt);
			} else {
				fprintf(stderr, "Unknown option character `\\x%x'.\n",
					   optopt);
			}
			help(argv[0]);
			exit(EXIT_FAILURE);
		default:
			help(argv[0]);
			abort();
		}
	}

	openlog(NULL, LOG_PID | LOG_NDELAY, LOG_DAEMON);
	if (debug == true) {
		setlogmask(LOG_UPTO(LOG_DEBUG));
	} else {
		setlogmask(LOG_UPTO(LOG_INFO));
	}
	read_configuration(0);

	if (!foreground_mode) {
		daemonise(pid_file);
	}

	/* Configuration reload on SIGHUP handler */
	handler = signal(SIGHUP, read_configuration);
	if (handler == SIG_ERR) {
		syslog(LOG_ERR, "An error occurred while setting a signal handler.\n");
        exit(EXIT_FAILURE);
    }

	buf_t *msg = malloc(sizeof(buf_t));
	if (msg == NULL) {
		syslog(LOG_ERR, "MEMORY ALLOCATION ERROR at %s:%d", __FILE__ , __LINE__);
		exit(EXIT_FAILURE);
	}
	memset(msg, 0, sizeof(buf_t));
	for (;;) {
		/* Only way to guarantee this fits without casting all over the place */
		union sockaddr_portable {
			struct sockaddr_ll ll;
			struct sockaddr_storage storage;
		} lladdr = {0};
		socklen_t socklen = sizeof(union sockaddr_portable);
		int len = recvfrom(sock, msg, sizeof(buf_t), 0, (struct sockaddr *)&lladdr, &socklen);
		syslog(LOG_DEBUG, "Got packet with ifindex %d\n", lladdr.ll.sll_ifindex);
		if (lladdr.ll.sll_ifindex == 0) {
			syslog(LOG_ERR, "No interface index received. No way to know where the packet came from.");
			continue;
		}
		syslog(LOG_DEBUG, "Executing parse function.\n");
		handle_packet(msg->uint8, len, &lladdr.ll);
	}
}
