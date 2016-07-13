#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/if_ether.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <libconfig.h>
#include "hexdump.h"
#include "sock.h"
#include "ra.h"


#define UNUSED(expr) (void)(expr)

static void debug_router_advertisement(const struct ra *ra, 
                                       const struct in6_addr *source_addr,
                                       const struct in6_pktinfo *pkt_info) {
	char addr_str[INET6_ADDRSTRLEN];

	printf("Router Lifetime: %d\n", ra->advert.nd_ra_router_lifetime);
	printf("MTU: %d\n", ra->mtu);
	printf("Prefix count: %d\n", ra->prefix_count);
	printf("RDNSS count: %d\n", ra->rdnss_count);
	printf("DNSSL count: %d\n", ra->dnssl_count);
	hexdump("Source Link address", &ra->source_lladdr, ETHER_ADDR_LEN);

	inet_ntop(AF_INET6, source_addr, addr_str, INET6_ADDRSTRLEN);
	printf("Source address: %s\n", addr_str);
	inet_ntop(AF_INET6, &pkt_info->ipi6_addr, addr_str, INET6_ADDRSTRLEN);
	printf("Destination address: %s\n", addr_str);

	printf("Interface index: %d\n", pkt_info->ipi6_ifindex);

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
	solicit.nd_rs_cksum = ntohs(*(uint16_t *)&buf[2]);
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
	advert->nd_ra_cksum = ntohs(*(uint16_t *)&buf[2]);
	advert->nd_ra_curhoplimit = buf[4];
	advert->nd_ra_flags_reserved = buf[5];
	advert->nd_ra_router_lifetime = ntohs(*(uint16_t *)&buf[6]);
	advert->nd_ra_reachable = ntohl(*(uint32_t *)&buf[8]);
	advert->nd_ra_retransmit = ntohl(*(uint32_t *)&buf[12]);
	
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
			memcpy(&ra->source_lladdr, &buf[nread+2], ETHER_ADDR_LEN);
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
			prefix_info->nd_opt_pi_valid_time = ntohl(*(uint32_t *)&buf[nread+4]);
			prefix_info->nd_opt_pi_preferred_time = ntohl(*(uint32_t *)&buf[nread+8]);
			prefix_info->nd_opt_pi_reserved2 = ntohl(*(uint32_t *)&buf[nread+12]);
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
			mtu.nd_opt_mtu_reserved = ntohs(*(uint16_t *)&buf[nread+2]);
			mtu.nd_opt_mtu_mtu = ntohl(*(uint32_t *)&buf[nread+4]);
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
			rdnss.nd_opt_rdnss_reserved = ntohs(*(uint16_t *)&buf[nread+2]);
			rdnss.nd_opt_rdnss_lifetime = ntohl(*(uint32_t *)&buf[nread+4]);

			/* Read all RDNSS entries */
			for (int i = 0; ra->rdnss_count < MAX_RDNSS && i < (rdnss.nd_opt_rdnss_len-8)/16; i++) {
				memcpy(&ra->rdnss[ra->rdnss_count], &buf[nread+8+i*16], 16);
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
			dnssl.nd_opt_dnssl_reserved = ntohs(*(uint16_t *)&buf[nread+2]);
			dnssl.nd_opt_dnssl_lifetime = ntohl(*(uint32_t *)&buf[nread+4]);

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
				ra->dnssl_count++;
			}
	
			break;
		}
		/* Unhandled stuff */
		case ND_OPT_TARGET_LINKADDR:	/* Not allowed, not a problem either */
		case ND_OPT_REDIRECTED_HEADER:	/* Not allowed, not a problem either */
		case ND_OPT_RTR_ADV_INTERVAL:	/* Mobile IPv6, irrelevant for security */
		case ND_OPT_HOME_AGENT_INFO:	/* Mobile IPv6, FIXME unsure what to do here */
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
	int rv;
	uint8_t msg[MAX_MSGLEN]; 
	struct sockaddr_in6 source_addr;
	struct in6_pktinfo *pkt_info = NULL;
	unsigned char chdr[CMSG_SPACE(sizeof(struct in6_pktinfo)) + CMSG_SPACE(sizeof(int))];
	config_t config, *cf;
	memset(msg, 0, sizeof(msg));

	int sock = open_icmpv6_socket();
	if (sock < 0) {
		fprintf(stderr, "Sorry, no.\n");
		return 1;
	}

	/* TODO: Add getopt for getting a non-default configuration file location */
	cf = &config;
	config_init(cf);
	rv = config_read_file(cf, "abusir.conf");
	if (rv != CONFIG_TRUE) {
		fprintf(stderr, "%s:%d - %s\n",
				config_error_file(cf),
				config_error_line(cf),
				config_error_text(cf));
        config_destroy(cf);
		return EXIT_FAILURE;
	}
	

	for (;;) {

		struct iovec iov;
		iov.iov_len = MAX_MSGLEN;
		iov.iov_base = (void *) msg;

		struct msghdr mhdr;
		memset(&mhdr, 0, sizeof(mhdr));
		mhdr.msg_name = (void *) &source_addr;
		mhdr.msg_namelen = sizeof(source_addr);
		mhdr.msg_iov = &iov;
		mhdr.msg_iovlen = 1;
		mhdr.msg_control = (void *)chdr;
		mhdr.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo)) + CMSG_SPACE(sizeof(int));

		int len = recvmsg(sock, &mhdr, 0);

		for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&mhdr); cmsg != NULL; cmsg = CMSG_NXTHDR(&mhdr, cmsg)) {
			if (cmsg->cmsg_level != IPPROTO_IPV6) { /* Should never happen with our interface filters */
				continue;
			}

			switch (cmsg->cmsg_type) {
			case IPV6_PKTINFO:
				if ((cmsg->cmsg_len == CMSG_LEN(sizeof(struct in6_pktinfo)))
						&& ((struct in6_pktinfo *)CMSG_DATA(cmsg))->ipi6_ifindex) {
					pkt_info = (struct in6_pktinfo *)CMSG_DATA(cmsg);
				} else {
					fprintf(stderr, "Received a bogus IPV6_PKTINFO from the kernel! len=%d, index=%d\n",
							(int)cmsg->cmsg_len, 
					                ((struct in6_pktinfo *)CMSG_DATA(cmsg))->ipi6_ifindex);
					return EXIT_FAILURE;
				}
				break;
			}
		}
		if (pkt_info == NULL) {
			fprintf(stderr, "Packet info structure is missing. No way to check which interface is used. Stopping");
			continue;
		}
		printf("Executing parse function.\n");
		handle_packet((uint8_t *)msg, len, &source_addr.sin6_addr, pkt_info);
	}
	return EXIT_SUCCESS;
}
