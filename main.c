#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <errno.h>
#include <stdio.h>

#include "hexdump.h"
#include "sock.h"

/* netinet/icmp6.h does not have these :'( */
#ifndef ND_OPT_RDNSS
#define ND_OPT_RDNSS 25
struct nd_opt_rdnss {
	uint8_t nd_opt_rdnss_type;
	uint8_t nd_opt_rdnss_len;
	uint16_t nd_opt_rdnss_reserved;
	uint32_t nd_opt_rdnss_lifetime;
};
#endif

#ifndef ND_OPT_DNSSL
#define ND_OPT_DNSSL 31
struct nd_opt_dnssl {
	uint8_t nd_opt_dnssl_type;
	uint8_t nd_opt_dnssl_len;
	uint16_t nd_opt_dnssl_reserved;
	uint32_t nd_opt_dnssl_lifetime;
};
#endif

#define UNUSED(expr) (void)(expr)

void parse_router_solicitation(uint8_t *buf, size_t len) {
	if (len < 8) {
		fprintf(stderr, "Packet too short for router solicitation.\n");
		return;
	}
	struct nd_router_solicit solicit;
	solicit.nd_rs_type = buf[0];
	solicit.nd_rs_code = buf[1];
	solicit.nd_rs_cksum = ntohs(*(uint16_t *)&buf[2]);
	fprintf(stderr, "Got solicitation with checksum %d\n", solicit.nd_rs_cksum);
}

void parse_router_advertisement(uint8_t *buf, size_t len) {
	if (len < 16) {
		fprintf(stderr, "Packet too short for router advertisement.\n");
		return;
	}
	struct nd_router_advert advert;
	advert.nd_ra_type = buf[0];
	advert.nd_ra_code = buf[1];
	advert.nd_ra_cksum = ntohs(*(uint16_t *)&buf[2]);
	advert.nd_ra_curhoplimit = buf[4];
	advert.nd_ra_flags_reserved = buf[5];
	advert.nd_ra_router_lifetime = ntohs(*(uint16_t *)&buf[6]);
	advert.nd_ra_reachable = ntohl(*(uint32_t *)&buf[8]);
	advert.nd_ra_retransmit = ntohl(*(uint32_t *)&buf[12]);
	printf("Type: %d\n", advert.nd_ra_type);
	printf("Code: %d\n", advert.nd_ra_code);
	printf("Cksum: %d\n", advert.nd_ra_cksum);
	printf("Current Hop Limit: %d\n", advert.nd_ra_curhoplimit);
	printf("Flags: %d\n", advert.nd_ra_flags_reserved);
	printf("Router lifetime: %d\n", advert.nd_ra_router_lifetime);
	
	printf("Len: %ld\n", len);
	for (size_t nread = 16;nread < len; nread += buf[nread + 1] * 8) {
		printf("Offset: %ld\n", nread);
		printf("Type: %x\n", buf[nread]);
		printf("Len: %x\n", buf[nread+1]*8);
		if (buf[nread + 1] == 0) {
			fprintf(stderr, "Error: zero length in router advertisement option\n");
			break;
		}
		switch(buf[nread]) {
		case ND_OPT_SOURCE_LINKADDR:	/* TODO: Spoof this! */
			fprintf(stderr, "TODO: Spoof this source link address\n");
			break;
		case ND_OPT_PREFIX_INFORMATION: {	/* TODO: Undo with lifetime 0 */
			if (buf[nread+1]*8 < 32) {
				fprintf(stderr, "Error: Incorrect length in prefix information RA option.\n");
				break;
			}
			struct nd_opt_prefix_info prefix_info;
			prefix_info.nd_opt_pi_type = buf[nread];
			prefix_info.nd_opt_pi_len = buf[nread+1];
			prefix_info.nd_opt_pi_prefix_len = buf[nread+2];
			prefix_info.nd_opt_pi_flags_reserved = buf[nread+3];
			prefix_info.nd_opt_pi_valid_time = ntohl(*(uint32_t *)&buf[nread+4]);
			prefix_info.nd_opt_pi_preferred_time = ntohl(*(uint32_t *)&buf[nread+8]);
			prefix_info.nd_opt_pi_reserved2 = ntohl(*(uint32_t *)&buf[nread+12]);
			memcpy(&prefix_info.nd_opt_pi_prefix, &buf[nread+16], 16);

			char addr[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, &prefix_info.nd_opt_pi_prefix, addr, INET6_ADDRSTRLEN);
			printf("Prefix valid time: %d\n", prefix_info.nd_opt_pi_valid_time);
			printf("Prefix: %s/%d\n", addr, prefix_info.nd_opt_pi_prefix_len);
			break;
		}
		case ND_OPT_MTU: {				/* TODO: Undo with proper MTU */
			struct nd_opt_mtu mtu;
			mtu.nd_opt_mtu_type =  buf[nread];
			mtu.nd_opt_mtu_len = buf[nread+1];
			mtu.nd_opt_mtu_reserved = ntohs(*(uint16_t *)&buf[nread+2]);
			mtu.nd_opt_mtu_mtu = ntohl(*(uint32_t *)&buf[nread+4]);
			printf("TODO: Counterattack MTU: %d\n", mtu.nd_opt_mtu_mtu);
			break;
		}
		case ND_OPT_RDNSS: {				/* TODO: Undo with lifetime 0 */
			if (buf[nread+1]*8 < 2 || buf[nread+1] * 8 % 16 != 8) {
				fprintf(stderr, "Incorrect length for RDNSS option\n");
				break;
			}
			struct nd_opt_rdnss rdnss;
			rdnss.nd_opt_rdnss_type = buf[nread];
			rdnss.nd_opt_rdnss_len = buf[nread+1];
			rdnss.nd_opt_rdnss_reserved = ntohs(*(uint16_t *)&buf[nread+2]);
			rdnss.nd_opt_rdnss_lifetime = ntohl(*(uint32_t *)&buf[nread+4]);
			printf("TODO: Counterattack the DNS servers with lifetime: %d\n", rdnss.nd_opt_rdnss_lifetime);
			printf("Read %d addresses\n", (rdnss.nd_opt_rdnss_len*8-8)/16);
			struct in6_addr dns_servers[(rdnss.nd_opt_rdnss_len*8-8)/16];
			for (int i = 0; i < (rdnss.nd_opt_rdnss_len*8-8)/16; i++) {
				memcpy(&dns_servers[i], &buf[nread+8+i*16], 16);
				char address[INET6_ADDRSTRLEN];
				inet_ntop(AF_INET6, &dns_servers[i], address, INET6_ADDRSTRLEN);
				printf("Got nameserver: %s\n", address);
			}
			
			break;
		}
		case ND_OPT_DNSSL: {		/* TODO: Undo with lifetime 0 */
			struct nd_opt_dnssl dnssl;
			dnssl.nd_opt_dnssl_type = buf[nread];
			dnssl.nd_opt_dnssl_len = buf[nread+1];
			dnssl.nd_opt_dnssl_reserved = ntohs(*(uint16_t *)&buf[nread+2]);
			dnssl.nd_opt_dnssl_lifetime = ntohl(*(uint32_t *)&buf[nread+4]);
			printf("TODO: Counterattack the DNS search list which has lifetime: %d\n", dnssl.nd_opt_dnssl_lifetime);

			char *dnssl_domains[dnssl.nd_opt_dnssl_len*8];
			dnssl_domains[0] = (char *)&buf[nread+8];
			printf("Got search domain: %s\n", dnssl_domains[0]);
			for(int i = 8, j = 1; i < dnssl.nd_opt_dnssl_len; i++) {
				if (buf[nread+i] != '\0') {
					continue;
				}
				dnssl_domains[j] = (char *)&buf[nread+i];
				printf("Got search domain: %s\n", dnssl_domains[j]);
				j++;
			}
			break;
		}
		/* Unhandled stuff */
		case ND_OPT_TARGET_LINKADDR:	/* Not allowed, not a problem either */
		case ND_OPT_REDIRECTED_HEADER:	/* Not allowed, not a problem either */
		case ND_OPT_RTR_ADV_INTERVAL:
		case ND_OPT_HOME_AGENT_INFO:	
		default:
			fprintf(stderr, "Unknown option type %d\n", buf[nread]);
		}

	}
	
	
}


static inline void parse(uint8_t *buf, size_t len) {
	hexdump("buf", buf, len);
	switch (buf[0]) {
	case ND_ROUTER_SOLICIT:
		parse_router_solicitation(buf, len);
		break;
	case ND_ROUTER_ADVERT:
		parse_router_advertisement(buf, len);
		break;
	default:
		fprintf(stderr, "Unknown message type: %d\n", buf[0]);	/* Should not be hit with our interface filters */
		return;
	}
}


int main (int argc, char *argv[]) {
	UNUSED(argc);
	UNUSED(argv);
	uint8_t msg[1024];
	char address[INET6_ADDRSTRLEN];
	struct sockaddr_in6 addr;
	struct in6_pktinfo *pkt_info;
	unsigned char chdr[CMSG_SPACE(sizeof(struct in6_pktinfo)) + CMSG_SPACE(sizeof(int))];
	
	memset(msg, 0, sizeof(msg));

	int sock = open_icmpv6_socket();
	if (sock < 0) {
		fprintf(stderr, "Sorry, no.\n");
		return 1;
	}

	for (;;) {
		struct iovec iov;
		iov.iov_len = 1024;
		iov.iov_base = (void *) msg;

		struct msghdr mhdr;
		memset(&mhdr, 0, sizeof(mhdr));
		mhdr.msg_name = (void *) &addr;
		mhdr.msg_namelen = sizeof(addr);
		mhdr.msg_iov = &iov;
		mhdr.msg_iovlen = 1;
		mhdr.msg_control = (void *)chdr;
		mhdr.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo)) + CMSG_SPACE(sizeof(int));

		int len = recvmsg(sock, &mhdr, 0);
		printf("%d\n", len);
		hexdump("mhdr", &mhdr, sizeof(mhdr));
		hexdump("chdr", &chdr, sizeof(chdr));
		inet_ntop(AF_INET6, &(addr.sin6_addr), address, INET6_ADDRSTRLEN);
		printf("%s\n", address);

		for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&mhdr); cmsg != NULL; cmsg = CMSG_NXTHDR(&mhdr, cmsg)) {
			if (cmsg->cmsg_level != IPPROTO_IPV6)
				continue;

			switch (cmsg->cmsg_type) {
			case IPV6_PKTINFO:
				if ((cmsg->cmsg_len == CMSG_LEN(sizeof(struct in6_pktinfo)))
						&& ((struct in6_pktinfo *)CMSG_DATA(cmsg))->ipi6_ifindex) {
					pkt_info = (struct in6_pktinfo *)CMSG_DATA(cmsg);
				} else {
					fprintf(stderr, "received a bogus IPV6_PKTINFO from the kernel! len=%d, index=%d\n",
							(int)cmsg->cmsg_len, ((struct in6_pktinfo *)CMSG_DATA(cmsg))->ipi6_ifindex);
					return -1;
				}
				break;
			}
		}
		hexdump("pktinfo", pkt_info, sizeof(struct in6_pktinfo));
		printf("Executing parse function.\n");
		parse((uint8_t *)msg, len);
	}
	return 1;
}
