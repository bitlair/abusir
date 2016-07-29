#ifndef _RA_H
#define _RA_H
#include <linux/if_packet.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>

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

#define HDR_LEN         sizeof(struct nd_router_advert)

/* Define the theoretical limits that can fit in a packet 
 * The prefix option is fixed length: with 1500 MTU, only 45 will fit.
 * The RDNSS option is not fixed length, but contains 16-byte IPv6-addreses
 * The DNSSL option is not fixed length and the shortest DNSSL option is one length byte, a character and a NUL-byte.
 */
#define MAX_PREFIXES    ((IP_MAXPACKET - HDR_LEN) / sizeof(struct nd_opt_prefix_info) + 1)
#define MAX_RDNSS       ((IP_MAXPACKET - HDR_LEN - sizeof(struct nd_opt_rdnss)) / sizeof(struct in6_addr) + 1)
#define MAX_DNSSL       ((IP_MAXPACKET - HDR_LEN - sizeof(struct nd_opt_dnssl)) / 3 + 1)

// 3 characters per byte in ETH_ALEN: e.g. 01:23:45:54:32:10\0
#define MAC_MAXSTR (3*ETH_ALEN)

/* RFC1035, section 2.3.5 and section 3.1 specifies a max length of 255.
 * It also specifies a max label length of 63, but we do not enforce this, 
 * as anything advertised with longer labels should die too. */
#define HOST_NAME_MAX 255

struct ra {
	struct sockaddr_ll lladdr;
	struct in6_addr source_addr;
    struct nd_router_advert advert;
    uint16_t prefix_count;
    uint16_t rdnss_count;
    uint16_t dnssl_count;
    uint16_t mtu;
    struct nd_opt_prefix_info prefix_info[MAX_PREFIXES];
    struct in6_addr rdnss[MAX_RDNSS];
	uint32_t rdnss_lifetime[MAX_RDNSS];
    char dnssl[MAX_DNSSL][HOST_NAME_MAX+1];
	uint32_t dnssl_lifetime[MAX_DNSSL];
    uint8_t source_lladdr[ETH_ALEN];
};

#define PARSE_INT(x, y, size) { \
	memcpy(&(x), (y), (size)); \
	if ((size) == sizeof(short)) { \
		(x) = ntohs((x)); \
	} else { \
		(x) = ntohl((x)); \
	}\
}

typedef union {
	uint8_t uint8[IP_MAXPACKET];
	uint16_t uint16[IP_MAXPACKET/sizeof(uint16_t)];
	uint32_t uint32[IP_MAXPACKET/sizeof(uint32_t)];
} buf_t;

#endif
