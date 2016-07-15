#ifndef _CONF_H
#define _CONF_H

#include <stdint.h>
#include <net/if.h>
#include <netinet/ip6.h>
#include "ra.h"

struct cf_interface {
	char ifname[IF_NAMESIZE];
	uint16_t prefix_count;
	uint16_t rdnss_count;
	uint16_t dnssl_count;
	int allowed_mtu;
	struct in6_addr prefix[16];
	uint16_t prefix_len[16];
	struct in6_addr rdnss[16];
	char dnssl[16][HOST_NAME_MAX];
};

/* Globals */
struct {
	char *config_file;
} options;

struct {
	uint16_t iface_count;
	struct cf_interface *interfaces;
} state;
#define UNUSED(expr) (void)(expr)
int strtolong(const char *ptr, long minval, long maxval, long *value);
void read_configuration(int signo);


#endif
