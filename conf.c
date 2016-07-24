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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <libconfig.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ip6.h>

#include "hexdump.h"
#include "conf.h"
config_t config, *cf = &config;

const char *conf_file;

/* Why did I need to make this myself again? */
int strtolong(const char *ptr, long minval, long maxval, long *value) {
		errno = 0;
		char *endptr;
		*value = strtol(ptr, &endptr, 10);
		if (errno) {
			printf("Error converting string (%s) to int: %d: %s\n", ptr, errno, strerror(errno));
			return errno;
		}
		if (ptr+strlen(ptr) != endptr) {
			printf("Non-numeric characters in string: %s\n", ptr);
			errno = EINVAL;
			return errno;
		}
		if (ptr == endptr) {
			printf("No digits found in string: %s\n", ptr);
			errno = EINVAL;
			return errno;
		}
		if (*value < minval || *value > maxval) {
			printf("Invalid number specified: %s\n", ptr);
			errno = ERANGE;
			return errno;
		}
		return 0;
}

static void read_rdnss(struct cf_interface *iface, config_setting_t *interface_settings) {
	config_setting_t *rdnss = config_setting_get_member(interface_settings, "allowed_rdnss");
	if (rdnss == NULL) {
		printf("Not reading any allowed rdnss for %s\n", iface->ifname);
		return;
	}
		
	iface->rdnss_count = config_setting_length(rdnss);
	for (int i = 0; i < iface->rdnss_count; i++) {
		const char *string = config_setting_get_string_elem(rdnss, i);
		if (string == NULL) {
			printf("Error getting RDNSS at index %d: %d: %s\n", i, errno, strerror(errno));
			break;
		}
		/* Convert the address string to an IPv6 address struct */
		struct in6_addr addr;
		int rv = inet_pton(AF_INET6, string, &addr);
		if (!rv) {
			printf("Error converting address (%s) to structure: %d: %s\n", string, errno, strerror(errno));
			break;
		}
		memcpy(&iface->rdnss[i], &addr, sizeof(struct in6_addr));
		hexdump("addr", &addr, sizeof(struct in6_addr));
	}
}
static void read_dnssl(struct cf_interface *iface, config_setting_t *interface_settings) {
	config_setting_t *dnssl = config_setting_get_member(interface_settings, "allowed_dnssl");
	if (dnssl == NULL) {
		printf("Not reading any allowed dnssl for %s\n", iface->ifname);
		return;
	}
		
	iface->dnssl_count = config_setting_length(dnssl);
	for (int i = 0; i < iface->dnssl_count; i++) {
		const char *string = config_setting_get_string_elem(dnssl, i);
		if (string == NULL) {
			printf("Error getting DNSSL at index %d: %d: %s\n", i, errno, strerror(errno));
			break;
		}
		strncpy(iface->dnssl[i], string, HOST_NAME_MAX);
		iface->dnssl[i][HOST_NAME_MAX] = '\0';
		printf("%s\n", iface->dnssl[i]);
	}
}

static void read_prefixes(struct cf_interface *iface, config_setting_t *interface_settings) {
	config_setting_t *prefixes = config_setting_get_member(interface_settings, "allowed_prefixes");
	if (prefixes == NULL) {
		printf("Not reading any allowed_prefixes for %s\n", iface->ifname);
		return;
	}
	iface->prefix_count = config_setting_length(prefixes);
	for (int i = 0; i < iface->prefix_count; i++) {
		const char *string = config_setting_get_string_elem(prefixes, i);
		if (string == NULL) {
			printf("Error getting prefix: %d: %s\n", errno, strerror(errno));
			break;
		}
		/* Split the prefix and length */
		char tmp[strlen(string)+1];
		memcpy(tmp, string, strlen(string)+1);
		char *ptr = tmp;
		while (*ptr != '\0') {
			if (*ptr == '/') {
				*ptr = '\0';
				ptr++;
				break;
			}
			ptr++;
		}
		/* Convert the prefix string to an IPv6 address struct */
		struct in6_addr prefix;
		int rv = inet_pton(AF_INET6, tmp, &prefix);
		if (!rv) {
			printf("Error converting prefix (%s) to IPv6 address: %d: %s\n", string, errno, strerror(errno));
			break;
		}
		hexdump("prefix", &prefix, sizeof(struct in6_addr));

		/* Convert the prefix to an integer */
		long prefix_len;
		rv = strtolong(ptr, 1, 127, &prefix_len);
		if (rv) {
			fprintf(stderr, "Error parsing prefix %s: %d: %s\n", string, errno, strerror(errno));
			break;
		}

		/* Only if it's all good, write to the state list 
		 * FIXME When configuration errors occur, there will be 0 prefixes with 0 length. */
		iface->prefix_len[i] = prefix_len;
		memcpy(&iface->prefix[i], &prefix, sizeof(struct in6_addr));
		
	}

}
void read_configuration(int signo) {
	UNUSED(signo);

	config_setting_t *interfaces;


	config_destroy(cf);
	config_init(cf);

	fprintf(stderr, "Reading configuration file\n");
	int rv = config_read_file(cf, conf_file);
	if (rv != CONFIG_TRUE) {
		fprintf(stderr, "Error reading configuration file %s:%d - %s\n",
				config_error_file(cf),
				config_error_line(cf),
				config_error_text(cf));
        config_destroy(cf);
		return;
	}
	
	interfaces = config_lookup(cf, "interfaces");
	if (!interfaces) {
		fprintf(stderr, "No interfaces config.\n");
		return;
	}
	state.iface_count = config_setting_length(interfaces);
	if (state.iface_count == 0) {
		fprintf(stderr, "Error: No interfaces defined in the configuration file.\n");
		return;
	}
	state.interfaces = realloc(state.interfaces, state.iface_count*sizeof(struct cf_interface));
	if (!state.interfaces) {
		fprintf(stderr, "MEMORY ALLOCATION ERROR\n");
		exit(EXIT_FAILURE);
	}
	memset(state.interfaces, 0, state.iface_count*sizeof(struct cf_interface));
	for (int i = 0; i < state.iface_count; i++) {
		config_setting_t *interface_settings = config_setting_get_elem(interfaces, i);
		if (!interface_settings) {
			fprintf(stderr, "%s:%d - %s\n",
					config_error_file(cf),
					config_error_line(cf),
					config_error_text(cf));
			return;
		}
		printf("Parsing configuration for interface %s\n", config_setting_name(interface_settings));
		strncpy(state.interfaces[i].ifname, config_setting_name(interface_settings), IF_NAMESIZE);
		state.interfaces[i].ifname[IF_NAMESIZE] = '\0';
		read_prefixes(&state.interfaces[i], interface_settings);
		read_rdnss(&state.interfaces[i], interface_settings);
		read_dnssl(&state.interfaces[i], interface_settings);
		rv = config_setting_lookup_int(interface_settings, "allowed_mtu", &state.interfaces[i].allowed_mtu);
		if (rv != CONFIG_TRUE) {
			fprintf(stderr, "Allowed MTU not found, guarding MTU 1500.\n");
			state.interfaces[i].allowed_mtu = 1500;
			break;
		}
	}
}
