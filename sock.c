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
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <stdio.h>
#include <errno.h>


int open_icmpv6_socket(void) {
    int sock;
    struct icmp6_filter filter;
    int err;

    sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (sock < 0) {
        fprintf(stderr, "Can't create socket(AF_INET6): %s\n", strerror(errno));
        return -1;
    }

    err = setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, (int[]){1}, (socklen_t)sizeof(int));
    if (err < 0) {
        fprintf(stderr, "setsockopt(IPV6_RECVPKTINFO): %s\n", strerror(errno));
        return -1;
    }

    err = setsockopt(sock, IPPROTO_RAW, IPV6_CHECKSUM, (int[]){2}, (socklen_t)sizeof(int));
    if (err < 0) {
        fprintf(stderr, "setsockopt(IPV6_CHECKSUM): %s\n", strerror(errno));
        return -1;
    }

    err = setsockopt(sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, (int[]){255}, (socklen_t)sizeof(int));
    if (err < 0) {
        fprintf(stderr, "setsockopt(IPV6_UNICAST_HOPS): %s\n", strerror(errno));
        return -1;
    }

    err = setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, (int[]){255}, (socklen_t)sizeof(int));
    if (err < 0) {
        fprintf(stderr, "setsockopt(IPV6_MULTICAST_HOPS): %s\n", strerror(errno));
        return -1;
    }
    err = setsockopt(sock, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, (int[]){1}, (socklen_t)sizeof(int));
    if (err < 0) {
        fprintf(stderr, "setsockopt(IPV6_RECVHOPLIMIT): %s\n", strerror(errno));
        return -1;
    }

    /* Select only the ICMPv6 types that we want */
    ICMP6_FILTER_SETBLOCKALL(&filter);
    ICMP6_FILTER_SETPASS(ND_ROUTER_SOLICIT, &filter);
    ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT, &filter);

    err = setsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, (socklen_t)sizeof(filter));
    if (err < 0) {
        fprintf(stderr, "setsockopt(ICMPV6_FILTER): %s", strerror(errno));
        return -1;
    }

    return sock;
}
