#define _GNU_SOURCE
#include <sys/socket.h>
#include <netinet/in.h>
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
        fprintf(stderr, "can't create socket(AF_INET6): %s", strerror(errno));
        return -1;
    }

    err = setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, (int[]){1}, sizeof(int));
    if (err < 0) {
        fprintf(stderr, "setsockopt(IPV6_RECVPKTINFO): %s", strerror(errno));
        return -1;
    }

    err = setsockopt(sock, IPPROTO_RAW, IPV6_CHECKSUM, (int[]){2}, sizeof(int));
    if (err < 0) {
        fprintf(stderr, "setsockopt(IPV6_CHECKSUM): %s", strerror(errno));
        return -1;
    }

    err = setsockopt(sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, (int[]){255}, sizeof(int));
    if (err < 0) {
        fprintf(stderr, "setsockopt(IPV6_UNICAST_HOPS): %s", strerror(errno));
        return -1;
    }

    err = setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, (int[]){255}, sizeof(int));
    if (err < 0) {
        fprintf(stderr, "setsockopt(IPV6_MULTICAST_HOPS): %s", strerror(errno));
        return -1;
    }
    err = setsockopt(sock, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, (int[]){1}, sizeof(int));
    if (err < 0) {
        fprintf(stderr, "setsockopt(IPV6_RECVHOPLIMIT): %s", strerror(errno));
        return -1;
    }

    /* Select only the ICMPv6 types that we want */
    ICMP6_FILTER_SETBLOCKALL(&filter);
    ICMP6_FILTER_SETPASS(ND_ROUTER_SOLICIT, &filter);
    ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT, &filter);

    err = setsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter));
    if (err < 0) {
        fprintf(stderr, "setsockopt(ICMPV6_FILTER): %s", strerror(errno));
        return -1;
    }

    return sock;
}
