#include "srf-ip-conn/common/sock.h"

// Get sockaddr, IPv4 or IPv6.
void *sock_get_in_addr(struct sockaddr *sa) {
	if (sa->sa_family == AF_INET)
		return &SOCK_ADDR_IN_ADDR(sa);
	return &SOCK_ADDR_IN6_ADDR(sa);
}

// Get port, IPv4 or IPv6.
uint16_t sock_get_port(struct sockaddr *sa) {
	if (sa->sa_family == AF_INET)
		return SOCK_ADDR_IN_PORT(sa);
	return SOCK_ADDR_IN6_PORT(sa);
}
