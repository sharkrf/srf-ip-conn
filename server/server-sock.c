#include "server-sock.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>

// Get sockaddr, IPv4 or IPv6.
static void *server_sock_get_in_addr(struct sockaddr *sa) {
	if (sa->sa_family == AF_INET)
		return &(((struct sockaddr_in*)sa)->sin_addr);
	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

// Returns 1 if socket can be read. Returns -1 on error.
static int server_sock_check_read(int sockfd) {
	fd_set rfds;
	struct timeval timeout = { .tv_sec = 1, .tv_usec = 0 };

	FD_ZERO(&rfds);
	FD_SET(sockfd, &rfds);

	switch (select(sockfd+1, &rfds, NULL, NULL, &timeout)) {
		case -1:
			fprintf(stderr, "server-sock error: select() error\n");
			return -1;
		case 0: // Timeout
			return 0;
		default:
			return FD_ISSET(sockfd, &rfds);
	}
}

// Receives UDP packet to buf. Returns 1 if a packet has been received, return -1 on error.
int server_sock_receive(int sockfd, uint8_t *buf, uint16_t buflen) {
	int numbytes;
	struct sockaddr_storage their_addr;
	socklen_t addr_len;
	char s[INET6_ADDRSTRLEN];

	switch (server_sock_check_read(sockfd)) {
		case -1: return -1;
		case 0: return 0;
		default:
			addr_len = sizeof(their_addr);
			if ((numbytes = recvfrom(sockfd, buf, buflen, 0, (struct sockaddr *)&their_addr, &addr_len)) == -1)
				return -1;

			printf("server-sock: got %u bytes packet from %s\n", numbytes,
					inet_ntop(their_addr.ss_family, server_sock_get_in_addr((struct sockaddr *)&their_addr), s, sizeof(s)));
			return numbytes;
	}
}

int server_sock_init(uint16_t port, flag_t ipv4_only) {
	struct addrinfo hints, *servinfo, *p;
	int res = -1;
	int optval;
	char port_str[6];
	char s[INET6_ADDRSTRLEN];

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = ipv4_only ? AF_INET : AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;

	snprintf(port_str, sizeof(port_str), "%u", port);
	if ((res = getaddrinfo(NULL, port_str, &hints, &servinfo)) != 0) {
		fprintf(stderr, "server-sock error: getaddrinfo error: %s\n", gai_strerror(res));
		return -1;
	}

	// Loop through all the results and bind to the first we can.
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((res = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
			continue;

		if (bind(res, p->ai_addr, p->ai_addrlen) == -1) {
			close(res);
			continue;
		}
		break;
	}

	if (p == NULL) {
		fprintf(stderr, "server-sock error: failed to bind socket\n");
		return -1;
	}

	printf("server-sock: bound to %s\n",
			inet_ntop(p->ai_addr->sa_family, server_sock_get_in_addr((struct sockaddr *)&p->ai_addr), s, sizeof(s)));

	freeaddrinfo(servinfo);

	// Setting TOS.
	optval = 184;
	setsockopt(res, IPPROTO_IP, IP_TOS, &optval, sizeof(optval));

	return res;
}
