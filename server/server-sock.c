#include "server-sock.h"
#include "sock.h"

#include <netdb.h>
#include <unistd.h>
#include <string.h>

// As we deal with only one received packet at a time, we store it in this struct.
server_sock_received_packet_t server_sock_received_packet;
static int server_sock_fd = -1;

// Returns 1 if socket can be read. Returns -1 on error.
static int server_sock_check_read(void) {
	fd_set rfds;
	struct timeval timeout = { .tv_sec = 1, .tv_usec = 0 }; // Blocking only for 1 second.

	if (server_sock_fd < 0)
		return -1;

	FD_ZERO(&rfds);
	FD_SET(server_sock_fd, &rfds);

	switch (select(server_sock_fd+1, &rfds, NULL, NULL, &timeout)) {
		case -1:
			fprintf(stderr, "server-sock error: select() error\n");
			return -1;
		case 0: // Timeout
			return 0;
		default:
			return FD_ISSET(server_sock_fd, &rfds);
	}
}

// Receives UDP packet to server_sock_received_packet.
// Returns received number of bytes if a packet has been received, and -1 on error.
int server_sock_receive(void) {
	socklen_t addr_len;
	char s[INET6_ADDRSTRLEN];

	switch (server_sock_check_read()) {
		case -1: return -1;
		case 0: return 0;
		default:
			addr_len = sizeof(server_sock_received_packet.from_addr);
			if ((server_sock_received_packet.received_bytes = recvfrom(server_sock_fd, server_sock_received_packet.buf, sizeof(server_sock_received_packet.buf), 0, (struct sockaddr *)&server_sock_received_packet.from_addr, &addr_len)) == -1)
				return -1;

			printf("server-sock: got %u byte packet from %s:%u\n", server_sock_received_packet.received_bytes,
					inet_ntop(server_sock_received_packet.from_addr.sa_family, sock_get_in_addr(&server_sock_received_packet.from_addr), s, sizeof(s)),
					sock_get_port(&server_sock_received_packet.from_addr));
			return server_sock_received_packet.received_bytes;
	}
}

// Sends packet given in buf with size buflen to dst_addr.
flag_t server_sock_send(uint8_t *buf, uint16_t buflen, struct sockaddr *dst_addr) {
	socklen_t addr_len = sizeof(struct sockaddr);

	return (sendto(server_sock_fd, buf, buflen, 0, dst_addr, addr_len) == buflen);
}

// Returns 1 if initialization was successful, 0 on error.
flag_t server_sock_init(uint16_t port, flag_t ipv4_only) {
	struct addrinfo hints, *servinfo, *p;
	int optval;
	char port_str[6];
	char s[INET6_ADDRSTRLEN];

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = ipv4_only ? AF_INET : AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;

	snprintf(port_str, sizeof(port_str), "%u", port);
	if ((server_sock_fd = getaddrinfo(NULL, port_str, &hints, &servinfo)) != 0) {
		fprintf(stderr, "server-sock error: getaddrinfo error: %s\n", gai_strerror(server_sock_fd));
		server_sock_fd = -1;
		return 0;
	}

	// Loop through all the results and bind to the first we can.
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((server_sock_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
			continue;

		if (bind(server_sock_fd, p->ai_addr, p->ai_addrlen) == -1) {
			close(server_sock_fd);
			continue;
		}
		break;
	}

	if (p == NULL) {
		fprintf(stderr, "server-sock error: failed to bind socket\n");
		server_sock_fd = -1;
		return 0;
	}

	printf("server-sock: bound to %s\n",
			inet_ntop(p->ai_addr->sa_family, sock_get_in_addr((struct sockaddr *)&p->ai_addr), s, sizeof(s)));

	freeaddrinfo(servinfo);

	// Setting TOS.
	optval = 184;
	setsockopt(server_sock_fd, IPPROTO_IP, IP_TOS, &optval, sizeof(optval));

	return 1;
}

void server_sock_deinit(void) {
	close(server_sock_fd);
	server_sock_fd = -1;
}
