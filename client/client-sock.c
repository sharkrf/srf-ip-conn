#include "client-sock.h"
#include "sock.h"

#include <netdb.h>
#include <unistd.h>
#include <string.h>

// As we deal with only one received packet at a time, we store it in this struct.
client_sock_received_packet_t client_sock_received_packet;
static int client_sock_fd = -1;
static struct sockaddr client_sock_server_addr;

// Returns 1 if socket can be read. Returns -1 on error.
static int client_sock_check_read(void) {
	fd_set rfds;
	struct timeval timeout = { .tv_sec = 1, .tv_usec = 0 }; // Blocking only for 1 second.

	if (client_sock_fd < 0)
		return -1;

	FD_ZERO(&rfds);
	FD_SET(client_sock_fd, &rfds);

	switch (select(client_sock_fd+1, &rfds, NULL, NULL, &timeout)) {
		case -1:
			fprintf(stderr, "client-sock error: select() error\n");
			return -1;
		case 0: // Timeout
			return 0;
		default:
			return FD_ISSET(client_sock_fd, &rfds);
	}
}

// Receives UDP packet to client_sock_received_packet.
// Returns received number of bytes if a packet has been received, and -1 on error.
int client_sock_receive(void) {
	socklen_t addr_len;
	char s[INET6_ADDRSTRLEN];
	struct sockaddr from_addr;

	switch (client_sock_check_read()) {
		case -1: return -1;
		case 0: return 0;
		default:
			addr_len = sizeof(from_addr);
			if ((client_sock_received_packet.received_bytes = recvfrom(client_sock_fd, client_sock_received_packet.buf, sizeof(client_sock_received_packet.buf), 0, (struct sockaddr *)&from_addr, &addr_len)) == -1)
				return -1;

			printf("client-sock: got %u byte packet from %s:%u\n", client_sock_received_packet.received_bytes,
					inet_ntop(from_addr.sa_family, sock_get_in_addr(&from_addr), s, sizeof(s)),
					sock_get_port(&from_addr));
			return client_sock_received_packet.received_bytes;
	}
}

// Sends packet given in buf with size buflen to dst_addr.
flag_t client_sock_send(uint8_t *buf, uint16_t buflen) {
	socklen_t addr_len = sizeof(struct sockaddr);

	return (sendto(client_sock_fd, buf, buflen, 0, (struct sockaddr *)&client_sock_server_addr, addr_len) == buflen);
}

// Returns 1 if initialization was successful, 0 on error.
flag_t client_sock_connect(char *host, uint16_t port, flag_t ipv4_only) {
	struct addrinfo hints, *servinfo, *p;
	int optval;
	char port_str[6];

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = ipv4_only ? AF_INET : AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;

	snprintf(port_str, sizeof(port_str), "%u", port);
	if ((client_sock_fd = getaddrinfo(host, port_str, &hints, &servinfo)) != 0) {
		fprintf(stderr, "client-sock error: getaddrinfo error: %s\n", gai_strerror(client_sock_fd));
		client_sock_fd = -1;
		return 0;
	}

	// Loop through all the results and bind to the first we can.
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((client_sock_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
			continue;

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "client-sock error: failed to create socket\n");
		client_sock_fd = -1;
		return 0;
	}

	freeaddrinfo(servinfo);
	memcpy(&client_sock_server_addr, p->ai_addr, min(sizeof(client_sock_server_addr), p->ai_addrlen));

	// Setting TOS.
	optval = 184;
	setsockopt(client_sock_fd, IPPROTO_IP, IP_TOS, &optval, sizeof(optval));

	return 1;
}

void client_sock_deinit(void) {
	close(client_sock_fd);
	client_sock_fd = -1;
}
