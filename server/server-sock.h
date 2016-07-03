#ifndef SERVER_SOCK_H_
#define SERVER_SOCK_H_

#include "srf-ip-conn-packets.h"

#include <sys/socket.h>

typedef struct {
	uint8_t buf[SRF_IP_CONN_PACKETS_MAX_SIZE];
	uint16_t received_bytes;
	struct sockaddr_storage from_addr;
} server_sock_received_packet_t;

extern server_sock_received_packet_t server_sock_received_packet;

int server_sock_receive(void);
flag_t server_sock_send(uint8_t *buf, uint16_t buflen, struct sockaddr_storage *dst_addr);

flag_t server_sock_init(uint16_t port, flag_t ipv4_only);
void server_sock_deinit(void);

#endif
