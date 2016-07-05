#ifndef CLIENT_SOCK_H_
#define CLIENT_SOCK_H_

#include "srf-ip-conn-packet.h"

#include <netinet/in.h>

typedef struct {
	uint8_t buf[sizeof(srf_ip_conn_packet_t)];
	uint16_t received_bytes;
} client_sock_received_packet_t;

extern client_sock_received_packet_t client_sock_received_packet;

int client_sock_receive(void);
flag_t client_sock_send(uint8_t *buf, uint16_t buflen);

flag_t client_sock_connect(char *host, uint16_t port, flag_t ipv4_only);
void client_sock_deinit(void);

#endif
