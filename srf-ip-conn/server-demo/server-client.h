#ifndef SERVER_CLIENT_H_
#define SERVER_CLIENT_H_

#include "srf-ip-conn-packets.h"
#include "types.h"

#include <netinet/in.h>

typedef struct {
	uint32_t client_id;
	uint8_t token[8];
	flag_t logged_in;
	struct sockaddr from_addr;
	time_t last_valid_packet_got_at;
} server_client_t;

extern server_client_t server_client;

void server_client_login(uint32_t client_id, uint8_t token[SRF_IP_CONN_TOKEN_LENGTH], struct sockaddr *from_addr);
flag_t server_client_is_logged_in(struct sockaddr *from_addr);
void server_client_got_valid_packet(void);
void server_client_config(srf_ip_conn_config_payload_t *config_payload);
void server_client_logout(void);
void server_client_process(void);

#endif
