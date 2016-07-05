#ifndef CLIENT_H_
#define CLIENT_H_

#include "types.h"
#include "srf-ip-conn-packet.h"

#define CLIENT_STATE_INIT			0
#define CLIENT_STATE_LOGIN_SENT		1
#define CLIENT_STATE_AUTH_SENT		2
#define CLIENT_STATE_CONFIG_SENT	3
#define CLIENT_STATE_CONNECTED		4
#define CLIENT_STATE_CLOSED			5
typedef uint8_t client_state_t;

extern uint32_t client_id;
extern client_state_t client_state;
extern uint8_t client_token[SRF_IP_CONN_TOKEN_LENGTH];

void client_got_valid_packet(void);

void client_got_token(uint8_t token[SRF_IP_CONN_TOKEN_LENGTH]);
void client_got_ack(srf_ip_conn_ack_result_t ack_result);
void client_got_nak(srf_ip_conn_nak_result_t nak_result);
void client_got_pong(void);

void client_send_close(void);

flag_t client_process(void);

#endif
