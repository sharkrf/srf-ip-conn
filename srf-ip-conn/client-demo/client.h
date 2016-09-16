/*

Copyright (c) 2016 SharkRF OÜ. https://www.sharkrf.com/
Author: Norbert "Nonoo" Varga, HA2NON

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.

*/

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
