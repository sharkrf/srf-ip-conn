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

#ifndef SERVER_CLIENT_H_
#define SERVER_CLIENT_H_

#include "srf-ip-conn-packet.h"
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
