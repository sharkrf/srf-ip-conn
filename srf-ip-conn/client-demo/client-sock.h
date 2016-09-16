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
