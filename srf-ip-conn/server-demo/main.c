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

#include "server-sock.h"
#include "server-client.h"
#include "packet.h"
#include "config.h"

#include <stdlib.h>
#include <time.h>

int main(void) {
	printf("SharkRF IP connector protocol test server application\n");

	// Seeding the random number generator.
	srand(time(NULL));

	if (!server_sock_init(CONFIG_SERVER_PORT, CONFIG_IPV4_ONLY))
		return 1;

	printf("server: starting listening loop\n");

	while (1) {
		switch (server_sock_receive()) {
			case -1: return 1;
			case 0: break;
			default:
				if (server_sock_received_packet.received_bytes >= sizeof(srf_ip_conn_packet_header_t) &&
						srf_ip_conn_packet_is_header_valid((srf_ip_conn_packet_header_t *)server_sock_received_packet.buf))
					packet_process();
				else
					printf("  not an srf ip conn packet, ignoring\n");
				break;
		}

		server_client_process();
	}

	server_sock_deinit();

	return 0;
}
