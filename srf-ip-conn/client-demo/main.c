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

#include "client-sock.h"
#include "client.h"
#include "packet.h"
#include "config.h"

#include <stdlib.h>
#include <signal.h>
#include <time.h>

static volatile flag_t main_exit_needed = 0;

static void main_sigint_handler(int signal) {
	main_exit_needed = 1;
}

int main(int argc, char **argv) {
	struct sigaction sighandler;

	printf("SharkRF IP connector protocol test client application\n");

	if (argc < 3) {
		printf("usage: %s [host] [client id]\n", argv[0]);
		return 1;
	}
	client_id = atoi(argv[2]);

	// Seeding the random number generator.
	srand(time(NULL));

	if (!client_sock_connect(argv[1], CONFIG_SERVER_PORT, CONFIG_IPV4_ONLY))
		return 1;

	// Setting up a signal handler to catch a SIGINT (CTRL+C) keypress.
	sighandler.sa_handler = main_sigint_handler;
	sigemptyset(&sighandler.sa_mask);
	sighandler.sa_flags = 0;
	sigaction(SIGINT, &sighandler, NULL);

	while (client_process() && !main_exit_needed) {
		switch (client_sock_receive()) {
			case -1: main_exit_needed = 1; break;
			case 0: break;
			default:
				if (client_sock_received_packet.received_bytes >= sizeof(srf_ip_conn_packet_header_t) &&
						srf_ip_conn_packet_is_header_valid((srf_ip_conn_packet_header_t *)client_sock_received_packet.buf))
					packet_process();
				else
					printf("  not an srf ip conn packet, ignoring\n");
				break;
		}
	}

	if (client_state == CLIENT_STATE_CONNECTED)
		client_send_close();
	client_sock_deinit();

	return 0;
}
