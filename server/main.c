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
				if (packet_is_header_valid())
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
