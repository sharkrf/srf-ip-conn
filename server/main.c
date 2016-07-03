#include "server-sock.h"
#include "packet.h"

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#define MAIN_SERVER_PORT		65100
#define MAIN_SERVER_IPV4_ONLY	1

int main(int argc, char **argv) {
	// Seeding the random number generator.
	srand(time(NULL));

	if (!server_sock_init(MAIN_SERVER_PORT, MAIN_SERVER_IPV4_ONLY))
		return 1;

	printf("server: starting listening loop\n");

	while (1) {
		switch (server_sock_receive()) {
			case -1: return 1;
			case 0: break;
			default:
				if (memcmp(server_sock_received_packet.buf, "SRFIPC", 6) == 0)
					packet_process();
				else
					printf("  not an srf ip conn packet, ignoring\n");
				break;
		}
	}

	server_sock_deinit();

	return 0;
}
