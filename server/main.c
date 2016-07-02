#include "server-sock.h"
#include "packet.h"

#include <unistd.h>
#include <string.h>

#define MAIN_SERVER_PORT		65100
#define MAIN_SERVER_IPV4_ONLY	1

int main(int argc, char **argv) {
	int sockfd;
	uint8_t buf[SRF_IP_CONN_PACKETS_MAX_SIZE];
	int received_bytes;

	sockfd = server_sock_init(MAIN_SERVER_PORT, MAIN_SERVER_IPV4_ONLY);
	if (sockfd < 0)
		return 1;

	printf("server: starting listening loop\n");

	while (1) {
		received_bytes = server_sock_receive(sockfd, buf, sizeof(buf));
		switch (received_bytes) {
			case -1: return 1;
			case 0: break;
			default:
				if (memcmp(buf, "SRFIPC", 6) == 0)
					packet_process(buf, received_bytes);
				else
					printf("  not an srf ip conn packet, ignoring\n");
				break;
		}
	}

	close(sockfd);

	return 0;
}
