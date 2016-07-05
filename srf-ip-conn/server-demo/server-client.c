#include "server-client.h"
#include "sock.h"

#include <string.h>
#include <time.h>

// We handle only one client at a time.
server_client_t server_client = { .logged_in = 0, .last_valid_packet_got_at = 0 };

void server_client_login(uint32_t client_id, uint8_t token[SRF_IP_CONN_TOKEN_LENGTH], struct sockaddr *from_addr) {
	server_client_logout();

	server_client.client_id = client_id;
	memcpy(server_client.token, token, SRF_IP_CONN_TOKEN_LENGTH);
	memcpy(&server_client.from_addr, from_addr, sizeof(struct sockaddr));
	server_client_got_valid_packet();
	server_client.logged_in = 1;
	printf("  client %u logged in\n", client_id);
}

flag_t server_client_is_logged_in(struct sockaddr *from_addr) {
	if (!server_client.logged_in)
		return 0;

	if (from_addr->sa_family != server_client.from_addr.sa_family)
		return 0;

	if (from_addr->sa_family == AF_INET) {
		return (SOCK_ADDR_IN_ADDR(from_addr).s_addr == SOCK_ADDR_IN_ADDR(&server_client.from_addr).s_addr &&
				SOCK_ADDR_IN_PORT(from_addr) == SOCK_ADDR_IN_PORT(&server_client.from_addr));
	} else {
		return (memcmp(&SOCK_ADDR_IN6_ADDR(from_addr),
				&SOCK_ADDR_IN6_ADDR(&server_client.from_addr),
				sizeof(SOCK_ADDR_IN6_ADDR(from_addr))) == 0 &&
				SOCK_ADDR_IN6_PORT(from_addr) == SOCK_ADDR_IN6_PORT(&server_client.from_addr));
	}
}

void server_client_got_valid_packet(void) {
	time(&server_client.last_valid_packet_got_at);
}

void server_client_config(srf_ip_conn_config_payload_t *config_payload) {
	// Only printing the info, we don't store it in the API example.
	config_payload->operator_callsign[sizeof(config_payload->operator_callsign)-1] = 0;
	printf("    operator callsign: %s\n", config_payload->operator_callsign);
	config_payload->hw_manufacturer[sizeof(config_payload->hw_manufacturer)-1] = 0;
	printf("    hw manufacturer: %s\n", config_payload->hw_manufacturer);
	config_payload->hw_model[sizeof(config_payload->hw_model)-1] = 0;
	printf("    hw model: %s\n", config_payload->hw_model);
	config_payload->hw_version[sizeof(config_payload->hw_version)-1] = 0;
	printf("    hw version: %s\n", config_payload->hw_version);
	config_payload->sw_version[sizeof(config_payload->sw_version)-1] = 0;
	printf("    sw version: %s\n", config_payload->sw_version);
	printf("    rx freq: %u\n", ntohl(config_payload->rx_freq));
	printf("    tx freq: %u\n", ntohl(config_payload->tx_freq));
	printf("    tx power: %u dbm\n", config_payload->tx_power);
	printf("    latitude: %f\n", config_payload->latitude);
	printf("    longitude: %f\n", config_payload->longitude);
	printf("    height: %d m\n", ntohs(config_payload->height_agl));
	config_payload->location[sizeof(config_payload->location)-1] = 0;
	printf("    location: %s\n", config_payload->location);
	config_payload->description[sizeof(config_payload->description)-1] = 0;
	printf("    description: %s\n", config_payload->description);
}

void server_client_logout(void) {
	if (!server_client.logged_in)
		return;

	printf("  client %u logged out\n", server_client.client_id);
	server_client.logged_in = 0;
}

void server_client_process(void) {
	if (server_client.logged_in && time(NULL)-server_client.last_valid_packet_got_at > 30) {
		printf("server-client: client timeout\n");
		server_client_logout();
	}
}
