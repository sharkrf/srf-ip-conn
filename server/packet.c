#include "packet.h"
#include "server-sock.h"

#include <stdlib.h>

static struct {
	uint32_t client_id;
	uint8_t given_token[8];
} packet_new_connection_data;

static void packet_process_login(void) {
	srf_ip_conn_login_t *packet = (srf_ip_conn_login_t *)(server_sock_received_packet.buf+sizeof(srf_ip_conn_header_t));
	srf_ip_conn_token_t answer;
	uint8_t i;

	if (server_sock_received_packet.received_bytes != sizeof(srf_ip_conn_header_t)+sizeof(srf_ip_conn_login_t)) {
		printf("  packet is %u bytes, not %lu, ignoring\n", server_sock_received_packet.received_bytes, sizeof(srf_ip_conn_header_t)+sizeof(srf_ip_conn_login_t));
		return;
	}

	packet_new_connection_data.client_id = packet->client_id;
	printf("  got login packet from id %u, answering with token ", packet->client_id);
	for (i = 0; i < sizeof(packet_new_connection_data.given_token); i++) {
		packet_new_connection_data.given_token[i] = answer.token[i] = rand();
		printf("%.2x", answer.token[i]);
	}
	printf("\n");

	server_sock_send((uint8_t *)&answer, sizeof(answer), &server_sock_received_packet.from_addr);
}

static void packet_process_auth(void) {
	// TODO
}

static void packet_process_config(void) {
	// TODO
}

static void packet_process_ping(void) {
	// TODO
}

static void packet_process_close(void) {
	// TODO
}

static void packet_process_raw(void) {
	// TODO
}

static void packet_process_dmr(void) {
	// TODO
}

static void packet_process_dstar(void) {
	// TODO
}

static void packet_process_c4fm(void) {
	// TODO
}

void packet_process(void) {
	srf_ip_conn_header_t *header = (srf_ip_conn_header_t *)server_sock_received_packet.buf;

	if (header->version != 0)
		return;

	switch (header->pkt_type) {
		case SRF_IP_CONN_PKT_TYPE_LOGIN:
			packet_process_login();
			break;
		case SRF_IP_CONN_PKT_TYPE_AUTH:
			packet_process_auth();
			break;
		case SRF_IP_CONN_PKT_TYPE_CONFIG:
			packet_process_config();
			break;
		case SRF_IP_CONN_PKT_TYPE_PING:
			packet_process_ping();
			break;
		case SRF_IP_CONN_PKT_TYPE_CLOSE:
			packet_process_close();
			break;
		case SRF_IP_CONN_PKT_TYPE_DATA_RAW:
			packet_process_raw();
			break;
		case SRF_IP_CONN_PKT_TYPE_DATA_DMR:
			packet_process_dmr();
			break;
		case SRF_IP_CONN_PKT_TYPE_DATA_DSTAR:
			packet_process_dstar();
			break;
		case SRF_IP_CONN_PKT_TYPE_DATA_C4FM:
			packet_process_c4fm();
			break;
	}
}
