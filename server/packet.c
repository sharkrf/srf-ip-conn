#include "packet.h"

#include <stdlib.h>

static struct {
	uint32_t client_id;
	uint8_t given_token[8];
} packet_new_connection_data;

static void packet_process_login(uint8_t *buf, uint16_t buflen) {
	srf_ip_conn_login_t *packet = buf+sizeof(srf_ip_conn_header_t);
	srf_ip_conn_token_t answer;
	uint8_t i;

	if (buflen != sizeof(srf_ip_conn_header_t)+sizeof(srf_ip_conn_login_t)) {
		printf("  packet is %u bytes, not %u, ignoring\n", buflen, sizeof(srf_ip_conn_header_t)+sizeof(srf_ip_conn_login_t));
		return;
	}

	packet_new_connection_data.client_id = packet->client_id;
	printf("  got login packet from id %u, answering with token ", packet->client_id);
	for (i = 0; i < sizeof(packet_new_connection_data.given_token); i++) {
		packet_new_connection_data.given_token[i] = answer.token[i] = rand();
		printf("%.2x", answer.token[i]);
	}
	printf("\n");

	// TODO: answer send
}

static void packet_process_auth(uint8_t *buf, uint16_t buflen) {
	// TODO
}

static void packet_process_config(uint8_t *buf, uint16_t buflen) {
	// TODO
}

static void packet_process_ping(uint8_t *buf, uint16_t buflen) {
	// TODO
}

static void packet_process_close(uint8_t *buf, uint16_t buflen) {
	// TODO
}

static void packet_process_raw(uint8_t *buf, uint16_t buflen) {
	// TODO
}

static void packet_process_dmr(uint8_t *buf, uint16_t buflen) {
	// TODO
}

static void packet_process_dstar(uint8_t *buf, uint16_t buflen) {
	// TODO
}

static void packet_process_c4fm(uint8_t *buf, uint16_t buflen) {
	// TODO
}

void packet_process(uint8_t *buf, uint16_t buflen) {
	srf_ip_conn_hdr_t *header = (srf_ip_conn_hdr_t *)buf;

	if (header->version != 0)
		return;

	switch (header->pkt_type) {
		case SRF_IP_CONN_PKT_TYPE_LOGIN:
			packet_process_login(buf, buflen);
			break;
		case SRF_IP_CONN_PKT_TYPE_AUTH:
			packet_process_auth(buf, buflen);
			break;
		case SRF_IP_CONN_PKT_TYPE_CONFIG:
			packet_process_config(buf, buflen);
			break;
		case SRF_IP_CONN_PKT_TYPE_PING:
			packet_process_ping(buf, buflen);
			break;
		case SRF_IP_CONN_PKT_TYPE_CLOSE:
			packet_process_close(buf, buflen);
			break;
		case SRF_IP_CONN_PKT_TYPE_DATA_RAW:
			packet_process_raw(buf, buflen);
			break;
		case SRF_IP_CONN_PKT_TYPE_DATA_DMR:
			packet_process_dmr(buf, buflen);
			break;
		case SRF_IP_CONN_PKT_TYPE_DATA_DSTAR:
			packet_process_dstar(buf, buflen);
			break;
		case SRF_IP_CONN_PKT_TYPE_DATA_C4FM:
			packet_process_c4fm(buf, buflen);
			break;
	}
}
