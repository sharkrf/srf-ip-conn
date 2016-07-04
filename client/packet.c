#include "packet.h"
#include "client.h"
#include "client-sock.h"
#include "hmac.h"

#include <string.h>

void packet_init(srf_ip_conn_packet_header_t *packet_header, srf_ip_conn_packet_type_t packet_type) {
	memcpy(packet_header->magic, SRF_IP_CONN_MAGIC_STR, SRF_IP_CONN_MAGIC_STR_LENGTH);
	packet_header->packet_type = packet_type;
	packet_header->version = 0;
}

static void packet_process_token(void) {
	srf_ip_conn_packet_t *packet = (srf_ip_conn_packet_t *)client_sock_received_packet.buf;

	if (client_sock_received_packet.received_bytes != sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_token_payload_t)) {
		printf("  packet is %u bytes, not %lu, ignoring\n", client_sock_received_packet.received_bytes, sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_token_payload_t));
		return;
	}

	client_got_token(packet->token.token);
}

static void packet_process_ack(void) {
	srf_ip_conn_packet_t *packet = (srf_ip_conn_packet_t *)client_sock_received_packet.buf;

	if (client_sock_received_packet.received_bytes != sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_ack_payload_t)) {
		printf("  packet is %u bytes, not %lu, ignoring\n", client_sock_received_packet.received_bytes, sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_ack_payload_t));
		return;
	}
	if (!hmac_check(client_token, packet, sizeof(srf_ip_conn_ack_payload_t))) {
		printf("  invalid hmac, ignoring ack packet\n");
		return;
	}

	client_got_ack(packet->ack.result);
}

static void packet_process_nak(void) {
	srf_ip_conn_packet_t *packet = (srf_ip_conn_packet_t *)client_sock_received_packet.buf;

	if (client_sock_received_packet.received_bytes != sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_nak_payload_t)) {
		printf("  packet is %u bytes, not %lu, ignoring\n", client_sock_received_packet.received_bytes, sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_nak_payload_t));
		return;
	}
	if (!hmac_check(client_token, packet, sizeof(srf_ip_conn_nak_payload_t))) {
		printf("  invalid hmac, ignoring nak packet\n");
		return;
	}

	client_got_nak(packet->nak.result);
}

static void packet_process_pong(void) {
	srf_ip_conn_packet_t *packet = (srf_ip_conn_packet_t *)client_sock_received_packet.buf;

	if (client_sock_received_packet.received_bytes != sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_pong_payload_t)) {
		printf("  packet is %u bytes, not %lu, ignoring\n", client_sock_received_packet.received_bytes, sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_pong_payload_t));
		return;
	}
	if (!hmac_check(client_token, packet, sizeof(srf_ip_conn_pong_payload_t))) {
		printf("  invalid hmac, ignoring pong packet\n");
		return;
	}

	client_got_pong();
}

static void packet_process_raw(void) {
	srf_ip_conn_packet_t *packet = (srf_ip_conn_packet_t *)client_sock_received_packet.buf;

	if (client_sock_received_packet.received_bytes != sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_data_raw_payload_t)) {
		printf("  packet is %u bytes, not %lu, ignoring\n", client_sock_received_packet.received_bytes, sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_data_raw_payload_t));
		return;
	}
	if (!hmac_check(client_token, packet, sizeof(srf_ip_conn_data_raw_payload_t))) {
		printf("  invalid hmac, ignoring packet\n");
		return;
	}

	srf_ip_conn_packets_print_data_raw_payload(&packet->data_raw);
	client_got_valid_packet();
}

static void packet_process_dmr(void) {
	srf_ip_conn_packet_t *packet = (srf_ip_conn_packet_t *)client_sock_received_packet.buf;

	if (client_sock_received_packet.received_bytes != sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_data_dmr_payload_t)) {
		printf("  packet is %u bytes, not %lu, ignoring\n", client_sock_received_packet.received_bytes, sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_data_dmr_payload_t));
		return;
	}
	if (!hmac_check(client_token, packet, sizeof(srf_ip_conn_data_dmr_payload_t))) {
		printf("  invalid hmac, ignoring packet\n");
		return;
	}

	srf_ip_conn_packets_print_data_dmr_payload(&packet->data_dmr);
	client_got_valid_packet();
}

static void packet_process_dstar(void) {
	srf_ip_conn_packet_t *packet = (srf_ip_conn_packet_t *)client_sock_received_packet.buf;

	if (client_sock_received_packet.received_bytes != sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_data_dstar_payload_t)) {
		printf("  packet is %u bytes, not %lu, ignoring\n", client_sock_received_packet.received_bytes, sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_data_dstar_payload_t));
		return;
	}
	if (!hmac_check(client_token, packet, sizeof(srf_ip_conn_data_dstar_payload_t))) {
		printf("  invalid hmac, ignoring packet\n");
		return;
	}

	srf_ip_conn_packets_print_data_dstar_payload(&packet->data_dstar);
	client_got_valid_packet();
}

static void packet_process_c4fm(void) {
	srf_ip_conn_packet_t *packet = (srf_ip_conn_packet_t *)client_sock_received_packet.buf;

	if (client_sock_received_packet.received_bytes != sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_data_c4fm_payload_t)) {
		printf("  packet is %u bytes, not %lu, ignoring\n", client_sock_received_packet.received_bytes, sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_data_c4fm_payload_t));
		return;
	}
	if (!hmac_check(client_token, packet, sizeof(srf_ip_conn_data_c4fm_payload_t))) {
		printf("  invalid hmac, ignoring packet\n");
		return;
	}

	srf_ip_conn_packets_print_data_c4fm_payload(&packet->data_c4fm);
	client_got_valid_packet();
}

flag_t packet_is_header_valid(void) {
	return (client_sock_received_packet.received_bytes >= sizeof(srf_ip_conn_packet_header_t) &&
			memcmp(client_sock_received_packet.buf, SRF_IP_CONN_MAGIC_STR, SRF_IP_CONN_MAGIC_STR_LENGTH) == 0);
}

void packet_process(void) {
	srf_ip_conn_packet_header_t *header = (srf_ip_conn_packet_header_t *)client_sock_received_packet.buf;

	switch (header->version) {
		case 0:
			switch (header->packet_type) {
				case SRF_IP_CONN_PACKET_TYPE_TOKEN:
					packet_process_token();
					break;
				case SRF_IP_CONN_PACKET_TYPE_ACK:
					packet_process_ack();
					break;
				case SRF_IP_CONN_PACKET_TYPE_NAK:
					packet_process_nak();
					break;
				case SRF_IP_CONN_PACKET_TYPE_PONG:
					packet_process_pong();
					break;
				case SRF_IP_CONN_PACKET_TYPE_DATA_RAW:
					packet_process_raw();
					break;
				case SRF_IP_CONN_PACKET_TYPE_DATA_DMR:
					packet_process_dmr();
					break;
				case SRF_IP_CONN_PACKET_TYPE_DATA_DSTAR:
					packet_process_dstar();
					break;
				case SRF_IP_CONN_PACKET_TYPE_DATA_C4FM:
					packet_process_c4fm();
					break;
			}
			break;
	}
}
