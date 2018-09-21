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

#include "packet.h"
#include "client.h"
#include "client-sock.h"
#include "config.h"

#include <string.h>

static void packet_process_token(void) {
	srf_ip_conn_packet_t *packet = (srf_ip_conn_packet_t *)client_sock_received_packet.buf;

	if (client_sock_received_packet.received_bytes != sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_token_payload_t)) {
		printf("  packet is %zd bytes, not %lu, ignoring\n", client_sock_received_packet.received_bytes, sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_token_payload_t));
		return;
	}

	client_got_token(packet->token.token);
}

static void packet_process_ack(void) {
	srf_ip_conn_packet_t *packet = (srf_ip_conn_packet_t *)client_sock_received_packet.buf;

	if (client_sock_received_packet.received_bytes != sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_ack_payload_t)) {
		printf("  packet is %zd bytes, not %lu, ignoring\n", client_sock_received_packet.received_bytes, sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_ack_payload_t));
		return;
	}
	if (!srf_ip_conn_packet_hmac_check(client_token, CONFIG_PASSWORD, packet, sizeof(srf_ip_conn_ack_payload_t))) {
		printf("  invalid hmac, ignoring ack packet\n");
		return;
	}

	client_got_ack(packet->ack.result);
}

static void packet_process_nak(void) {
	srf_ip_conn_packet_t *packet = (srf_ip_conn_packet_t *)client_sock_received_packet.buf;

	if (client_sock_received_packet.received_bytes != sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_nak_payload_t)) {
		printf("  packet is %zd bytes, not %lu, ignoring\n", client_sock_received_packet.received_bytes, sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_nak_payload_t));
		return;
	}
	if (!srf_ip_conn_packet_hmac_check(client_token, CONFIG_PASSWORD, packet, sizeof(srf_ip_conn_nak_payload_t))) {
		printf("  invalid hmac, ignoring nak packet\n");
		return;
	}

	client_got_nak(packet->nak.result);
}

static void packet_process_pong(void) {
	srf_ip_conn_packet_t *packet = (srf_ip_conn_packet_t *)client_sock_received_packet.buf;

	if (client_sock_received_packet.received_bytes != sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_pong_payload_t)) {
		printf("  packet is %zd bytes, not %lu, ignoring\n", client_sock_received_packet.received_bytes, sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_pong_payload_t));
		return;
	}
	if (!srf_ip_conn_packet_hmac_check(client_token, CONFIG_PASSWORD, packet, sizeof(srf_ip_conn_pong_payload_t))) {
		printf("  invalid hmac, ignoring pong packet\n");
		return;
	}

	client_got_pong();
}

static void packet_process_raw(void) {
	srf_ip_conn_packet_t *packet = (srf_ip_conn_packet_t *)client_sock_received_packet.buf;

	if (client_sock_received_packet.received_bytes != sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_data_raw_payload_t)) {
		printf("  packet is %zd bytes, not %lu, ignoring\n", client_sock_received_packet.received_bytes, sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_data_raw_payload_t));
		return;
	}
	if (!srf_ip_conn_packet_hmac_check(client_token, CONFIG_PASSWORD, packet, sizeof(srf_ip_conn_data_raw_payload_t))) {
		printf("  invalid hmac, ignoring packet\n");
		return;
	}

	srf_ip_conn_packet_print_data_raw_payload(&packet->data_raw);
	client_got_valid_packet();
}

static void packet_process_dmr(void) {
	srf_ip_conn_packet_t *packet = (srf_ip_conn_packet_t *)client_sock_received_packet.buf;

	if (client_sock_received_packet.received_bytes != sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_data_dmr_payload_t)) {
		printf("  packet is %zd bytes, not %lu, ignoring\n", client_sock_received_packet.received_bytes, sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_data_dmr_payload_t));
		return;
	}
	if (!srf_ip_conn_packet_hmac_check(client_token, CONFIG_PASSWORD, packet, sizeof(srf_ip_conn_data_dmr_payload_t))) {
		printf("  invalid hmac, ignoring packet\n");
		return;
	}

	srf_ip_conn_packet_print_data_dmr_payload(&packet->data_dmr);
	client_got_valid_packet();
}

static void packet_process_dstar(void) {
	srf_ip_conn_packet_t *packet = (srf_ip_conn_packet_t *)client_sock_received_packet.buf;

	if (client_sock_received_packet.received_bytes != sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_data_dstar_payload_t)) {
		printf("  packet is %zd bytes, not %lu, ignoring\n", client_sock_received_packet.received_bytes, sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_data_dstar_payload_t));
		return;
	}
	if (!srf_ip_conn_packet_hmac_check(client_token, CONFIG_PASSWORD, packet, sizeof(srf_ip_conn_data_dstar_payload_t))) {
		printf("  invalid hmac, ignoring packet\n");
		return;
	}

	srf_ip_conn_packet_print_data_dstar_payload(&packet->data_dstar);
	client_got_valid_packet();
}

static void packet_process_c4fm(void) {
	srf_ip_conn_packet_t *packet = (srf_ip_conn_packet_t *)client_sock_received_packet.buf;

	if (client_sock_received_packet.received_bytes != sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_data_c4fm_payload_t)) {
		printf("  packet is %zd bytes, not %lu, ignoring\n", client_sock_received_packet.received_bytes, sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_data_c4fm_payload_t));
		return;
	}
	if (!srf_ip_conn_packet_hmac_check(client_token, CONFIG_PASSWORD, packet, sizeof(srf_ip_conn_data_c4fm_payload_t))) {
		printf("  invalid hmac, ignoring packet\n");
		return;
	}

	srf_ip_conn_packet_print_data_c4fm_payload(&packet->data_c4fm);
	client_got_valid_packet();
}

static void packet_process_nxdn(void) {
	srf_ip_conn_packet_t *packet = (srf_ip_conn_packet_t *)client_sock_received_packet.buf;

	if (client_sock_received_packet.received_bytes != sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_data_nxdn_payload_t)) {
		printf("  packet is %zd bytes, not %lu, ignoring\n", client_sock_received_packet.received_bytes, sizeof(srf_ip_conn_packet_header_t)+sizeof(srf_ip_conn_data_nxdn_payload_t));
		return;
	}
	if (!srf_ip_conn_packet_hmac_check(client_token, CONFIG_PASSWORD, packet, sizeof(srf_ip_conn_data_nxdn_payload_t))) {
		printf("  invalid hmac, ignoring packet\n");
		return;
	}

	srf_ip_conn_packet_print_data_nxdn_payload(&packet->data_nxdn);
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
				case SRF_IP_CONN_PACKET_TYPE_DATA_NXDN:
					packet_process_nxdn();
					break;
			}
			break;
	}
}
