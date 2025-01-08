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

#include "srf-ip-conn/common/srf-ip-conn-packet.h"
#include "srf-ip-conn/common/sha2.h"

#include <stdio.h>
#include <string.h>
#if FSL_RTOS_MQX
#include <rtcs.h>
#else
#include <arpa/inet.h>
#endif

void srf_ip_conn_packet_init(srf_ip_conn_packet_header_t *packet_header, srf_ip_conn_packet_type_t packet_type) {
	memcpy(packet_header->magic, SRF_IP_CONN_MAGIC_STR, SRF_IP_CONN_MAGIC_STR_LENGTH);
	packet_header->packet_type = packet_type;
	packet_header->version = 0;
}

flag_t srf_ip_conn_packet_is_header_valid(srf_ip_conn_packet_header_t *packet_header) {
	return (memcmp(packet_header->magic, SRF_IP_CONN_MAGIC_STR, SRF_IP_CONN_MAGIC_STR_LENGTH) == 0);
}

static void srf_ip_conn_packet_hash_calc(uint8_t token[SRF_IP_CONN_TOKEN_LENGTH], char password[SRF_IP_CONN_MAX_PASSWORD_LENGTH], srf_ip_conn_packet_t *packet, uint16_t payload_length, uint8_t dst[SHA256_DIGEST_SIZE]) {
	sha256_ctx ctx256;

	sha256_init(&ctx256);
	sha256_update(&ctx256, token, SRF_IP_CONN_TOKEN_LENGTH);
	sha256_update(&ctx256, (uint8_t *)password, strlen(password));
	sha256_update(&ctx256, (uint8_t *)packet + sizeof(srf_ip_conn_packet_header_t), payload_length-SHA256_DIGEST_SIZE);
	sha256_final(&ctx256, dst);
}

void srf_ip_conn_packet_hmac_add(uint8_t token[SRF_IP_CONN_TOKEN_LENGTH], char *password, srf_ip_conn_packet_t *packet, uint16_t payload_length) {
	srf_ip_conn_packet_hash_calc(token, password, packet, payload_length, (uint8_t *)packet + sizeof(srf_ip_conn_packet_header_t) + payload_length - SHA256_DIGEST_SIZE);
}

flag_t srf_ip_conn_packet_hmac_check(uint8_t token[SRF_IP_CONN_TOKEN_LENGTH], char *password, srf_ip_conn_packet_t *packet, uint16_t payload_length) {
	uint8_t hash[SHA256_DIGEST_SIZE];

	srf_ip_conn_packet_hash_calc(token, password, packet, payload_length, hash);

	// Returning 1 if calculated hash matches HMAC.
	return (memcmp((uint8_t *)packet + sizeof(srf_ip_conn_packet_header_t) + payload_length - SHA256_DIGEST_SIZE, hash, SHA256_DIGEST_SIZE) == 0);
}

void srf_ip_conn_packet_print_data_raw_payload(srf_ip_conn_data_raw_payload_t *payload) {
	uint8_t i;

	printf("  seq. no: %u\n", ntohl(payload->seq_no));
	printf("  call session id: 0x%.8x\n", ntohl(payload->call_session_id));
	printf("  rssi: %d dbm\n", payload->rssi_dbm);
	printf("  tdma channel: %u", payload->tdma_channel);
	printf("  length: %u\n", payload->length);
	printf("  payload: ");
	for (i = 0; i < sizeof(payload->data); i++)
		printf("%.2x", payload->data[i]);
	printf("\n");
}

void srf_ip_conn_packet_print_data_dmr_payload(srf_ip_conn_data_dmr_payload_t *payload) {
	uint8_t i;

	printf("  seq. no: %u\n", ntohl(payload->seq_no));
	printf("  call session id: 0x%.8x\n", ntohl(payload->call_session_id));
	printf("  dst id: %u\n", (payload->dst_id[0] << 16) | (payload->dst_id[1] << 8) | (payload->dst_id[2]));
	printf("  src id: %u\n", (payload->src_id[0] << 16) | (payload->src_id[1] << 8) | (payload->src_id[2]));
	printf("  tdma channel: %u\n", payload->tdma_channel);
	printf("  call type: %s\n", payload->call_type ? "group" : "private");
	printf("  slot type: %u ", payload->slot_type);
	switch (payload->slot_type) {
		case SRF_IP_CONN_DATA_DMR_SLOT_TYPE_VOICE_LC_HEADER: printf("voice lc header\n"); break;
		case SRF_IP_CONN_DATA_DMR_SLOT_TYPE_TERMINATOR_WITH_LC: printf("terminator with lc\n"); break;
		case SRF_IP_CONN_DATA_DMR_SLOT_TYPE_CSBK: printf("csbk\n"); break;
		case SRF_IP_CONN_DATA_DMR_SLOT_TYPE_DATA_HEADER: printf("header\n"); break;
		case SRF_IP_CONN_DATA_DMR_SLOT_TYPE_RATE_12_DATA: printf("rate 1/2 data\n"); break;
		case SRF_IP_CONN_DATA_DMR_SLOT_TYPE_RATE_34_DATA: printf("rate 3/4 data\n"); break;
		case SRF_IP_CONN_DATA_DMR_SLOT_TYPE_VOICE_DATA_A: printf("voice data a\n"); break;
		case SRF_IP_CONN_DATA_DMR_SLOT_TYPE_VOICE_DATA_B: printf("voice data b\n"); break;
		case SRF_IP_CONN_DATA_DMR_SLOT_TYPE_VOICE_DATA_C: printf("voice data c\n"); break;
		case SRF_IP_CONN_DATA_DMR_SLOT_TYPE_VOICE_DATA_D: printf("voice data d\n"); break;
		case SRF_IP_CONN_DATA_DMR_SLOT_TYPE_VOICE_DATA_E: printf("voice data e\n"); break;
		case SRF_IP_CONN_DATA_DMR_SLOT_TYPE_VOICE_DATA_F: printf("voice data f\n"); break;
		case SRF_IP_CONN_DATA_DMR_SLOT_TYPE_PI_HEADER: printf("pi header\n"); break;
		default: printf("unknown\n"); break;
	}
	printf("  color code: %u\n", payload->color_code);
	printf("  rssi: %d dbm\n", payload->rssi_dbm);
	printf("  payload: ");
	for (i = 0; i < sizeof(payload->data); i++)
		printf("%.2x", payload->data[i]);
	printf("\n");
}

void srf_ip_conn_packet_print_data_dstar_payload(srf_ip_conn_data_dstar_payload_t *payload) {
	uint8_t i;
	uint8_t j;

	printf("  seq. no: %u\n", ntohl(payload->seq_no));
	printf("  call session id: 0x%.8x\n", ntohl(payload->call_session_id));
	payload->dst_callsign[sizeof(payload->dst_callsign)-1] = 0;
	printf("  dst callsign: %s\n", payload->dst_callsign);
	payload->src_callsign[sizeof(payload->src_callsign)-1] = 0;
	payload->src_callsign_suffix[sizeof(payload->src_callsign_suffix)-1] = 0;
	printf("  src callsign: %s/%s\n", payload->src_callsign, payload->src_callsign_suffix);

	payload->storage.packet_count = min(payload->storage.packet_count, sizeof(payload->storage.packet_types));
	printf("  packets: %u\n", payload->storage.packet_count);
	if (payload->storage.packet_count == 1 && payload->storage.packet_types[0] == SRF_IP_CONN_DATA_DSTAR_PACKET_TYPE_HEADER) {
		printf("  packet type 0: header\n");
		printf("  rssi: %d dbm\n", payload->storage.rssi_dbm_values[0]);
	} else {
		for (i = 0; i < payload->storage.packet_count; i++) {
			printf("  packet type %u: %u ", i, payload->storage.packet_types[i]);
			switch (payload->storage.packet_types[i]) {
				default: printf("invalid\n"); break;
				case SRF_IP_CONN_DATA_DSTAR_PACKET_TYPE_DATA: printf("data\n"); break;
				case SRF_IP_CONN_DATA_DSTAR_PACKET_TYPE_TERMINATOR: printf("terminator\n"); break;
			}
			printf("  rssi: %d dbm\n", payload->storage.rssi_dbm_values[i]);
			printf("  payload: ");
			for (j = 0; j < 12; j++)
				printf("%.2x", payload->storage.data[i][j]);
			printf("\n");
		}
	}
}

void srf_ip_conn_packet_print_data_c4fm_payload(srf_ip_conn_data_c4fm_payload_t *payload) {
	uint8_t i;

	printf("  seq. no: %u\n", ntohl(payload->seq_no));
	printf("  call session id: 0x%.8x\n", ntohl(payload->call_session_id));
	payload->dst_callsign[sizeof(payload->dst_callsign)-1] = 0;
	printf("  dst callsign: %s\n", payload->dst_callsign);
	payload->src_callsign[sizeof(payload->src_callsign)-1] = 0;
	printf("  src callsign: %s\n", payload->src_callsign);
	printf("  rssi: %d dbm\n", payload->rssi_dbm);
	printf("  c4fm packet type: %u ", payload->packet_type);
	switch (payload->packet_type) {
		case SRF_IP_CONN_DATA_C4FM_PACKET_TYPE_HEADER: printf("header\n"); break;
		case SRF_IP_CONN_DATA_C4FM_PACKET_TYPE_VDMODE1: printf("vdmode1\n"); break;
		case SRF_IP_CONN_DATA_C4FM_PACKET_TYPE_VDMODE2: printf("vdmode2\n"); break;
		case SRF_IP_CONN_DATA_C4FM_PACKET_TYPE_DATA_FR: printf("data fr\n"); break;
		case SRF_IP_CONN_DATA_C4FM_PACKET_TYPE_VOICE_FR: printf("voice fr\n"); break;
		case SRF_IP_CONN_DATA_C4FM_PACKET_TYPE_TERMINATOR: printf("terminator\n"); break;
		default: printf("unknown\n"); break;
	}
	printf("  payload: ");
	for (i = 0; i < sizeof(payload->data); i++)
		printf("%.2x", payload->data[i]);
	printf("\n");
}

void srf_ip_conn_packet_print_data_nxdn_payload(srf_ip_conn_data_nxdn_payload_t *payload) {
	uint8_t i;

	printf("  seq. no: %u\n", ntohl(payload->seq_no));
	printf("  call session id: 0x%.8x\n", ntohl(payload->call_session_id));
	printf("  dst id: %u\n", payload->dst_id);
	printf("  src id: %u\n", payload->src_id);
	printf("  call type: %s\n", payload->call_type ? "group" : "private");
	printf("  packet type: %u ", payload->packet_type);
	switch (payload->packet_type) {
		case SRF_IP_CONN_DATA_NXDN_PACKET_TYPE_HEADER: printf("header\n"); break;
		case SRF_IP_CONN_DATA_NXDN_PACKET_TYPE_VOICE_IN_PART1: printf("voice in part1\n"); break;
		case SRF_IP_CONN_DATA_NXDN_PACKET_TYPE_VOICE_IN_PART2: printf("voice in part2\n"); break;
		case SRF_IP_CONN_DATA_NXDN_PACKET_TYPE_VOICE_IN_BOTH_PARTS: printf("voice in both parts\n"); break;
		case SRF_IP_CONN_DATA_NXDN_PACKET_TYPE_DATA: printf("data\n"); break;
		case SRF_IP_CONN_DATA_NXDN_PACKET_TYPE_TERMINATOR: printf("terminator\n"); break;
		default: printf("unknown\n"); break;
	}
	printf("  ran: %u\n", payload->ran);
	printf("  rssi: %d dbm\n", payload->rssi_dbm);
	printf("  payload: ");
	for (i = 0; i < sizeof(payload->data); i++)
		printf("%.2x", payload->data[i]);
	printf("\n");
}

void srf_ip_conn_packet_print_data_p25_payload(srf_ip_conn_data_p25_payload_t *payload) {
	uint8_t i;

	printf("  seq. no: %u\n", ntohl(payload->seq_no));
	printf("  call session id: 0x%.8x\n", ntohl(payload->call_session_id));
	printf("  dst id: %u\n", (payload->dst_id[0] << 16) | (payload->dst_id[1] << 8) | (payload->dst_id[2]));
	printf("  src id: %u\n", (payload->src_id[0] << 16) | (payload->src_id[1] << 8) | (payload->src_id[2]));
	printf("  call type: %s\n", payload->call_type ? "group" : "private");
	printf("  packet type: %u ", payload->packet_type);
	switch (payload->packet_type) {
		case SRF_IP_CONN_DATA_P25_PACKET_TYPE_HEADER: printf("header\n"); break;
		case SRF_IP_CONN_DATA_P25_PACKET_TYPE_LDU1: printf("ldu1\n"); break;
		case SRF_IP_CONN_DATA_P25_PACKET_TYPE_LDU2: printf("ldu2\n"); break;
		case SRF_IP_CONN_DATA_P25_PACKET_TYPE_DATA: printf("data\n"); break;
		case SRF_IP_CONN_DATA_P25_PACKET_TYPE_TERMINATOR: printf("terminator\n"); break;
		default: printf("unknown\n"); break;
	}
	printf("  nac: %u\n", payload->nac);
	printf("  rssi: %d dbm\n", payload->rssi_dbm);
	printf("  payload: ");
	for (i = 0; i < sizeof(payload->data); i++)
		printf("%.2x", payload->data[i]);
	printf("\n");
}
