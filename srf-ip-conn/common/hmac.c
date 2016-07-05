#include "srf-ip-conn/common/hmac.h"
#include "srf-ip-conn/common/sha2.h"

#include <string.h>

static void hmac_calc(uint8_t token[SRF_IP_CONN_TOKEN_LENGTH], char password[SRF_IP_CONN_MAX_PASSWORD_LENGTH], srf_ip_conn_packet_t *packet, uint16_t payload_length, uint8_t dst[SHA256_DIGEST_LENGTH]) {
	SHA256_CTX ctx256;

	SHA256_Init(&ctx256);
	SHA256_Update(&ctx256, token, SRF_IP_CONN_TOKEN_LENGTH);
	SHA256_Update(&ctx256, (uint8_t *)password, strlen(password));
	SHA256_Update(&ctx256, (uint8_t *)packet + sizeof(srf_ip_conn_packet_header_t), payload_length-SHA256_DIGEST_LENGTH);
	SHA256_Final(dst, &ctx256);
}

void hmac_add(uint8_t token[SRF_IP_CONN_TOKEN_LENGTH], char password[SRF_IP_CONN_MAX_PASSWORD_LENGTH], srf_ip_conn_packet_t *packet, uint16_t payload_length) {
	hmac_calc(token, password, packet, payload_length, (uint8_t *)packet + sizeof(srf_ip_conn_packet_header_t) + payload_length - SHA256_DIGEST_LENGTH);
}

flag_t hmac_check(uint8_t token[SRF_IP_CONN_TOKEN_LENGTH], char password[SRF_IP_CONN_MAX_PASSWORD_LENGTH], srf_ip_conn_packet_t *packet, uint16_t payload_length) {
	uint8_t hash[SHA256_DIGEST_LENGTH];

	hmac_calc(token, password, packet, payload_length, hash);

	// Returning 1 if calculated hash matches HMAC.
	return (memcmp((uint8_t *)packet + sizeof(srf_ip_conn_packet_header_t) + payload_length - SHA256_DIGEST_LENGTH, hash, SHA256_DIGEST_LENGTH) == 0);
}
