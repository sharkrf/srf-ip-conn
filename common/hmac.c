#include "hmac.h"
#include "config.h"
#include "sha2.h"

#include <string.h>

static void hmac_calc(uint8_t token[SRF_IP_CONN_TOKEN_LENGTH], srf_ip_conn_packet_t *packet, uint16_t payload_length, uint8_t dst[SHA256_DIGEST_LENGTH]) {
	SHA256_CTX ctx256;
	uint8_t tmp[SRF_IP_CONN_TOKEN_LENGTH+SRF_IP_CONN_MAX_PASSWORD_LENGTH+sizeof(srf_ip_conn_packet_t)-sizeof(srf_ip_conn_packet_header_t)-SHA256_DIGEST_LENGTH];

	// Copying token to tmp.
	memcpy(tmp, token, SRF_IP_CONN_TOKEN_LENGTH);
	// Copying password to tmp.
	strncpy((char *)tmp+SRF_IP_CONN_TOKEN_LENGTH, CONFIG_PASSWORD, SRF_IP_CONN_MAX_PASSWORD_LENGTH);
	// Copying packet payload to tmp.
	memcpy(tmp+SRF_IP_CONN_TOKEN_LENGTH+strlen(CONFIG_PASSWORD), (uint8_t *)packet + sizeof(srf_ip_conn_packet_header_t), payload_length-SHA256_DIGEST_LENGTH);

	// Calculating hash.
	SHA256_Init(&ctx256);
	SHA256_Update(&ctx256, tmp, SRF_IP_CONN_TOKEN_LENGTH+strlen(CONFIG_PASSWORD)+payload_length-SHA256_DIGEST_LENGTH);
	SHA256_Final(dst, &ctx256);
}

void hmac_add(uint8_t token[SRF_IP_CONN_TOKEN_LENGTH], srf_ip_conn_packet_t *packet, uint16_t payload_length) {
	hmac_calc(token, packet, payload_length, (uint8_t *)packet + sizeof(srf_ip_conn_packet_header_t) + payload_length - SHA256_DIGEST_LENGTH);
}

flag_t hmac_check(uint8_t token[SRF_IP_CONN_TOKEN_LENGTH], srf_ip_conn_packet_t *packet, uint16_t payload_length) {
	uint8_t hash[SHA256_DIGEST_LENGTH];

	hmac_calc(token, packet, payload_length, hash);

	// Returning 1 if calculated hash matches HMAC.
	return (memcmp((uint8_t *)packet + sizeof(srf_ip_conn_packet_header_t) + payload_length - SHA256_DIGEST_LENGTH, hash, SHA256_DIGEST_LENGTH) == 0);
}
