#ifndef HMAC_H_
#define HMAC_H_

#include "srf-ip-conn/common/srf-ip-conn-packets.h"
#include "srf-ip-conn/common/types.h"

void hmac_add(uint8_t token[SRF_IP_CONN_TOKEN_LENGTH], char password[SRF_IP_CONN_MAX_PASSWORD_LENGTH+1], srf_ip_conn_packet_t *packet, uint16_t payload_length);
flag_t hmac_check(uint8_t token[SRF_IP_CONN_TOKEN_LENGTH], char password[SRF_IP_CONN_MAX_PASSWORD_LENGTH+1], srf_ip_conn_packet_t *packet, uint16_t payload_length);

#endif
