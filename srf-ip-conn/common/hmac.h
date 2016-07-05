#ifndef HMAC_H_
#define HMAC_H_

#include "srf-ip-conn-packets.h"
#include "types.h"

void hmac_add(uint8_t token[SRF_IP_CONN_TOKEN_LENGTH], srf_ip_conn_packet_t *packet, uint16_t payload_length);
flag_t hmac_check(uint8_t token[SRF_IP_CONN_TOKEN_LENGTH], srf_ip_conn_packet_t *packet, uint16_t payload_length);

#endif
