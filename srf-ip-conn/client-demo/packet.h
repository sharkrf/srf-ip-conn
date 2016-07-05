#ifndef PACKET_H_
#define PACKET_H_

#include "srf-ip-conn-packets.h"
#include "types.h"

void packet_init(srf_ip_conn_packet_header_t *packet_header, srf_ip_conn_packet_type_t packet_type);
flag_t packet_is_header_valid(void);
void packet_process(void);

#endif
