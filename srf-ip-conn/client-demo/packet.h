#ifndef PACKET_H_
#define PACKET_H_

#include "srf-ip-conn-packet.h"
#include "types.h"

flag_t packet_is_header_valid(void);
void packet_process(void);

#endif
