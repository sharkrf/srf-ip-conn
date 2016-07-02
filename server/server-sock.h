#ifndef SERVER_SOCK_H_
#define SERVER_SOCK_H_

#include "types.h"

int server_sock_receive(int sockfd, uint8_t *buf, uint16_t buflen);
int server_sock_init(uint16_t port, flag_t ipv4_only);

#endif
