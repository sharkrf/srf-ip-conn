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

#include "client.h"
#include "client-sock.h"
#include "packet.h"
#include "config.h"

#include <time.h>
#include <unistd.h>
#include <stdlib.h>

uint32_t client_id;
client_state_t client_state = CLIENT_STATE_INIT;
uint8_t client_token[SRF_IP_CONN_TOKEN_LENGTH];
static time_t client_got_last_valid_packet_at = 0;
static time_t client_last_packet_sent_at = 0;

void client_got_valid_packet(void) {
	time(&client_got_last_valid_packet_at);
}

static void client_state_change(client_state_t new_state) {
	if (client_state != new_state) {
		printf("client: changing state to ");
		switch (new_state) {
			case CLIENT_STATE_INIT: printf("init\n"); break;
			case CLIENT_STATE_LOGIN_SENT: printf("login sent\n"); break;
			case CLIENT_STATE_AUTH_SENT: printf("auth sent\n"); break;
			case CLIENT_STATE_CONFIG_SENT: printf("config sent\n"); break;
			case CLIENT_STATE_CONNECTED: printf("connected\n"); break;
			case CLIENT_STATE_CLOSED: printf("closed\n"); break;
			default: printf("unknown\n"); break;
		}
		client_state = new_state;
	}
}

static void client_send_login(void) {
	srf_ip_conn_packet_t packet;

	printf("client: sending login\n");

	srf_ip_conn_packet_init(&packet.header, SRF_IP_CONN_PACKET_TYPE_LOGIN);
	packet.login.client_id = htonl(client_id);
	client_sock_send((uint8_t *)&packet, sizeof(srf_ip_conn_packet_header_t) + sizeof(srf_ip_conn_login_payload_t));
	time(&client_last_packet_sent_at);

	client_state_change(CLIENT_STATE_LOGIN_SENT);
}

static void client_send_auth(void) {
	srf_ip_conn_packet_t packet;
	uint8_t i;

	printf("  sending auth\n");

	srf_ip_conn_packet_init(&packet.header, SRF_IP_CONN_PACKET_TYPE_AUTH);
	for (i = 0; i < sizeof(packet.auth.random_data); i++)
		packet.auth.random_data[i] = rand();
	srf_ip_conn_packet_hmac_add(client_token, CONFIG_PASSWORD, &packet, sizeof(srf_ip_conn_auth_payload_t));
	client_sock_send((uint8_t *)&packet, sizeof(srf_ip_conn_packet_header_t) + sizeof(srf_ip_conn_auth_payload_t));
	time(&client_last_packet_sent_at);

	client_state_change(CLIENT_STATE_AUTH_SENT);
}

void client_got_token(uint8_t token[SRF_IP_CONN_TOKEN_LENGTH]) {
	uint8_t i;

	if (client_state != CLIENT_STATE_LOGIN_SENT) {
		printf("  client is not in login sent state, ignoring token packet\n");
		return;
	}

	printf("  got token from server: ");
	for (i = 0; i < SRF_IP_CONN_TOKEN_LENGTH; i++) {
		client_token[i] = token[i];
		printf("%.2x", token[i]);
	}
	printf("\n");

	client_got_valid_packet();
	client_send_auth();
}

static void client_send_config(void) {
	srf_ip_conn_packet_t packet;

	printf("client: sending config\n");

	srf_ip_conn_packet_init(&packet.header, SRF_IP_CONN_PACKET_TYPE_CONFIG);

	snprintf(packet.config.operator_callsign, sizeof(packet.config.operator_callsign), "HA2NON");
	snprintf(packet.config.hw_manufacturer, sizeof(packet.config.hw_manufacturer), "SharkRF");
	snprintf(packet.config.hw_model, sizeof(packet.config.hw_model), "openSPOT");
	snprintf(packet.config.hw_version, sizeof(packet.config.hw_version), "1.1");
	snprintf(packet.config.sw_version, sizeof(packet.config.sw_version), "0001");
	packet.config.rx_freq = packet.config.tx_freq = htonl(436000000);
	packet.config.tx_power = 20;
	packet.config.latitude = 47.6411825;
	packet.config.longitude = 18.3020316;
	packet.config.height_agl = htons(123);
	snprintf(packet.config.location, sizeof(packet.config.location), "test client location");
	snprintf(packet.config.description, sizeof(packet.config.description), "test client description");

	srf_ip_conn_packet_hmac_add(client_token, CONFIG_PASSWORD, &packet, sizeof(srf_ip_conn_config_payload_t));
	client_sock_send((uint8_t *)&packet, sizeof(srf_ip_conn_packet_header_t) + sizeof(srf_ip_conn_config_payload_t));
	time(&client_last_packet_sent_at);

	client_state_change(CLIENT_STATE_CONFIG_SENT);
}

void client_got_ack(srf_ip_conn_ack_result_t ack_result) {
	switch (client_state) {
		case CLIENT_STATE_AUTH_SENT:
			switch (ack_result) {
				case SRF_IP_CONN_ACK_RESULT_AUTH:
					printf("  got ack for auth\n");
					client_send_config();
					client_state_change(CLIENT_STATE_CONFIG_SENT);
					client_got_valid_packet();
					break;
				default:
					printf("  ignoring ack, invalid result\n");
					break;
			}
			break;
		case CLIENT_STATE_CONFIG_SENT:
			switch (ack_result) {
				case SRF_IP_CONN_ACK_RESULT_CONFIG:
					printf("  got ack for config\n");
					client_state_change(CLIENT_STATE_CONNECTED);
					client_got_valid_packet();
					break;
				default:
					printf("  ignoring ack, invalid result\n");
					break;
			}
			break;
		case CLIENT_STATE_CONNECTED:
			switch (ack_result) {
				case SRF_IP_CONN_ACK_RESULT_CLOSE:
					printf("  got ack for close\n");
					client_state_change(CLIENT_STATE_CLOSED);
					client_got_valid_packet();
					break;
				default:
					printf("  ignoring ack, invalid result\n");
					break;
			}
			break;
		default:
			printf("  ignoring ack, we are not in a state where we expect one\n");
			break;
	}
}

void client_got_nak(srf_ip_conn_nak_result_t nak_result) {
	switch (client_state) {
		case CLIENT_STATE_AUTH_SENT:
			switch (nak_result) {
				case SRF_IP_CONN_NAK_RESULT_AUTH_INVALID_HMAC:
					printf("  got nak with invalid hmac for auth, retrying in 5 seconds\n");
					sleep(5);
					client_state_change(CLIENT_STATE_INIT);
					break;
				case SRF_IP_CONN_NAK_RESULT_AUTH_INVALID_CLIENT_ID:
					printf("  got nak with invalid client id for login, retrying in 5 seconds\n");
					sleep(5);
					client_state_change(CLIENT_STATE_INIT);
					break;
				case SRF_IP_CONN_NAK_RESULT_AUTH_SERVER_FULL:
					printf("  got nak with server full for login, retrying in 5 seconds\n");
					sleep(5);
					client_state_change(CLIENT_STATE_INIT);
					break;
				default:
					printf("  unknown nak, retrying in 5 seconds\n");
					sleep(5);
					client_state_change(CLIENT_STATE_INIT);
					break;
			}
			break;
		default:
			printf("  ignoring nak, we are not in a state where we expect one\n");
			break;
	}
}

void client_got_pong(void) {
	switch (client_state) {
		case CLIENT_STATE_CONNECTED:
			printf("  got pong\n");
			client_got_valid_packet();
			break;
		default:
			printf("  ignoring pong, we are not in a state where we expect one\n");
			break;
	}
}

static void client_send_ping(void) {
	srf_ip_conn_packet_t packet;
	uint8_t i;

	printf("client: sending ping\n");

	srf_ip_conn_packet_init(&packet.header, SRF_IP_CONN_PACKET_TYPE_PING);
	for (i = 0; i < sizeof(packet.ping.random_data); i++)
		packet.ping.random_data[i] = rand();
	srf_ip_conn_packet_hmac_add(client_token, CONFIG_PASSWORD, &packet, sizeof(srf_ip_conn_ping_payload_t));
	client_sock_send((uint8_t *)&packet, sizeof(srf_ip_conn_packet_header_t) + sizeof(srf_ip_conn_ping_payload_t));
	time(&client_last_packet_sent_at);
}

void client_send_close(void) {
	srf_ip_conn_packet_t packet;
	uint8_t i;

	printf("client: sending close packet\n");

	srf_ip_conn_packet_init(&packet.header, SRF_IP_CONN_PACKET_TYPE_CLOSE);
	for (i = 0; i < sizeof(packet.close.random_data); i++)
		packet.close.random_data[i] = rand();
	srf_ip_conn_packet_hmac_add(client_token, CONFIG_PASSWORD, &packet, sizeof(srf_ip_conn_close_payload_t));
	client_sock_send((uint8_t *)&packet, sizeof(srf_ip_conn_packet_header_t) + sizeof(srf_ip_conn_close_payload_t));
	time(&client_last_packet_sent_at);
}

flag_t client_process(void) {
	switch (client_state) {
		case CLIENT_STATE_INIT:
			client_got_valid_packet(); // Resetting the timer.
			client_send_login();
			break;
		case CLIENT_STATE_CONNECTED:
			if (time(NULL)-client_last_packet_sent_at > 5)
				client_send_ping();
			break;
		case CLIENT_STATE_CLOSED:
			return 0;
		default:
			// If we didn't received a valid packet for a long time.
			if (time(NULL)-client_got_last_valid_packet_at > 30) {
				printf("client: rx timeout\n");
				client_state_change(CLIENT_STATE_INIT);
			}
			break;
	}
	return 1;
}
