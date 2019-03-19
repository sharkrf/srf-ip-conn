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

#ifndef SRF_IP_CONN_PACKET_H_
#define SRF_IP_CONN_PACKET_H_

#include "srf-ip-conn/common/types.h"

#define SRF_IP_CONN_MAGIC_STR                                   "SRFIPC"
#define SRF_IP_CONN_MAGIC_STR_LENGTH                            (sizeof(SRF_IP_CONN_MAGIC_STR)-1)
#define SRF_IP_CONN_MAX_PASSWORD_LENGTH                         32
#define SRF_IP_CONN_TOKEN_LENGTH                                8
#define SRF_IP_CONN_MAX_CALLSIGN_LENGTH						    10

#define SRF_IP_CONN_PACKET_TYPE_LOGIN                           0x00 // Payload: srf_ip_conn_login_payload_t
#define SRF_IP_CONN_PACKET_TYPE_TOKEN                           0x01 // Payload: srf_ip_conn_token_payload_t
#define SRF_IP_CONN_PACKET_TYPE_AUTH                            0x02 // Payload: srf_ip_conn_auth_payload_t
#define SRF_IP_CONN_PACKET_TYPE_ACK                             0x03 // Payload: srf_ip_conn_ack_payload_t
#define SRF_IP_CONN_PACKET_TYPE_NAK                             0x04 // Payload: srf_ip_conn_nak_payload_t
#define SRF_IP_CONN_PACKET_TYPE_CONFIG                          0x05 // Payload: srf_ip_conn_config_payload_t
#define SRF_IP_CONN_PACKET_TYPE_PING                            0x06 // Payload: srf_ip_conn_ping_payload_t
#define SRF_IP_CONN_PACKET_TYPE_PONG                            0x07 // Payload: srf_ip_conn_pong_payload_t
#define SRF_IP_CONN_PACKET_TYPE_CLOSE                           0x08 // Payload: srf_ip_conn_close_payload_t
#define SRF_IP_CONN_PACKET_TYPE_DATA_RAW                        0x09 // Payload: srf_ip_conn_data_raw_payload_t
#define SRF_IP_CONN_PACKET_TYPE_DATA_DMR                        0x0a // Payload: srf_ip_conn_data_dmr_payload_t
#define SRF_IP_CONN_PACKET_TYPE_DATA_DSTAR                      0x0b // Payload: srf_ip_conn_data_dstar_payload_t
#define SRF_IP_CONN_PACKET_TYPE_DATA_C4FM                       0x0c // Payload: srf_ip_conn_data_c4fm_payload_t
#define SRF_IP_CONN_PACKET_TYPE_DATA_NXDN                       0x0d // Payload: srf_ip_conn_data_nxdn_payload_t
#define SRF_IP_CONN_PACKET_TYPE_DATA_P25                        0x0e // Payload: srf_ip_conn_data_p25_payload_t
typedef uint8_t srf_ip_conn_packet_type_t;

typedef struct __attribute__((packed)) {
    char magic[SRF_IP_CONN_MAGIC_STR_LENGTH];
    uint8_t version;                                            // 0x00
    srf_ip_conn_packet_type_t packet_type;                      // Packet type
} srf_ip_conn_packet_header_t;                                  // 8 bytes total

// CONNECTION MANAGEMENT PACKETS

typedef struct __attribute__((packed)) {
    uint32_t client_id;
} srf_ip_conn_login_payload_t;                                  // 4 bytes total

typedef struct __attribute__((packed)) {
    uint8_t token[SRF_IP_CONN_TOKEN_LENGTH];                    // 8 bytes of random data
} srf_ip_conn_token_payload_t;                                  // 8 bytes total

typedef struct __attribute__((packed)) {
    uint8_t random_data[8];
    uint8_t hmac[32];                                           // Hashed Message Auth Code, sha256( token + secret password + random_data )
} srf_ip_conn_auth_payload_t;                                   // 40 bytes total

#define SRF_IP_CONN_ACK_RESULT_AUTH                             0
#define SRF_IP_CONN_ACK_RESULT_CONFIG                           1
#define SRF_IP_CONN_ACK_RESULT_CLOSE                            2
typedef uint8_t srf_ip_conn_ack_result_t;

typedef struct __attribute__((packed)) {
    srf_ip_conn_ack_result_t result;
    uint8_t random_data[8];
    uint8_t hmac[32];                                           // Hashed Message Auth Code, sha256( token + secret password + random_data )
} srf_ip_conn_ack_payload_t;                                    // 41 bytes total

#define SRF_IP_CONN_NAK_RESULT_AUTH_INVALID_CLIENT_ID           0
#define SRF_IP_CONN_NAK_RESULT_AUTH_INVALID_HMAC                1
typedef uint8_t srf_ip_conn_nak_result_t;

typedef struct __attribute__((packed)) {
    srf_ip_conn_nak_result_t result;
    uint8_t random_data[8];
    uint8_t hmac[32];                                           // Hashed Message Auth Code, sha256( token + secret password + random_data )
} srf_ip_conn_nak_payload_t;                                    // 41 bytes total

typedef struct __attribute__((packed)) {
    char operator_callsign[SRF_IP_CONN_MAX_CALLSIGN_LENGTH+1];  // Operator callsign, null-terminated
    char hw_manufacturer[17];                                   // Hardware manufacturer, null-terminated
    char hw_model[17];                                          // Hardware model number, null-terminated
    char hw_version[9];                                         // Hardware version, null-terminated
    char sw_version[9];                                         // Software version, null-terminated
    uint32_t rx_freq;                                           // RX frequency in Hz
    uint32_t tx_freq;                                           // TX frequency in Hz
    uint8_t tx_power;                                           // ERP in dBm
    float latitude;                                             // Latitude
    float longitude;                                            // Longitude
    int16_t height_agl;                                         // Height above ground level in meters
    char location[33];                                          // Location, null-terminated
    char description[33];                                       // Description, null-terminated
    uint8_t hmac[32];                                           // Hashed Message Auth Code, sha256 ( token + secret password + all fields of this struct except hmac )
} srf_ip_conn_config_payload_t;                                 // 180 bytes total

typedef struct __attribute__((packed)) {
    uint8_t random_data[8];
    uint8_t hmac[32];                                           // Hashed Message Auth Code, sha256( token + secret password + random_data )
} srf_ip_conn_ping_payload_t;                                   // 40 bytes total

typedef struct __attribute__((packed)) {
    uint8_t random_data[8];
    uint8_t hmac[32];                                           // Hashed Message Auth Code, sha256( token + secret password + random_data )
} srf_ip_conn_pong_payload_t;                                   // 40 bytes total

typedef struct __attribute__((packed)) {
    uint8_t random_data[8];
    uint8_t hmac[32];                                           // Hashed Message Auth Code, sha256( token + secret password + random_data )
} srf_ip_conn_close_payload_t;                                  // 40 bytes total

// RAW

typedef struct __attribute__((packed)) {
    uint32_t seq_no;                                            // Sequence number (starts from 0 and incremented for every data packet for the whole connection)
    uint32_t call_session_id;                                   // Random 32-bit value for the call.
    int8_t rssi_dbm;                                            // Received signal strength
    uint8_t tdma_channel                        : 1;
    uint8_t reserved                            : 7;
    uint8_t length;                                             // Length of raw data in bytes
    uint8_t data[120];                                          // Raw data
    uint8_t hmac[32];                                           // Hashed Message Auth Code, sha256 ( token + secret password + all fields of this struct except hmac )
} srf_ip_conn_data_raw_payload_t;                               // 163 bytes total

// DMR

#define SRF_IP_CONN_DATA_DMR_SLOT_TYPE_UNKNOWN                  0x00
#define SRF_IP_CONN_DATA_DMR_SLOT_TYPE_VOICE_LC_HEADER          0x01
#define SRF_IP_CONN_DATA_DMR_SLOT_TYPE_TERMINATOR_WITH_LC       0x02
#define SRF_IP_CONN_DATA_DMR_SLOT_TYPE_CSBK                     0x03
#define SRF_IP_CONN_DATA_DMR_SLOT_TYPE_DATA_HEADER              0x04
#define SRF_IP_CONN_DATA_DMR_SLOT_TYPE_RATE_12_DATA             0x05
#define SRF_IP_CONN_DATA_DMR_SLOT_TYPE_RATE_34_DATA             0x06
#define SRF_IP_CONN_DATA_DMR_SLOT_TYPE_VOICE_DATA_A             0x0a
#define SRF_IP_CONN_DATA_DMR_SLOT_TYPE_VOICE_DATA_B             0x0b
#define SRF_IP_CONN_DATA_DMR_SLOT_TYPE_VOICE_DATA_C             0x0c
#define SRF_IP_CONN_DATA_DMR_SLOT_TYPE_VOICE_DATA_D             0x0d
#define SRF_IP_CONN_DATA_DMR_SLOT_TYPE_VOICE_DATA_E             0x0e
#define SRF_IP_CONN_DATA_DMR_SLOT_TYPE_VOICE_DATA_F             0x0f
#define SRF_IP_CONN_DATA_DMR_SLOT_TYPE_PI_HEADER                0x10
typedef uint8_t srf_ip_conn_data_dmr_slot_type_t;

typedef struct __attribute__((packed)) {
    uint32_t seq_no;                                            // Sequence number (starts from 0 and incremented for every data packet for the whole connection)
    uint32_t call_session_id;                                   // Random 32-bit value for the call.
    uint8_t dst_id[3];                                          // Destination DMR ID
    uint8_t src_id[3];                                          // Source DMR ID
    uint8_t tdma_channel                        : 1;
    uint8_t call_type                           : 1;            // Private = 0; Group = 1
    uint8_t color_code                          : 4;
    uint8_t reserved                            : 2;
    srf_ip_conn_data_dmr_slot_type_t slot_type;
    int8_t rssi_dbm;                                            // Received signal strength
    uint8_t data[33];                                           // Raw DMR data
    uint8_t hmac[32];                                           // Hashed Message Auth Code, sha256 ( token + secret password + all fields of this struct except hmac )
} srf_ip_conn_data_dmr_payload_t;                               // 82 bytes total

// D-STAR

// To reduce overhead, D-STAR frames should be stored in an srf_ip_conn_data_dstar_storage_t struct.
// An srf_ip_conn_data_dstar_payload_t data packet should only be sent to the network if there's
// a header, or terminator packet in it, or the storage is full with data packets.
//
// As the decoded D-STAR header is 39 bytes long (without the 16 bit CRC), a complete D-STAR header
// is transmitted with packet_types[0] = SRF_IP_CONN_DATA_DSTAR_PACKET_TYPE_HEADER and packet_count
// set to 1.
// When a packet type is SRF_IP_CONN_DATA_DSTAR_PACKET_TYPE_TERMINATOR, the data for the corresponding
// packet in the storage is ignored.

#define SRF_IP_CONN_DATA_DSTAR_PACKET_TYPE_HEADER               0x00
#define SRF_IP_CONN_DATA_DSTAR_PACKET_TYPE_DATA                 0x01
#define SRF_IP_CONN_DATA_DSTAR_PACKET_TYPE_TERMINATOR           0x02
typedef uint8_t srf_ip_conn_data_dstar_packet_type_t;

typedef struct __attribute__((packed)) {
    struct __attribute__((packed)) {
    	uint8_t is_data                         : 1;
        uint8_t via_repeater                    : 1;
        uint8_t interruption                    : 1;
        uint8_t is_control_signal               : 1;
        uint8_t is_urgent                       : 1;
        uint8_t type                            : 3;
    } flag1;
    uint8_t flag2;
    uint8_t flag3;
    char dst_rptr_callsign[8];
    char src_rptr_callsign[8];
    char dst_callsign[8];
    char src_callsign[8];
    char src_callsign_suffix[8];
} srf_ip_conn_data_dstar_decoded_header_t;

typedef struct __attribute__((packed)) {
    uint8_t packet_count;                                       // Number of D-STAR packets in current packet, max 9
    srf_ip_conn_data_dstar_packet_type_t packet_types[9];       // Type of each packet in the current packet
    int8_t rssi_dbm_values[9];                                  // RSSI of each packet in the current packet
    union {
        srf_ip_conn_data_dstar_decoded_header_t decoded_header;
        uint8_t data[9][12];                                    // Raw D-STAR packet data (9 packets, 108 bytes)
    };
} srf_ip_conn_data_dstar_storage_t;

typedef struct __attribute__((packed)) {
    uint32_t seq_no;                                            // Sequence number (starts from 0 and incremented for every data packet for the whole connection)
    uint32_t call_session_id;                                   // Random 32-bit value for the call.
    uint8_t dst_callsign[9];                                    // Destination callsign, null-terminated
    uint8_t src_callsign[9];                                    // Source callsign, null-terminated
    uint8_t src_callsign_suffix[5];                             // Source callsign suffix, null-terminated
    srf_ip_conn_data_dstar_storage_t storage;
    uint8_t hmac[32];                                           // Hashed Message Auth Code, sha256 ( token + secret password + all fields of this struct except hmac )
} srf_ip_conn_data_dstar_payload_t;                             // 190 bytes total

// C4FM

#define SRF_IP_CONN_DATA_C4FM_PACKET_TYPE_HEADER                0x00
#define SRF_IP_CONN_DATA_C4FM_PACKET_TYPE_VDMODE1               0x01
#define SRF_IP_CONN_DATA_C4FM_PACKET_TYPE_VDMODE2               0x02
#define SRF_IP_CONN_DATA_C4FM_PACKET_TYPE_DATA_FR               0x03
#define SRF_IP_CONN_DATA_C4FM_PACKET_TYPE_VOICE_FR              0x04
#define SRF_IP_CONN_DATA_C4FM_PACKET_TYPE_TERMINATOR            0x05
typedef uint8_t srf_ip_conn_data_c4fm_packet_type_t;

typedef struct __attribute__((packed)) {
    uint32_t seq_no;                                            // Sequence number (starts from 0 and incremented for every data packet for the whole connection)
    uint32_t call_session_id;                                   // Random 32-bit value for the call.
    uint8_t dst_callsign[11];                                   // Destination callsign, null-terminated
    uint8_t src_callsign[11];                                   // Source callsign, null-terminated
    uint8_t call_type                           : 1;            // Private = 0; Group = 1
    uint8_t reserved                            : 7;
    int8_t rssi_dbm;                                            // Received signal strength
    srf_ip_conn_data_c4fm_packet_type_t packet_type;
    uint8_t data[120];                                          // Raw C4FM packet data
    uint8_t hmac[32];                                           // Hashed Message Auth Code, sha256 ( token + secret password + all fields of this struct except hmac )
} srf_ip_conn_data_c4fm_payload_t;                              // 185 bytes total

// NXDN

#define SRF_IP_CONN_DATA_NXDN_PACKET_TYPE_HEADER                0x00
#define SRF_IP_CONN_DATA_NXDN_PACKET_TYPE_VOICE_IN_PART1        0x01
#define SRF_IP_CONN_DATA_NXDN_PACKET_TYPE_VOICE_IN_PART2        0x02
#define SRF_IP_CONN_DATA_NXDN_PACKET_TYPE_VOICE_IN_BOTH_PARTS   0x03
#define SRF_IP_CONN_DATA_NXDN_PACKET_TYPE_DATA                  0x04
#define SRF_IP_CONN_DATA_NXDN_PACKET_TYPE_TERMINATOR            0x05
typedef uint8_t srf_ip_conn_data_nxdn_packet_type_t;

typedef struct __attribute__((packed)) {
    uint32_t seq_no;                                            // Sequence number (starts from 0 and incremented for every data packet for the whole connection)
    uint32_t call_session_id;                                   // Random 32-bit value for the call.
    uint16_t dst_id;                                            // Destination NXDN ID
    uint16_t src_id;                                            // Source NXDN ID
    uint8_t call_type                           : 1;            // Private = 0; Group = 1
    uint8_t ran                                 : 6;
    uint8_t reserved                            : 1;
    int8_t rssi_dbm;                                            // Received signal strength
    srf_ip_conn_data_nxdn_packet_type_t packet_type;
    uint8_t data[48];                                           // Raw NXDN packet data
    uint8_t hmac[32];                                           // Hashed Message Auth Code, sha256 ( token + secret password + all fields of this struct except hmac )
} srf_ip_conn_data_nxdn_payload_t;                              // 95 bytes total

// P25

#define SRF_IP_CONN_DATA_P25_PACKET_TYPE_HEADER                0x00
#define SRF_IP_CONN_DATA_P25_PACKET_TYPE_LDU1                  0x01
#define SRF_IP_CONN_DATA_P25_PACKET_TYPE_LDU2                  0x02
#define SRF_IP_CONN_DATA_P25_PACKET_TYPE_DATA                  0x03
#define SRF_IP_CONN_DATA_P25_PACKET_TYPE_TERMINATOR            0x04
typedef uint8_t srf_ip_conn_data_p25_packet_type_t;

typedef struct __attribute__((packed)) {
    uint32_t seq_no;                                            // Sequence number (starts from 0 and incremented for every data packet for the whole connection)
    uint32_t call_session_id;                                   // Random 32-bit value for the call.
    uint8_t dst_id[3];                                          // Destination P25 ID
    uint8_t src_id[3];                                          // Source P25 ID
    uint16_t call_type                           : 1;           // Private = 0; Group = 1
    uint16_t nac                                 : 12;
    uint16_t reserved                            : 3;
    int8_t rssi_dbm;                                            // Received signal strength
    srf_ip_conn_data_p25_packet_type_t packet_type;
    uint8_t data[216];                                          // Raw P25 packet data
    uint8_t hmac[32];                                           // Hashed Message Auth Code, sha256 ( token + secret password + all fields of this struct except hmac )
} srf_ip_conn_data_p25_payload_t;                               // 266 bytes total

// GENERIC

typedef struct __attribute__((packed)) {
    srf_ip_conn_packet_header_t header;
    union {
        srf_ip_conn_login_payload_t login;
        srf_ip_conn_token_payload_t token;
        srf_ip_conn_auth_payload_t auth;
        srf_ip_conn_ack_payload_t ack;
        srf_ip_conn_nak_payload_t nak;
        srf_ip_conn_config_payload_t config;
        srf_ip_conn_ping_payload_t ping;
        srf_ip_conn_pong_payload_t pong;
        srf_ip_conn_close_payload_t close;
        srf_ip_conn_data_raw_payload_t data_raw;
        srf_ip_conn_data_dmr_payload_t data_dmr;
        srf_ip_conn_data_dstar_payload_t data_dstar;
        srf_ip_conn_data_c4fm_payload_t data_c4fm;
        srf_ip_conn_data_nxdn_payload_t data_nxdn;
        srf_ip_conn_data_p25_payload_t data_p25;
    };
} srf_ip_conn_packet_t;

void srf_ip_conn_packet_init(srf_ip_conn_packet_header_t *packet_header, srf_ip_conn_packet_type_t packet_type);
flag_t srf_ip_conn_packet_is_header_valid(srf_ip_conn_packet_header_t *packet_header);

void srf_ip_conn_packet_hmac_add(uint8_t token[SRF_IP_CONN_TOKEN_LENGTH], char password[SRF_IP_CONN_MAX_PASSWORD_LENGTH], srf_ip_conn_packet_t *packet, uint16_t payload_length);
flag_t srf_ip_conn_packet_hmac_check(uint8_t token[SRF_IP_CONN_TOKEN_LENGTH], char password[SRF_IP_CONN_MAX_PASSWORD_LENGTH], srf_ip_conn_packet_t *packet, uint16_t payload_length);

void srf_ip_conn_packet_print_data_raw_payload(srf_ip_conn_data_raw_payload_t *payload);
void srf_ip_conn_packet_print_data_dmr_payload(srf_ip_conn_data_dmr_payload_t *payload);
void srf_ip_conn_packet_print_data_dstar_payload(srf_ip_conn_data_dstar_payload_t *payload);
void srf_ip_conn_packet_print_data_c4fm_payload(srf_ip_conn_data_c4fm_payload_t *payload);
void srf_ip_conn_packet_print_data_nxdn_payload(srf_ip_conn_data_nxdn_payload_t *payload);
void srf_ip_conn_packet_print_data_p25_payload(srf_ip_conn_data_p25_payload_t *payload);

#endif
