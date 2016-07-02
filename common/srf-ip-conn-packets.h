#ifndef SRF_IP_CONN_PACKETS_H_
#define SRF_IP_CONN_PACKETS_H_

#include "types.h"

#define SRF_IP_CONN_PKT_TYPE_LOGIN                0x00		// No payload
#define SRF_IP_CONN_PKT_TYPE_TOKEN                0x01		// Payload: srf_ip_conn_token_t
#define SRF_IP_CONN_PKT_TYPE_AUTH                 0x02		// Payload: srf_ip_conn_auth_t
#define SRF_IP_CONN_PKT_TYPE_ACK                  0x03		// No payload
#define SRF_IP_CONN_PKT_TYPE_NAK                  0x04		// No payload
#define SRF_IP_CONN_PKT_TYPE_CONFIG               0x05		// Payload: srf_ip_conn_config_t
#define SRF_IP_CONN_PKT_TYPE_PING                 0x06		// No payload
#define SRF_IP_CONN_PKT_TYPE_PONG                 0x07		// No payload
#define SRF_IP_CONN_PKT_TYPE_CLOSE                0x08		// No payload
#define SRF_IP_CONN_PKT_TYPE_DATA_RAW             0x09		// Payload: srf_ip_conn_data_raw_t
#define SRF_IP_CONN_PKT_TYPE_DATA_DMR             0x0a 		// Payload: srf_ip_conn_data_dmr_t
#define SRF_IP_CONN_PKT_TYPE_DATA_DSTAR           0x0b 		// Payload: srf_ip_conn_data_dstar_t
#define SRF_IP_CONN_PKT_TYPE_DATA_C4FM            0x0c  	// Payload: srf_ip_conn_data_c4fm_t
typedef uint8_t srf_ip_conn_pkt_type_t;

typedef struct __attribute__((packed)) {
	char protocol_id[6];									// "SRFIPC"
	uint8_t version;										// 0x00
	srf_ip_conn_pkt_type_t pkt_type;						// Packet type
} srf_ip_conn_header_t;										// 8 bytes total

// LOGIN PACKETS

typedef struct __attribute__((packed)) srf_ip_conn_login {
	uint32_t client_id;
} srf_ip_conn_login_t;										// 4 bytes total

typedef struct __attribute__((packed)) srf_ip_conn_token {
	uint8_t token[8];										// 8 bytes of random data
} srf_ip_conn_token_t;										// 8 bytes total

typedef struct __attribute__((packed)) srf_ip_conn_auth_t {
	uint8_t hmac[32];										// Hashed Message Auth Code, sha256( token + secret password )
} srf_ip_conn_auth_t;										// 32 bytes total

typedef struct __attribute__((packed)) srf_ip_conn_config {
	char operator_callsign[11];								// Operator callsign, null-terminated
	char hw_manufacturer[17];								// Hardware manufacturer, null-terminated
	char hw_model[17];										// Hardware model number, null-terminated
	char hw_version[9];										// Hardware version, null-terminated
	char sw_version[9];										// Software version, null-terminated
	uint32_t rx_freq;										// RX frequency in Hz
	uint32_t tx_freq;										// TX frequency in Hz
	uint8_t tx_power;										// ERP in dBm
	float latitude;											// Latitude
	float longitude;										// Longitude
	uint16_t height;										// Height above ground level in m
	char location[33];										// Location, null-terminated
	char description[33];									// Description, null-terminated
	uint8_t hmac[32];										// Hashed Message Auth Code, sha256 ( token + secret password + all fields of this struct except hmac )
} srf_ip_conn_config_t;										// 181 bytes total

// RAW

typedef struct __attribute__((packed)) srf_ip_conn_data_raw {
	uint8_t version;                            			// 0x00
	uint32_t seq_no;										// Sequence number (starts from 0 and incremented for every data packet for the whole connection)
	int8_t rssi_dbm;										// Received signal strength
	uint8_t length;											// Length of raw data in bytes
	uint8_t data[120];										// Raw data
	uint8_t hmac[32];										// Hashed Message Auth Code, sha256 ( token + secret password + all fields of this struct except hmac )
} srf_ip_conn_data_raw_t;									// 159 bytes total

// DMR

#define	SRF_IP_CONN_DATA_DMR_SLOT_TYPE_UNKNOWN				0x00
#define	SRF_IP_CONN_DATA_DMR_SLOT_TYPE_VOICE_LC_HEADER		0x01
#define	SRF_IP_CONN_DATA_DMR_SLOT_TYPE_TERMINATOR_WITH_LC	0x02
#define	SRF_IP_CONN_DATA_DMR_SLOT_TYPE_CSBK					0x03
#define	SRF_IP_CONN_DATA_DMR_SLOT_TYPE_DATA_HEADER			0x04
#define	SRF_IP_CONN_DATA_DMR_SLOT_TYPE_RATE_12_DATA			0x05
#define	SRF_IP_CONN_DATA_DMR_SLOT_TYPE_RATE_34_DATA			0x06
#define	SRF_IP_CONN_DATA_DMR_SLOT_TYPE_VOICE_DATA_A			0x0a
#define	SRF_IP_CONN_DATA_DMR_SLOT_TYPE_VOICE_DATA_B			0x0b
#define	SRF_IP_CONN_DATA_DMR_SLOT_TYPE_VOICE_DATA_C			0x0c
#define	SRF_IP_CONN_DATA_DMR_SLOT_TYPE_VOICE_DATA_D			0x0d
#define	SRF_IP_CONN_DATA_DMR_SLOT_TYPE_VOICE_DATA_E			0x0e
#define	SRF_IP_CONN_DATA_DMR_SLOT_TYPE_VOICE_DATA_F			0x0f
typedef uint8_t srf_ip_conn_data_dmr_slot_type_t;

typedef struct __attribute__((packed)) srf_ip_conn_data_dmr {
	uint8_t version;                                     	// 0x00
	uint32_t seq_no;										// Sequence number (starts from 0 and incremented for every data packet for the whole connection)
	uint8_t dst_id[3];										// Destination DMR ID
	uint8_t src_id[3];										// Source DMR ID
	uint8_t tdma_channel						: 1;
	uint8_t call_type							: 1;		// Private = 0; Group = 1
	uint8_t reserved							: 6;
	srf_ip_conn_data_dmr_slot_type_t slot_type	: 4;
	uint8_t color_code							: 4;
	int8_t rssi_dbm;										// Received signal strength
	uint8_t data[33];										// Raw DMR data
	uint8_t hmac[32];										// Hashed Message Auth Code, sha256 ( token + secret password + all fields of this struct except hmac )
} srf_ip_conn_data_dmr_t;									// 79 bytes total

// D-STAR

#define SRF_IP_CONN_DATA_DSTAR_PACKET_TYPE_DATA             0x00
#define SRF_IP_CONN_DATA_DSTAR_PACKET_TYPE_CALL_START       0x01
#define SRF_IP_CONN_DATA_DSTAR_PACKET_TYPE_CALL_END         0x02
typedef uint8_t srf_ip_conn_data_dstar_packet_type_t;

typedef struct __attribute__((packed)) srf_ip_conn_data_dstar {
	uint8_t version;										// 0x00
    uint32_t seq_no;										// Sequence number (starts from 0 and incremented for every data packet for the whole connection)
    uint8_t dst_callsign[9];								// Destination callsign, null-terminated
    uint8_t src_callsign[9];								// Source callsign, null-terminated
    uint8_t src_callsign_suffix[5];							// Source callsign suffix, null-terminated
    int8_t rssi_dbm;										// Received signal strength
    uint8_t packet_count;									// Number of D-STAR packets in current packet, max 9
    srf_ip_conn_data_dstar_packet_type_t packet_types[9];	// Type of each packet in the current packet
    uint8_t data[108];										// Raw D-STAR packet data (12 bytes * 9 packets)
    uint8_t hmac[32];										// Hashed Message Auth Code, sha256 ( token + secret password + all fields of this struct except hmac )
} srf_ip_conn_data_dstar_t;									// 179 bytes total

// C4FM

#define	SRF_IP_CONN_DATA_C4FM_PACKET_TYPE_HEADER			0x00
#define	SRF_IP_CONN_DATA_C4FM_PACKET_TYPE_VDMODE1			0x01
#define	SRF_IP_CONN_DATA_C4FM_PACKET_TYPE_VDMODE2			0x02
#define	SRF_IP_CONN_DATA_C4FM_PACKET_TYPE_DATA_FR			0x03
#define	SRF_IP_CONN_DATA_C4FM_PACKET_TYPE_VOICE_FR			0x04
#define	SRF_IP_CONN_DATA_C4FM_PACKET_TYPE_TERMINATOR		0x05
typedef uint8_t srf_ip_conn_data_c4fm_packet_type_t;

typedef struct __attribute__((packed)) srf_ip_conn_dat_c4fm {
    uint8_t version;										// 0x00
    uint32_t seq_no;										// Sequence number (starts from 0 and incremented for every data packet for the whole connection)
    uint8_t dst_callsign[11];								// Destination callsign, null-terminated
    uint8_t src_callsign[11];								// Source callsign, null-terminated
	uint8_t call_type							: 1;		// Private = 0; Group = 1
	uint8_t reserved							: 7;
    int8_t rssi_dbm;										// Received signal strength
	srf_ip_conn_data_c4fm_packet_type_t packet_type;
    uint8_t data[120];										// Raw C4FM packet data
    uint8_t hmac[32];										// Hashed Message Auth Code, sha256 ( token + secret password + all fields of this struct except hmac )
} srf_ip_conn_data_c4fm_t;									// 182 bytes total

#define SRF_IP_CONN_PACKETS_MAX_SIZE						(sizeof(srf_ip_conn_header_t)+sizeof(srf_ip_conn_data_c4fm_t))

#endif
