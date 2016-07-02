# SharkRF IP Connector Protocol 1.0 (Draft)

## Protocol Description

### Login process

Client has to start the connection with the login process. If NAK is received or timeout happens during the process, client must close its socket.

<!--
Client->Server: Login
Note right of Server: If Repeater ID is accepted,\nthe server responds with Token,\n otherwise NAK
Server->Client: Token
Note left of Client: Token is used to generate HMAC
Client->Server: Auth
Note right of Server: If authorized,\nthe server replies with ACK,\n otherwise NAK
Server->Client: ACK
Client->Server: Config
Note right of Server: If Config is valid,\nthe server replies with ACK,\n otherwise NAK
Server->Client: ACK
-->
![Login Process Diagram](https://cdn.rawgit.com/akosmarton/e52fced36f0f7748f2ab6ad52517502a/raw/1941176e04990310842efca9443ff3cd97eb4772/diagram-login.svg)

### Ping

Client should ping the server periodically at least every 5 seconds after the last packet has sent to the server. No need to send ping if client transmits in this 5 second timeframe, the server only ends the session after 30 seconds of inactivity.

<!---
participant Client
participant Server
Client->Server: Ping
Server->Client: Pong
-->
![Ping Diagram](https://cdn.rawgit.com/akosmarton/056f75e19987bca3a54152c9e270d8ff/raw/df25347f4b59beb20a43fa52840e5d6b6ef01c7a/diagram-ping.svg)

### Data

Data packets can be sent in both directions.
If Sequence Number is overflowed, client must re-initalize the connection started with login process.

<!--
Client->Server: Data
Client->Server: Data
Server->Client: Data
Client->Server: Data
Server->Client: Data
-->
![Data Diagram](https://cdn.rawgit.com/akosmarton/4e98576fceca53b38bc0f6debcc327b4/raw/b1244833e428a7ef0537b9c10442225f0951b129/diagram-data.svg)

### Close

Both participants can close the connection gracefully.

<!--
Client->Server: Close
-->
<!--
participant Client
participant Server
Server->Client: Close
-->
![Close Diagram 1](https://cdn.rawgit.com/akosmarton/de355c0ffa6450a97cc6da84d68e4223/raw/ebaaea40eabf79e616a29fe2bdbc452b49aeec7a/diagram-close1.svg)	![Close Diagram 2](https://cdn.rawgit.com/akosmarton/97ba1a469ee1b4b52801d7448b971610/raw/67a127845b438c1a67470d7ae791332bf719182a/diagram-close2.svg)

## Packet Structure

The protocol uses UDP as transport layer. Server listens on port 65100 by default.

UDP payload structure:

Header | Payload *(optional)*
--- | ---

The used byte order is big-endian.

### Header

Every packet contains this header. The payload follows the header. Payload is optional, depends on the Packet Type.

```C
typedef struct __attribute__((packed)) srf_ip_conn_hdr {
	char protocol_id[6];				// "SRFIPC"
	uint8_t version;					// 0x00
	srf_ip_conn_pkt_type_t pkt_type;	// Packet type
} srf_ip_conn_hdr_t;					// 8 bytes total
```

#### Packet Types

```C
#define SRF_IP_CONN_PKT_TYPE_LOGIN                0x00  // No payload
#define SRF_IP_CONN_PKT_TYPE_TOKEN                0x01  // Payload: srf_ip_conn_token_t 
#define SRF_IP_CONN_PKT_TYPE_AUTH                 0x02  // Payload: srf_ip_conn_auth_t
#define SRF_IP_CONN_PKT_TYPE_ACK                  0x03  // No payload
#define SRF_IP_CONN_PKT_TYPE_NAK                  0x04  // No payload
#define SRF_IP_CONN_PKT_TYPE_CONFIG               0x05  // Payload: srf_ip_conn_config_t
#define SRF_IP_CONN_PKT_TYPE_PING                 0x06  // No payload
#define SRF_IP_CONN_PKT_TYPE_PONG                 0x07  // No payload
#define SRF_IP_CONN_PKT_TYPE_CLOSE                0x08  // No payload
#define SRF_IP_CONN_PKT_TYPE_DATA_RAW             0x09  // Payload: srf_ip_conn_data_raw_t
#define SRF_IP_CONN_PKT_TYPE_DATA_DMR             0x0a  // Payload: srf_ip_conn_data_dmr_t
#define SRF_IP_CONN_PKT_TYPE_DATA_DSTAR           0x0b  // Payload: srf_ip_conn_data_dstar_t
#define SRF_IP_CONN_PKT_TYPE_DATA_YSF             0x0c  // Payload: srf_ip_conn_data_ysf_t
typedef uint8_t srf_ip_conn_pkt_type_t;
```

### Payload Types

#### Login

```C
typedef struct __attribute__((packed)) srf_ip_conn_login {
	uint32_t rpt_id;	// Repeater ID
} srf_ip_conn_login_t;	// 4 bytes total
```

#### Token

```C
typedef struct __attribute__((packed)) srf_ip_conn_token {
	uint8_t token[8];	// 8 bytes of random data
} srf_ip_conn_token_t;	// 8 bytes total
```

#### Authentication

```C
typedef struct __attribute__((packed)) srf_ip_conn_auth_t {
	uint8_t hmac[32];	// Hashed Message Auth Code, sha256( token + secret password )
} srf_ip_conn_auth_t;	// 32 bytes total
```

#### Config

```C
typedef struct __attribute__((packed)) srf_ip_conn_config {
	char operator_callsign[11];	// Operator callsign, null-terminated
	char hw_manufacturer[17];	// Hardware manufacturer, null-terminated
	char hw_model[17];			// Hardware model number, null-terminated
	char hw_version[9];			// Hardware version, null-terminated
	char sw_version[9];			// Software version, null-terminated
	uint32_t rx_freq;			// RX frequency in Hz
	uint32_t tx_freq;			// TX frequency in Hz
	uint8_t tx_power;			// ERP in dBm
	float latitude;				// Latitude
	float longitude;			// Longitude
	uint16_t height;			// Height above ground level in m
	char location[33];			// Location, null-terminated
	char description[33];		// Description, null-terminated
	uint8_t hmac[32];			// Hashed Message Auth Code, sha256 ( token + secret password + all fields of this struct except hmac )
} srf_ip_conn_config_t;			// 181 bytes total
```

#### Raw Data

```C
typedef struct __attribute__((packed)) srf_ip_conn_data_raw {
	uint8_t version;									// 0x00
	uint32_t seq_no;									// Sequence number (starts from 0 and incremented for every data packet for the whole connection)
	int8_t rssi_dbm;									// Received signal strength
	uint8_t length;										// Length of raw data in bytes
	uint8_t data[128];									// Raw data
	uint8_t hmac[32];									// Hashed Message Auth Code, sha256 ( token + secret password + all fields of this struct except hmac )
} srf_ip_conn_data_raw_t;								// 166 bytes total
```

#### DMR Data

```C
typedef struct __attribute__((packed)) srf_ip_conn_data_dmr {
	uint8_t version;									// 0x00
	uint32_t seq_no;									// Sequence number (starts from 0 and incremented for every data packet for the whole connection)
	uint8_t dst_id[3];									// Destination DMR ID
	uint8_t src_id[3];									// Source DMR ID
	uint8_t slot								: 1;	// TDMA slot 0 / TDMA slot 1
	uint8_t call_type							: 1;	// Private = 0; Group = 1
	uint8_t reserved							: 6;
	srf_ip_conn_data_dmr_slot_type_t slot_type	: 4;	// Slot type
	uint8_t color_code							: 4;	// Color code
	int8_t rssi_dbm;									// Received signal strength
	uint8_t data[33];									// Raw DMR data
	uint8_t hmac[32];									// Hashed Message Auth Code, sha256 ( token + secret password + all fields of this struct except hmac )
} srf_ip_conn_data_dmr_t;								// 78 bytes total
```

##### Slot Types

```C
#define	SRF_IP_CONN_DATA_DMR_SLOT_TYPE_UNKNOWN                  0x00
#define	SRF_IP_CONN_DATA_DMR_SLOT_TYPE_VOICE_LC_HDR             0x01
#define	SRF_IP_CONN_DATA_DMR_SLOT_TYPE_TERMINATOR_WITH_LC       0x02
#define	SRF_IP_CONN_DATA_DMR_SLOT_TYPE_CSBK                     0x03
#define	SRF_IP_CONN_DATA_DMR_SLOT_TYPE_DATA_HDR                 0x04
#define	SRF_IP_CONN_DATA_DMR_SLOT_TYPE_RATE_12_DATA             0x05
#define	SRF_IP_CONN_DATA_DMR_SLOT_TYPE_RATE_34_DATA             0x06
#define	SRF_IP_CONN_DATA_DMR_SLOT_TYPE_VOICE_DATA_A             0x0a
#define	SRF_IP_CONN_DATA_DMR_SLOT_TYPE_VOICE_DATA_B             0x0b
#define	SRF_IP_CONN_DATA_DMR_SLOT_TYPE_VOICE_DATA_C             0x0c
#define	SRF_IP_CONN_DATA_DMR_SLOT_TYPE_VOICE_DATA_D             0x0d
#define	SRF_IP_CONN_DATA_DMR_SLOT_TYPE_VOICE_DATA_E             0x0e
#define	SRF_IP_CONN_DATA_DMR_SLOT_TYPE_VOICE_DATA_F             0x0f
typedef uint8_t srf_ip_conn_data_dmr_slot_type_t;
```

#### D-STAR Data

```C
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
} srf_ip_conn_data_dstar_t;									// 178 bytes total
```

##### Packet types

```C
#define SRF_IP_CONN_DATA_DSTAR_PACKET_TYPE_DATA          0x00
#define SRF_IP_CONN_DATA_DSTAR_PACKET_TYPE_CALL_START    0x01
#define SRF_IP_CONN_DATA_DSTAR_PACKET_TYPE_CALL_END      0x02
typedef uint8_t srf_ip_conn_data_dstar_packet_type_t;
```

#### Yaesu System Fusion Data *(TBD)*

```C
typedef struct __attribute__((packed)) srf_ip_conn_dat_ysf {
	// TBD
} srf_ip_conn_data_ysf_t;
```

