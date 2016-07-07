# SharkRF IP Connector Protocol

This is the protocol used by [SharkRF openSPOT](https://www.sharkrf.com/products/openspot/)'s UDP API to allow 3rd party developers to create their own applications which communicate using openSPOT. The protocol is designed for simplicity.

You can find a demo client and server application in this repo.

## Protocol Description

### Login process

Client has to start the connection with the login process. If NAK is received or timeout happens during the process, client has to retry logging in later. At least 5 seconds should be kept between retries, as server ignores frequent auth requests.

<!--
Client->Server: Login
Server->Client: Token
Note left of Client: Token is used to generate HMAC
Client->Server: Auth
Note right of Server: If authorized,\nthe server replies with ACK,\notherwise NAK
Server->Client: ACK
Note over Client: Client is now logged in.
-->
![Login Process Diagram](https://cdn.rawgit.com/sharkrf/srf-ip-conn/master/img/login.svg)

Max. password length is 32 characters. Server limits auth tries for only one in every 5 seconds. Packets with invalid HMAC are ignored.

### Config update (optional)

Client can optionally update it's config information.

<!--
Client->Server: Config
Server->Client: ACK
-->
![Config Process Diagram](https://cdn.rawgit.com/sharkrf/srf-ip-conn/master/img/config.svg)

### Ping

Client should ping the server periodically at least once every 30 seconds (5 seconds is recommended to keep firewalls open) after the last packet has sent to the server. No need to send ping if client transmits in this 5 second timeframe. The server ends the connection after 30 seconds of client inactivity.

<!---
Client->Server: Ping
Server->Client: Pong
-->
![Ping Process Diagram](https://cdn.rawgit.com/sharkrf/srf-ip-conn/master/img/ping.svg)

### Data

Data packets can be sent in both directions.

<!--
Client->Server: Data
Client->Server: Data
Server->Client: Data
Client->Server: Data
Server->Client: Data
-->
![Data Diagram](https://cdn.rawgit.com/sharkrf/srf-ip-conn/master/img/data.svg)

### Closing the connection

Both participants can close the connection gracefully.

<!--
Client->Server: Close
Server->Client: ACK
-->
![Close Process Diagram 1](https://cdn.rawgit.com/sharkrf/srf-ip-conn/master/img/close-client.svg)
<!--
Server->Client: Close
-->
![Close Process Diagram 2](https://cdn.rawgit.com/sharkrf/srf-ip-conn/master/img/close-server.svg)

## Packet Structure

The protocol uses UDP as transport layer. Server listens on port 65100 by default.

UDP packet (*srf_ip_conn_packet_t*) structure:

Header | Payload
--- | ---

See [srf-ip-conn/common/srf-ip-conn-packet.h](https://github.com/sharkrf/srf-ip-conn/blob/master/srf-ip-conn/common/srf-ip-conn-packet.h) for used packet structures. Byte order is big-endian.
