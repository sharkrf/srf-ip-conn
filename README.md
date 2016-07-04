# SharkRF IP Connector Protocol (Draft)

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
![Login Process Diagram](https://cdn.rawgit.com/akosmarton/e52fced36f0f7748f2ab6ad52517502a/raw/1941176e04990310842efca9443ff3cd97eb4772/diagram-login.svg)

Max. password length is 32 characters. Server limits auth tries for only one in every 5 seconds. Packets with invalid HMAC are ignored.

### Config update (optional)

Client can optionally update it's config information.

<!--
Client->Server: Config
Server->Client: ACK
-->

### Ping

Client should ping the server periodically at least once every 30 seconds (5 seconds is recommended to keep firewalls open) after the last packet has sent to the server. No need to send ping if client transmits in this 5 second timeframe. The server ends the connection after 30 seconds of inactivity.

<!---
Client->Server: Ping
Server->Client: Pong
-->
![Ping Diagram](https://cdn.rawgit.com/akosmarton/056f75e19987bca3a54152c9e270d8ff/raw/df25347f4b59beb20a43fa52840e5d6b6ef01c7a/diagram-ping.svg)

### Data

Data packets can be sent in both directions.

<!--
Client->Server: Data
Client->Server: Data
Server->Client: Data
Client->Server: Data
Server->Client: Data
-->
![Data Diagram](https://cdn.rawgit.com/akosmarton/4e98576fceca53b38bc0f6debcc327b4/raw/b1244833e428a7ef0537b9c10442225f0951b129/diagram-data.svg)

If client's sequence number is smaller than the last one received by the server, the server will close the connection. In this case, the client must re-initialize the connection starting with the login process.

### Closing the connection

Both participants can close the connection gracefully.

<!--
Client->Server: Close
Server->Client: ACK
-->
<!--
Server->Client: Close
-->
![Close Diagram 1](https://cdn.rawgit.com/akosmarton/de355c0ffa6450a97cc6da84d68e4223/raw/ebaaea40eabf79e616a29fe2bdbc452b49aeec7a/diagram-close1.svg)	![Close Diagram 2](https://cdn.rawgit.com/akosmarton/97ba1a469ee1b4b52801d7448b971610/raw/67a127845b438c1a67470d7ae791332bf719182a/diagram-close2.svg)

## Packet Structure

The protocol uses UDP as transport layer. Server listens on port 65100 by default.

UDP payload structure:

Header | Payload
--- | ---

See common/srf-ip-conn-packets.h for used packet structures. Byte order is big-endian.
