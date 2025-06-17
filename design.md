### aemu Postoffice

The goal of this project is to have reliable pdp and ptp communication between pro clients, by having a central server in the middle to handle all packets.

#### Functional Requirements

- Phase 1
  - Reliable communication
  - Low processing power requirement on clients
  - No port forwarding/dmz/upnp needed
  - Rely on original aemu server implementation for adhocctl peer matching
  - Rely on original aemu match making implementation, which just uses pdp sockets

A -- aemu server -- B
A -- aemu postoffice -- B

#### PDP flow

1. A and B opens a tcp socket to postoffice
2. A and B sends a communication packet registering the listening pdp socket with mac address and port number
3. postoffice sends ack communication packet to both
4. A sends a PDP packet with mac address and port pair of B to postoffice
5. postoffice forwards the PDP packet to B, with A's mac address and port

#### PTP flow

1. A opens a tcp socket to postoffice
2. A sends a communication packet registering the listen state with a mac address and a port number
3. B opens a tcp socket to postoffice
4. B sends a communication packet registering the connect state with src mac address and port number, and destination mac address and port number

- Listen socket not exist
5. postoffice would send a communication packet with the error, B should close the socket

- Listen socket found
5. If the destination is found, post office would send a communicaiton packet to A with the connection request containing the mac address and port from B

- Rejection (might not be a case on the ptp api actually)
6. A sends a rejection communication packet to postoffice with B's mac address and port
7. postoffice sends a rejection communicaiton packet to B
8. B should close the socket

- Accept
6. A creates a new tcp socket to postoffice
7. A sends a communicaiton packet to postoffice with both A and B's mac address and port
8. postoffice sends a communication packet to B, both sockets go into data mode

- Data communication
9. In ptp communication mode, both side should just send data directly, no postoffice communcation packets. Postoffice should just pass the data to both ends.

- End
10. A closes the accept socket, marking the end of the communication
11. postoffice closes the connect socket to B
12. B should close the socket now that the postoffice disconnected it
