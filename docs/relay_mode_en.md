# UDPHop Relay Mode Configurations

## Configuration file example

Example of client mode:
```
mode=client
kcp=regular3
inbound_bandwidth=500M
outbound_bandwidth=50M
listen_port=59000
destination_port=3000-3010
destination_address=123.45.67.89
encryption_password=qwerty1234
encryption_algorithm=AES-GCM
```

Example of relay mode:
```
mode=relay

[listener]
kcp=regular3
inbound_bandwidth=300M
outbound_bandwidth=300M
listen_port=3000-3010
encryption_password=qwerty1234
encryption_algorithm=AES-GCM

[forwarder]
kcp=regular2
inbound_bandwidth=300M
outbound_bandwidth=300MM
destination_port=13000-13010
destination_address=87.65.43.21
encryption_password=qwerty1234
encryption_algorithm=AES-OCB
udp_timeout=10
```

Example of server mode:
```
mode=server
kcp=regular2
inbound_bandwidth=1G
outbound_bandwidth=1G
listen_port=13000-13010
destination_port=59000
destination_address=::1
encryption_password=qwerty1234
encryption_algorithm=AES-OCB
```

As you can see, some settings and encryption options for the client and server are different.

That's right, you only need to correctly configure the channels on both sides of the relay station, and the relay node will re-encrypt when forwarding.

Process:
```mermaid
sequenceDiagram
    participant User's Application
    participant UDPHop Client
    participant UDPHop Relay
    participant UDPHop Server
    participant Server's Application
    User's Application->>UDPHop Client: Application Data
    Note over UDPHop Client: destination_port=13000-14000
    UDPHop Client->>UDPHop Relay: UDPHop Client Data
    UDPHop Client-->>UDPHop Relay: AES-GCM
    Note over UDPHop Relay: [listener]<br/>listen_port=13000-14000<br/>#10;<br/>[forwarder]<br>destination_port=13000-13010
    UDPHop Relay->>UDPHop Server: 13000-14000 Client Data
    UDPHop Relay-->>UDPHop Server: AES-OCB
    Note over UDPHop Server: listen_port=13000-13010
    UDPHop Server->>Server's Application: Application Data
    Server's Application->>UDPHop Server: Response Data
    UDPHop Server->>UDPHop Relay: UDPHop Server Data
    UDPHop Server-->>UDPHop Relay: AES-OCB
    UDPHop Relay->>UDPHop Client: UDPHop Server Data
    UDPHop Relay-->>UDPHop Client: AES-GCM
    UDPHop Client->>User's Application: Response Data
```

## Shareable options for Configuration Files

The following configuration options can be used outside `[listener]` and `[forwarder]` sections:
- encryption_password
- encryption_algorithm
- timeout
- keep_alive
- ipv4_only=1
- fec

If these options appear outside of sections label, they override all corresponding values inside the section label. Among them, `ipv4_only=1` is a special case, it is only covered when `ipv4_only=1`, and it is not covered when `ipv4_only=0`.

Because `ipv4_only=0` means to use the default setting, that is, dual-stack mode.


## Notes
If you need to configure `timeout` yourself, please ensure that the `timeout` of the relay node is greater than or equal to the `timeout` value of the server and client to avoid prematurely clearing the forwarding link.

## About the Section Tags
When configuring relay mode, it is necessary to clearly write the section labels of the two nodes - `[listener]` and `[forwarder]`, which cannot be ignored.