# UDP Hop

[点击此处查看简体中文版](README.md)

## Brief Introduction
Some ISPs limit the UDP traffic of home broadband, such as the three major ISPs in China.

To overcome this limitation, a common solution is to "turn" UDP traffic into TCP traffic using tools such as udp2raw. Unfortunately, the server version of udp2raw only supports Linux. Phantun is another tool similar to udp2raw.

So, can we continue to use UDP to avoid speed limits? This approach would offer more flexibility. Perhaps we can, as someone has suggested that after UDP is limited, the speed will recover as long as we reconnect.

If that's the case, we can build a new tool based on this idea - let's call it UDP Hop. **Every once in a while, the UDP Hop client will automatically re-establish a connection and transfer the transmission link to the new connection to continue sending data.**

For the convenience of Full Cone NAT users of home broadband, when UDP Hop runs in server basic mode, it can use STUN punch-through and support both IPv4 and IPv6.

### Detailed Introduction
Unlike TCP disguised tools, UDP Hop keeps using UDP throughout the process and assigns a Session ID for each UDP connection ("source IP: source port" tuple) internally to distinguish multiple UDP connections. The timeout period is 180 seconds, which means that a single Session will be automatically cleared if there is no traffic for more than 3 minutes.

When using it in practice, adjust the frequency of port hopping according to device performance to avoid causing significant NAT pressure on your gateway device, thereby affecting network performance. If conditions permit, it is recommended to run it on a soft router. If the soft router itself is also the gateway, this can eliminate NAT burden.

#### Related Projects
If you want to forward TCP traffic at the same time, you can try [KCP Tube](https://github.com/cnbatch/kcptube).

## Usage

**Reminder:** The time of the client must be synchronized with the server and the time difference cannot exceed 255 seconds.

### Basic Usage
`udphop config.conf`

Example of client mode:
```
mode=client
listen_port=59000
destination_port=3000
destination_address=123.45.67.89
dport_refresh=3600
encryption_password=qwerty1234
encryption_algorithm=AES-GCM
```

Example of server mode:
```
mode=server
listen_port=3000
destination_port=59000
destination_address=::1
encryption_password=qwerty1234
encryption_algorithm=AES-GCM
stun_server=stun.qq.com
log_path=./
```

Note: The `listen_port` in client mode does not necessarily have to be equal to the `destination_port` in server mode; the ports on both sides can be different.

If you want to specify the network card to listen on, simply specify the IP address of that network card by adding a line:
```
listen_on=192.168.1.1
```

If you want to listen on multiple ports and multiple network cards, separate them into multiple configuration files:
```
udphop config1.conf config2.conf
```

#### Verify configuration files
Use the ``--check-config`` option to check the configuration file for errors.
```
kcptube --check-config config1.conf
```
or
```
kcptube config1.conf --check-config
```

### More Flexible Usage - Dynamic Port in Server Mode

Example of client mode:
```
mode=client
listen_port=6000
destination_port=3000-4000
destination_address=123.45.67.89
dport_refresh=3600
encryption_password=qwerty1234
encryption_algorithm=AES-GCM
```

Example of server mode:
```
mode=server
listen_port=3000-4000
destination_port=6000
destination_address=::1
encryption_password=qwerty1234
encryption_algorithm=AES-GCM
```

### Parameter Introduction

| Name                | Possible Values     | Required | Remarks |
| ----                | ----                | ----     | ----    |
| mode                | client<br>server    | Yes      | Choose between client and server mode |
| listen_on | domain name or IP address |No|domain name / IP address only. Multiple addresses should be comma-separated.|
| listen_port         | 1 - 65535           | Yes      | Specify the port range when running as a server |
| destination_port    | 1 - 65535           | Yes      | Specify the port range when running as a client |
| destination_address | IP address, domain name | Yes   | When inputting an IPv6 address, no need for square brackets. Multiple addresses should be comma-separated.|
| dport_refresh       | 20 - 65535          | No       | Unit: seconds. Default value is 60 seconds. If less than 20 seconds, it will be considered as 20 seconds; if greater than 65535, it will be considered as 65536 seconds |
| encryption_algorithm| AES-GCM<br>AES-OCB<br>chacha20<br>xchacha20 | No | Select from AES-256-GCM-AEAD, AES-256-OCB-AEAD, ChaCha20-Poly1305, XChaCha20-Poly1305 |
| encryption_password | Any characters      | Depending on situation | Required when setting encryption_algorithm |
| timeout             | 0 - 65535           | No       | Unit: seconds. Default value is 1800. Set to 0 to use the default value. Represents the timeout setting between the UDP application and udphop |
| keep_alive          | 0 - 65535           | No       | Default value is 0, which means Keep Alive is disabled |
| stun_server         | STUN server address  | No       | Cannot be used when listen_port is in port range mode |
| log_path            | Directory for storing logs | No  | Should point to a directory, not a file itself. If not needed, remove this line |
| ipv4_only           | yes<br>true<br>1<br>no<br>false<br>0 | No | If IPv6 is disabled on the system, enable this option and set to yes, true, or 1 |
| ipv6_only | yes<br>true<br>1<br>no<br>false<br>0 |No|Ignore IPv4 address|
| fec                 | uint8:uint8         | No       | Format is `fec=D:R`, for example `fec=20:3`. The total of D + R cannot exceed 255. If one side is set to 0, it means this option is not used. Both ends must have the same settings |
| \[listener\] | N/A |Yes<br>(Relay Mode only)|Section Name of Relay Mode, UDPHop settings for specifying the listening mode<br>This tag represents data exchanged with the client|
| \[forwarder\] | N/A  |Yes<br>(Relay Mode only)|Section Name of Relay Mode, UDPHop settings for specifying the forwarding mode<br>This tag represents data exchanged with the server|

#### FEC (Forward Error Correction)
FEC format is `fec=D:R`, where D represents the original data quantity, and R represents the redundancy data quantity. The total of D + R cannot exceed 255.

For example, you can input `fec=20:4`, which means for every 20 data packets sent, 4 redundant packets are generated and sent.

**Reminder**: It is not recommended for OpenVPN using AEAD encryption mode to use this feature, because OpenVPN's tolerance for out-of-order packets is very poor under this circumstance, and UDPHop is not responsible for reordering packets, even for FEC-recovered data.

#### 中继模式
Please refer to [The Usage of Relay Mode](docs/relay_mode_en.md).

### Log Files
After obtaining the punched IP address and port for the first time, and when there is a change in the punched IP address and port, an `ip_address.txt` file will be created in the Log directory (overwriting if it already exists), with the IP address and port written into it.

The obtained punched address will also be displayed in the console.

`log_path=` must point to a directory, not a file itself.

If log writing is not needed, then remove the `log_path` line.

### STUN Servers
STUN Servers found in [NatTypeTeste](https://github.com/HMBSbige/NatTypeTester):
- stun.syncthing.net
- stun.qq.com
- stun.miwifi.com
- stun.bige0.com
- stun.stunprotocol.org

STUN Servers found in [Natter](https://github.com/MikeWang000000/Natter):

- fwa.lifesizecloud.com
- stun.isp.net.au
- stun.freeswitch.org
- stun.voip.blackberry.com
- stun.nextcloud.com
- stun.stunprotocol.org
- stun.sipnet.com
- stun.radiojar.com
- stun.sonetel.com
- stun.voipgate.com

Other STUN Servers: [public-stun-list.txt](https://gist.github.com/mondain/b0ec1cf5f60ae726202e)

---

## Pre-compiled binaries
To facilitate usage, pre-compiled binary executable files are provided for multiple platforms:
- Windows
- FreeBSD
- Linux

All pre-compiled binary files are statically compiled. The Linux version is mostly statically compiled, except for libc. Therefore, two versions are prepared, one for glibc (2.31) and the other for musl.

### Docker Image

For Linux environments, Docker images are also available (currently limited to x64). Download udphop_docker_image.zip and unzip it, then import it using `docker load -i udphop_docker.tar`.

After importing, the usage is as follows:
```
docker run -v /path/to/config_file.conf:/config_file.conf udphop config_file.conf
```

For example:
```
docker run -v /home/someone/config1.conf:/config1.conf udphop config1.conf
```

---

## Setting up the service
### FreeBSD

FreeBSD users can copy the downloaded binary file to `/usr/local/bin/` and then run the command:
```
chmod +x /usr/local/bin/udphop
```

The corresponding service files in the `service` directory of this project have been prepared.

1. Find the udphop file and copy it to `/usr/local/etc/rc.d/`.
2. Run the command `chmod +x /usr/local/etc/rc.d/udphop`.
3. Copy the configuration file to `/usr/local/etc/udphop/`.
    - Remember to name the configuration file `config.conf`.
        - The full pathname is: `/usr/local/etc/udphop/config.conf`.
4. Add a line to `/etc/rc.conf`: `udphop_enable="YES"`

Finally, run `service udphop start` to start the service.

---

## Compilation
The compiler must support C++17.

Dependencies:

- [asio](https://github.com/chriskohlhoff/asio) ≥ 1.18.2
- [botan3](https://github.com/randombit/botan)

### Windows
Please use vcpkg to install the dependency package `asio` in advance, with one command:

```
vcpkg install asio:x64-windows asio:x64-windows-static
vcpkg install botan:x64-windows botan:x64-windows-static
```
(If you need ARM or 32-bit x86 versions, please adjust the options yourself.)

Then open `sln\udphop.sln` with Visual Studio and compile it yourself.

### FreeBSD
Similarly, install dependencies asio and botan3 first, and cmake is also required. You can use the system's built-in pkg to install them:

```
pkg install asio botan3 cmake
```
Then build in the build directory:
```
mkdir build
cd build
cmake ..
make
```

### NetBSD
The steps are similar to FreeBSD. For NetBSD, use [pkgin](https://www.netbsd.org/docs/pkgsrc/using.html) to install dependencies and cmake:
```
pkgin install asio
pkgin install cmake
```

Please use `pkg_add` on OpenBSD to install the two dependencies mentioned above. On DragonflyBSD, please use `pkg`, the usage is the same as FreeBSD.

Since botan-3 is not yet included in these BSD systems, it needs to be compiled manually.

Please refer to the aforementioned FreeBSD for the remaining build steps.

Note that due to the lower versions of the compilers included in these BSD systems, please install a higher version of GCC in advance.

### Linux
The steps are similar to FreeBSD. Install asio and botan3 as well as cmake using the package manager provided by the distribution.

#### Alpine
````
apk add asio botan3-libs cmake
````
Then build in the build directory:
```
mkdir build
cd build
cmake ..
make
```

#### Notes on static compilation
There are two approaches:

- **Approach 1**

   Compile as usual and delete the generated `udphop` binary file. Then run the command:
    ```
    make VERBOSE=1
    ```
    Extract the last C++ linking command from the output, replace the `-lbotan-3` in the middle with the **full path** to `libbotan-3.a`, for example `/usr/lib/x86_64-linux-gnu/libbotan-3.a`.

- **Approach 2**

    Open `src/CMakeLists.txt`, change `target_link_libraries(${PROJECT_NAME} PRIVATE botan-3)` to `target_link_libraries(${PROJECT_NAME} PRIVATE botan-3 -static)`.

    Then compile as usual. Note that if the system uses glibc, this will statically compile glibc as well, resulting in warnings about `getaddrinfo`.

### macOS
I don't have a Mac computer, please figure out the steps by yourself.

---

## Improving UDP transmission performance
Increasing the receive buffer can improve UDP transmission performance.
### FreeBSD
Use the command `sysctl kern.ipc.maxsockbuf` to check the buffer size. To adjust it, run the command (change the number to the desired value):
```
sysctl -w kern.ipc.maxsockbuf=33554434
```
Alternatively, write it to `/etc/sysctl.conf`:
```
kern.ipc.maxsockbuf=33554434
```
### NetBSD & OpenBSD
Use the command `sysctl net.inet.udp.recvspace` to check the receive buffer size. To adjust it, run the command (change the number to the desired value):
```
sysctl -w net.inet.udp.recvspace=33554434
```
Alternatively, write it to `/etc/sysctl.conf`:
```
net.inet.udp.recvspace=33554434
```
If necessary, you can also adjust the value of `net.inet.udp.sendspace`. This is the setting for the send buffer.
### Linux
For the receive buffer, use the commands `sysctl net.core.rmem_max` and `sysctl net.core.rmem_default` to check the size.

To adjust it, run the command (change the number to the desired value):
```
sysctl -w net.core.rmem_max=33554434
sysctl -w net.core.rmem_default=33554434
```
Alternatively, write it to `/etc/sysctl.conf`:
```
net.core.rmem_max=33554434
net.core.rmem_default=33554434
```
If necessary, you can also adjust the values of `net.core.wmem_max` and `net.core.wmem_default`. These are the settings for the send buffer.

## IPv4 Mapped to IPv6
Since udphop internally uses IPv6 single-stack + enabling IPv4-mapped IPv6 addresses to simultaneously use IPv4 and IPv6 networks, make sure that the `v6only` option is set to 0.

**In normal situations, no additional settings are required. FreeBSD, Linux, and Windows all allow IPv4 addresses to be mapped to IPv6 by default.**

If the system does not support IPv6 or it is disabled, set `ipv4_only=true` in the configuration file. This will cause udphop to fall back to using IPv4 single-stack mode.

## Other notes
### MTU

UDPHop does not split data packets, it only adds a "shell" on the original data packet. Therefore, for programs like OpenVPN, the MTU value needs to be modified.

The size of the "shell" added by UDPHop is:

UDPHop data header occupies 12 bytes.

- Encryption option
    - If encryption is enabled, an additional 48 bytes are added
    - If encryption is not enabled, only 2 bytes are added for checksum

If FEC is enabled, an additional 5 bytes will be occupied.

### NetBSD
Use the command
```
sysctl -w net.inet6.ip6.v6only=0
```
After setting, single-stack + mapping address mode can listen to dual-stack.

However, for unknown reasons, it is not possible to actively connect to IPv4 mapped addresses.

### OpenBSD
Because OpenBSD completely blocks IPv4 mapped addresses, if dual-stack is used on the OpenBSD platform, the configuration file needs to be saved as two, one of which enables ipv4_only=1, and then both configuration files are loaded when using udphop.

### Too Many Open Files Encountered by Multiple Systems
Most of the time, this prompt is only encountered on the server side and not on the client side.

If it does occur on the client side, please check if the value of `mux_tunnels` is too high (please also refer to the "Multiplexing (mux_tunnels=N)" section).

#### GhostBSD
In general, most BSD systems will not encounter this, only GhostBSD updated in the second half of 2023 will encounter this phenomenon.

This is because GhostBSD has added this line in `/etc/sysctl.conf`:
```
kern.maxfiles=100000
```
This line reduces the upper limit, far below the corresponding value of the original FreeBSD.

The solution is simple, just delete this line. Commenting it out also works.<br />
You can also use the command `sysctl kern.maxfiles=300000` to temporarily modify the upper limit value.

#### Linux
Due to the Open Files limit in Linux system being 1024, it is easy to encounter this problem.

Temporary solution:
1. Run the command `ulimit -n` to check the output value
2. If the value is indeed only 1024, run the command `ulimit -n 300000`

Permanent solution:<br />
Edit /etc/security/limits.conf and add at the end:

```
*         hard    nofile       300000
*         soft    nofile       300000
root      hard    nofile       300000
root      soft    nofile       300000
```

## About the Code

### Thread Pool
The thread pool used by UDPHop comes from [BS::thread_pool](https://github.com/bshoshany/thread-pool), with some modifications made for parallel encryption and decryption processing in multiple connections.

### FEC

The FEC used by UDPHop uses Reed-Solomon coding, and the FEC code library comes from [fecpp](https://github.com/randombit/fecpp) with some modifications.

### Layout
The code is written very casually, wherever I think of writing, so the layout is messy.

As for the reader's feelings... well... that will definitely be unpleasant.