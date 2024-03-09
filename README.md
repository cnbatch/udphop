# UDP Hop

[Click Here for English Version](README_EN.md)

## 简单介绍
但凡使用过三大运营商的家用宽带，并且需要家宽互联，那么几乎都会体验到 UDP 被限速的情况。

为了解决UDP限速，目前比较常用的做法是使用 udp2raw 之类的工具“变成” TCP 流量。可惜的是， udp2raw 服务端版只支持 Linux。类似 udp2raw 的还有 Phantun。

那么能不能继续用 UDP 规避限速？这样做灵活性就可以高一点了。也许可以，有人提到过，UDP 被限速后只要重新连接，速度就会重新恢复。

既然如此，那就可以基于这个思路造一个新工具——就叫做 UDP Hop。**每隔一段时间，UDP Hop客户端就会自动重新建立连接，并把传输链路转移到新连接上继续传送。**

为了方便家宽 Full Cone NAT 用户使用，UDP Hop以服务端基本模式运行的时候可以利用 STUN 打洞，同时支持 IPv4 与 IPv6。

### 细节介绍
不同于 TCP 伪装工具，UDP Hop 全程保持 UDP，并且会在内部为每一个 UDP 连接（“源IP:源端口”的二元组）分配 Session ID，以此区分多个 UDP 连接。超时时间为 180 秒，换句话说，单个 Session 超过 3 分钟无流量就会自动清除。

实际使用时请根据设备性能适当调整跳换端口的频率，以免对自己的网关设备造成较大的 NAT 压力从而影响网络性能。若条件允许，建议运行在软路由上。如果软路由本身就是网关的话，这样做就可以免除 NAT 负担。

#### 关联项目
如果想同时转发TCP流量，可以试试 [KCP Tube](https://github.com/cnbatch/kcptube)


## 用法

**注意**，客户端的时间与服务端的时间务必同步，时间相差不能大于 255 秒。

### 基本用法
`udphop config.conf`

客户端模式示例：
```
mode=client
listen_port=59000
destination_port=3000
destination_address=123.45.67.89
dport_refresh=3600
encryption_password=qwerty1234
encryption_algorithm=AES-GCM
```

服务端模式示例：
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

备注：客户端模式的 `listen_port` 不一定非要等于服务端模式的 `destination_port`，两边的端口可以不一致。

如果要指定侦听的网卡，那就指定该网卡的 IP 地址，加一行即可
```
listen_on=192.168.1.1
```

如果想要侦听多个端口、多个网卡，那就分开多个配置文件

```
udphop config1.conf config2.conf
```

#### 验证配置文件
使用 ``--check-config`` 选项即可验证配置文件是否正确：
```
kcptube --check-config config1.conf
```
或
```
kcptube config1.conf --check-config
```

### 更灵活用法——服务端模式动态端口

客户端模式示例：
```
mode=client
listen_port=6000
destination_port=3000-4000
destination_address=123.45.67.89
dport_refresh=3600
encryption_password=qwerty1234
encryption_algorithm=AES-GCM
```

服务端模式示例：
```
mode=server
listen_port=3000-4000
destination_port=6000
destination_address=::1
encryption_password=qwerty1234
encryption_algorithm=AES-GCM
```

### 参数介绍

|  名称                | 可设置值            | 必填 |备注|
|  ----                | ----               | ---- | ---- |
| mode                 | client<br>server   |是    |客户端<br>服务端|
| listen_port          | 1 - 65535          |是    |以服务端运行时可以指定端口范围|
| destination_port     | 1 - 65535          |是    |以客户端运行时可以指定端口范围|
| destination_address  | IP地址、域名        |是    |填入 IPv6 地址时不需要中括号|
| dport_refresh        | 20 - 65535         |否    |单位“秒”。预设值 60 秒，小于20秒按20秒算，大于65535时按65536秒算|
| encryption_algorithm | AES-GCM<br>AES-OCB<br>chacha20<br>xchacha20 |否    |AES-256-GCM-AEAD<br>AES-256-OCB-AEAD<br>ChaCha20-Poly1305<br>XChaCha20-Poly1305 |
| encryption_password  | 任意字符            |视情况|设置了 encryption_algorithm 时必填|
| timeout              | 0 - 65535          |否    |单位“秒”。预设值为 1800，设为 0 则使用预设值<br>该选项表示的是，UDP 应用程序 ↔ udphop 之间的超时设置 |
| keep_alive           | 0 - 65535          |否    |预设值为 0，等于停用 Keep Alive |
| stun_server          | STUN 服务器地址     |否    |listen_port 为端口范围模式时不可使用|
| log_path             | 存放 Log 的目录     |否    |不能指向文件本身|
| ipv4_only | yes<br>true<br>1<br>no<br>false<br>0 |否|若系统禁用了 IPv6，须启用该选项并设为 yes 或 true 或 1|
| fec                  | uint8:uint8        |否    |格式为 `fec=D:R`，例如可以填入 `fec=20:3`。<br>注意：D + R 的总数最大值为 255，不能超过这个数。<br>冒号两侧任意一个值为 0 表示不使用该选项。两端的设置必须相同。|
| \[listener\] | N/A |是<br>(仅限中继模式)|中继模式的标签，用于指定监听模式的 UDPHop 设置<br>该标签表示与客户端交互数据|
| \[forwarder\] | N/A  |是<br>(仅限中继模式)|中继模式的标签，用于指定转运模式的 UDPHop 设置<br>该标签表示与服务端交互数据|

#### 前向纠错 (FEC, Forward Error Correction)
FEC 格式为 `fec=D:R`，其中 D 表示原始数据量，R 表示冗余数据量。D + R 的总数最大值为 255，不能超过这个数。

例如可以填入 `fec=20:4`，表示每发送 20 个数据包，就生成并发送 4 个冗余包。

**提醒**：不建议 AEAD 加密模式的 OpenVPN 使用这项功能，因为此时的 OpenVPN 对于乱序数据包的容忍度极差，而 UDPHop 并不负责重新排序数据包，即使是 FEC 恢复的数据同样如此。

#### 中继模式
请参看[中继模式使用说明](docs/relay_mode_zh-hans.md).

### Log 文件
在首次获取打洞后的 IP 地址与端口后，以及打洞的 IP 地址与端口发生变化后，会向 Log 目录创建 ip_address.txt 文件（若存在就覆盖），将 IP 地址与端口写进去。

获取到的打洞地址会同时显示在控制台当中。

`log_path=` 必须指向目录，不能指向文件本身。

如果不需要写入 Log 文件，那就删除 `log_path` 这一行。

### STUN Servers
从[NatTypeTeste](https://github.com/HMBSbige/NatTypeTester)找到的普通 STUN 服务器：
- stun.syncthing.net
- stun.qq.com
- stun.miwifi.com
- stun.bige0.com
- stun.stunprotocol.org

从[Natter](https://github.com/MikeWang000000/Natter)找到的STUN 服务器：

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

其它 STUN 服务器：[public-stun-list.txt](https://gist.github.com/mondain/b0ec1cf5f60ae726202e)

---

## 预编译二进制
为了方便使用，目前已经提供了多个平台的二进制可执行文件：
- Windows
- FreeBSD
- Linux

预编译的二进制文件全部都是静态编译。Linux 版本基本上都是静态编译，但 libc 除外，因此准备了两个版本，一个用于 glibc (2.36)，另一个用于 musl。

### Docker 镜像

对于 Linux 环境，另有提供 Docker 镜像（目前仅限 x64），下载 udphop_docker_image.zip 并解压，再使用 `docker load -i udphop_docker.tar` 导入。

导入后，使用方式为：
```
docker run -v /path/to/config_file.conf:/config_file.conf udphop config_file.conf
```

例如：
```
docker run -v /home/someone/config1.conf:/config1.conf udphop config1.conf
```

---

## 建立服务
### FreeBSD

FreeBSD 用户可将下载好的二进制文件复制到 `/usr/local/bin/`，然后运行命令
```
chmod +x /usr/local/bin/udphop
```

本项目的 `service` 目录已经准备好相应服务文件。

1. 找到 udphop 文件，复制到 `/usr/local/etc/rc.d/`
2. 运行命令 `chmod +x /usr/local/etc/rc.d/udphop`
3. 把配置文件复制到 `/usr/local/etc/udphop/`
    - 记得把配置文件命名为 `config.conf`
        - 完整的路径名：`/usr/local/etc/udphop/config.conf`
4. 在 `/etc/rc.conf` 加一行 `udphop_enable="YES"`

最后，运行 `service udphop start` 即可启动服务

---

## 编译
编译器须支持 C++20

依赖库：

- [asio](https://github.com/chriskohlhoff/asio) ≥ 1.18.2
- [botan3](https://github.com/randombit/botan)

### Windows
请事先使用 vcpkg 安装依赖包 `asio`，一句命令即可：

```
vcpkg install asio:x64-windows asio:x64-windows-static
vcpkg install botan:x64-windows botan:x64-windows-static
```
（如果需要 ARM 或者 32 位 x86 版本，请自行调整选项）

然后用 Visual Studio 打开 `sln\udphop.sln` 自行编译

### FreeBSD
同样，请先安装依赖项 asio 以及 botan3，另外还需要 cmake，用系统自带 pkg 即可安装：

```
pkg install asio botan3 cmake
```
接着在 build 目录当中构建
```
mkdir build
cd build
cmake ..
make
```

### 其它 BSD
步骤与 FreeBSD 类似，NetBSD 请使用 [pkgin](https://www.netbsd.org/docs/pkgsrc/using.html) 安装依赖项与 cmake：
```
pkgin install asio
pkgin install cmake
```
OpenBSD 请使用 `pkg_add` 安装上述两个依赖性。DragonflyBSD 请使用 `pkg`，用法与 FreeBSD 相同。

由于 botan-3 仍未被这几个 BSD 系统收录，须自行编译 botan-3。

剩余的构建步骤请参考上述的 FreeBSD。

注意，由于这几个 BSD 自带的编译器版本较低，请事先额外安装高版本 GCC。

### Linux
步骤与 FreeBSD 类似，请用发行版自带的包管理器安装 asio 与 botan3 以及 cmake。

#### Alpine
````
apk add asio botan3-libs cmake
````
接着在 build 目录当中构建
```
mkdir build
cd build
cmake ..
make
```

#### 静态编译注意事项
有两种做法

- **做法1**

    按照正常流程编译好，删除刚刚生成的 udphop 二进制文件，并运行命令
    ```
    make VERBOSE=1
    ```
    再从输出的内容提取出最后一条 C++ 链接命令，把中间的 `-lbotan-3` 改成 libbotan-3.a 的**完整路径**，例如 `/usr/lib/x86_64-linux-gnu/libbotan-3.a`。


- **做法2**

    打开 src/CMakeLists.txt，把 `target_link_libraries(${PROJECT_NAME} PRIVATE botan-3)` 改成 `target_link_libraries(${PROJECT_NAME} PRIVATE botan-3 -static)`

    然后即可正常编译。注意，如果系统使用 glibc 的话，这样会连同 glibc 一并静态编译，从而会跳出有关 getaddrinfo 的警告。

### macOS
我没苹果电脑，所有步骤请自行解决。

---

## 对 UDP 传输性能的改善
增加接收缓存可以改善 UDP 传输性能
### FreeBSD
可以使用命令 `sysctl kern.ipc.maxsockbuf` 查看缓存大小。如果需要调整，请运行命令（数字改为想要的数值）：
```
sysctl -w kern.ipc.maxsockbuf=33554434
```
或者在 `/etc/sysctl.conf` 写入 
```
kern.ipc.maxsockbuf=33554434
```
### NetBSD & OpenBSD
可以使用命令 `sysctl net.inet.udp.recvspace` 查看接收缓存大小。如果需要调整，请运行命令（数字改为想要的数值）：
```
sysctl -w net.inet.udp.recvspace=33554434
```
或者在 `/etc/sysctl.conf` 写入 
```
net.inet.udp.recvspace=33554434
```
若有必要，可以同时调整 `net.inet.udp.sendspace` 的数值。这是发送缓存的设置。
### Linux
对于接收缓存，可以使用命令 `sysctl net.core.rmem_max` 及 `sysctl net.core.rmem_default` 查看接收缓存大小。

如果需要调整，请运行命令（数字改为想要的数值）：
```
sysctl -w net.core.rmem_max=33554434
sysctl -w net.core.rmem_default=33554434
```
或者在 `/etc/sysctl.conf` 写入 
```
net.core.rmem_max=33554434
net.core.rmem_default=33554434
```
若有必要，可以同时调整 `net.core.wmem_max` 及 `net.core.wmem_default` 的数值。这是发送缓存的设置。

## IPv4 映射 IPv6
由于 udphop 内部使用的是 IPv6 单栈 + 开启 IPv4 映射地址（IPv4-mapped IPv6）来同时使用 IPv4 与 IPv6 网络，因此请确保 v6only 选项的值为 0。

**正常情况下不需要任何额外设置，FreeBSD 与 Linux 以及 Windows 都默认允许 IPv4 地址映射到 IPv6。**

如果系统不支持 IPv6，或者禁用了 IPv6，请在配置文件中设置 ipv4_only=true，这样 udphop 会退回到使用 IPv4 单栈模式。

## 其它注意事项
### MTU

UDPHop 并不拆分数据包，只会在原有数据包上套个“壳”。所以对于 OpenVPN 之类的程序而言，需要修改 MTU 值的设置。

UDPHop “壳”的大小为：

UDPHop 数据头占用 12 字节。

- 加密选项
    - 若启用加密，会增加 48 字节
    - 若不启用加密，则只增加 2 字节用于校验和

若启用 FEC，就再占用 5 字节。

### NetBSD
使用命令
```
sysctl -w net.inet6.ip6.v6only=0
```
设置后，单栈+映射地址模式可以侦听双栈。

但由于未知的原因，无法主动连接 IPv4 映射地址。

### OpenBSD
因为 OpenBSD 彻底屏蔽了 IPv4 映射地址，所以在 OpenBSD 平台使用双栈的话，需要将配置文件保存成两个，其中一个启用 ipv4_only=1，然后在使用 udphop 时同时载入两个配置文件。

### 多种系统都遇到的 Too Many Open Files
大多数情况下，这种提示只会在服务器端遇到，不会在客户端遇到。

如果确实在客户端遇到了，请检查 `mux_tunnels` 的数值是否过高（请顺便参考“多路复用 (mux_tunnels=N)”段落）。
#### GhostBSD
一般情况下，绝大多数 BSD 系统都不会遇到这种事，只有 2023 年下半年更新后的 GhostBSD 才会遇到这种现象。

这是因为 GhostBSD 在 `/etc/sysctl.conf` 当中加了这一行：
```
kern.maxfiles=100000
```
这一行缩减了上限，远低于原版 FreeBSD 的对应数值。

解决办法很简单，删掉这一行即可。注释掉也可以。<br />
还可以使用命令 `sysctl kern.maxfiles=300000` 临时修改上限值。

#### Linux
由于 Linux 系统的 Open Files 数量限制为 1024，所以很容易会遇到这种问题。

临时解决办法：
1. 运行命令 `ulimit -n`，查看输出的数值
2. 如果数值确实只有 1024，请运行命令 `ulimit -n 300000`

永久解决办法：<br />
编辑 /etc/security/limits.conf，在末尾加上

```
*         hard    nofile       300000
*         soft    nofile       300000
root      hard    nofile       300000
root      soft    nofile       300000
```

## 关于代码

### 线程池
udphop 使用的线程池来自于 [BS::thread_pool](https://github.com/bshoshany/thread-pool)，另外再做了些许修改，用于多连接时的并行加解密处理。

### FEC

UDPHop 所用的 FEC 采用 Reed-Solomon 编码， FEC 代码库来自于 [fecpp](https://github.com/randombit/fecpp)，并作了些许修改。

### 版面
代码写得很随意，想到哪写到哪，因此版面混乱。

至于阅读者的感受嘛…… 那肯定会不爽。