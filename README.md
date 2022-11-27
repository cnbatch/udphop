# UDP Hop

## 简单介绍
但凡使用过三大运营商的家用宽带，并且需要家宽互联，那么几乎都会体验到 UDP 被限速的情况。

为了解决UDP限速，目前比较常用的做法是使用 udp2raw 之类的工具“变成” TCP 流量。可惜的是， udp2raw 服务端版只支持 Linux。类似 udp2raw 的还有 Phantun。

那么能不能继续用 UDP 规避限速？这样做灵活性就可以高一点了。也许可以，有人提到过，UDP 被限速后只要重新连接，速度就会重新恢复。

既然如此，那就可以基于这个思路造一个新工具——就叫做 UDP Hop。**每隔一段时间，UDP Hop客户端就会自动重新建立连接，并把传输链路转移到新连接上继续传送。**

为了方便家宽 Full Cone NAT 用户使用，UDP Hop以服务端基本模式运行的时候可以利用 STUN 打洞，同时支持 IPv4 与 IPv6。

### 细节介绍
不同于 TCP 伪装工具，UDP Hop 全程保持 UDP，并且会在内部为每一个 UDP 连接（“源IP:源端口”的二元组）分配 Session ID，以此区分多个 UDP 连接。超时时间为 180 秒，换句话说，单个 Session 超过 3 分钟无流量就会自动清除。

## 用法
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
| encryption_algorithm | AES-GCM<br>AES-OCB |否    |AES-256-GCM-AEAD<br>AES-256-OCB-AEAD|
| encryption_password  | 任意字符            |视情况|设置了 encryption_algorithm 时必填|
| stun_server          | STUN 服务器地址     |否    |listen_port 为端口范围模式时不可使用|
| log_path             | 存放 Log 的目录     |否    |不能指向文件本身|

### Log 文件
目前只提供输出 IP 地址到指定 Log 目录的功能。

在首次获取打洞后的 IP 地址与端口后，以及打洞的 IP 地址与端口发生变化后，会向 Log 目录创建 ip_address.txt 文件（若存在就追加），将 IP 地址与端口写进去。

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

Linux 用户请先安装 botan-2，以便使用加解密共享库。

FreeBSD 用户可将下载好的二进制文件复制到 `/usr/local/bin/`，然后运行命令
```
chmod +x /usr/local/bin/udphop
```

---

## 建立服务
### FreeBSD

**提示：务必事先做完上一个步骤，将二进制文件复制到 `/usr/local/bin/`**

本项目的 `service` 目录已经准备好相应服务文件。

1. 找到 udphopd 文件，复制到 `/usr/local/etc/rc.d/`
2. 运行命令 `chmod +x /usr/local/etc/rc.d/udphopd`
3. 把配置文件复制到 `/usr/local/etc/udphopd/`
    - 记得把配置文件命名为 `config.conf`
        - 完整的路径名：`/usr/local/etc/udphopd/config.conf`
4. 在 `/etc/rc.conf` 加一行 `udphopd_enable="YES"`

最后，运行 `service udphopd start` 即可启动服务

---

## 编译
编译器须支持 C++17

依赖库：

- [asio](https://github.com/chriskohlhoff/asio) ≥ 1.18.2
- [botan2](https://github.com/randombit/botan)

### Windows
请事先使用 vcpkg 安装依赖包 `asio`，一句命令即可：

```
vcpkg install asio:x64-windows asio:x64-windows-static
vcpkg install botan:x64-windows botan:x64-windows-static
```
（如果需要 ARM 或者 32 位 x86 版本，请自行调整选项）

然后用 Visual Studio 打开 `sln\udphop.sln` 自行编译

### FreeBSD
同样，请先安装依赖项 asio 以及 botan2，另外还需要 cmake，用系统自带 pkg 即可安装：

```
pkg install asio botan2 cmake
```
接着在 build 目录当中构建
```
mkdir build
cd build
cmake ..
make
```

### NetBSD
步骤与 FreeBSD 类似，使用 [pkgin](https://www.netbsd.org/docs/pkgsrc/using.html) 安装依赖项与 cmake：
```
pkgin install asio
pkgin install botan-2
pkgin install cmake
```
构建步骤请参考上述的 FreeBSD。

注意，由于 NetBSD 自带的 GCC 版本较低，未必能成功编译出可用的二进制文件，有可能需要用 pkgin 额外安装高版本 GCC。

### Linux
步骤与 FreeBSD 类似，请用发行版自带的包管理器安装 asio 与 botan2 以及 cmake。

#### Fedora
````
dnf install asio botan2 cmake
````
接着在 build 目录当中构建
```
mkdir build
cd build
cmake ..
make
```

如果所使用发行版的 asio 版本过低，需要自行解决。

### macOS
我没苹果电脑，所有步骤请自行解决。

---

## IPv4 映射 IPv6
由于该项目内部使用的是 IPv6 单栈 + 开启 IPv4 映射地址（IPv4-mapped IPv6）来使用 IPv4 网络，因此请确保 v6only 选项的值为 0。

**正常情况下不需要任何额外设置，FreeBSD 与 Linux 以及 Windows 都默认允许 IPv4 地址映射到 IPv6。**

如果不放心，那么可以这样做
### FreeBSD
按照FreeBSD手册 [33.9.5. IPv6 and IPv4 Address Mapping](https://docs.freebsd.org/en/books/handbook/advanced-networking/#_ipv6_and_ipv4_address_mapping) 介绍，在 `/etc/rc.conf` 加一行即可
```
ipv6_ipv4mapping="YES"
```
如果还是不放心，那就运行命令
```
sysctl net.inet6.ip6.v6only=0
```

### Linux
可运行命令
```
sysctl -w net.ipv6.bindv6only=0
```
正常情况下不需要这样做，它的默认值就是 0。

## 其它注意事项
### NetBSD
使用命令
```
sysctl -w net.inet6.ip6.v6only=0
```
设置后，单栈+映射地址模式可以侦听双栈。

但由于未知的原因，它无法主动连接 IPv4 映射地址，因此 `destination_address` 只能使用 IPv6 地址。

### OpenBSD
因为 OpenBSD 彻底屏蔽了 IPv4 映射地址，所以在 OpenBSD 平台只能使用 IPv6 单栈模式。

## 关于代码
### 为什么要用两个 asio::io_context
这里用了两个 asio::io_context，其中一个是用于收发数据的异步循环，另一个用于处理内部逻辑。

之所以要这样做，完全是为了迁就 BSD 系统。如果只用一个 io_context 去做所有的事，由于两次接收之间的延迟过高，在 BSD 平台会导致 UDP 丢包率过高。

## 版面
代码写得很随意，想到哪写到哪，因此版面混乱。