# Wireshark 介绍和 packet analysis
- Wireshark/tcpdump/tshark 的使用
- 数据包在 L2/MAC, L3/IP, L4/TCP/UDP/SSL/TLS, L7/HTTP/HTTPS/WebSocket 的关注点
- TechZone 系列培训资料，[点赞收藏转发吃灰](https://techzone.cisco.com/t5/Troubleshooting-and-Tools/Wireshark-Packet-Analysis-for-TAC-Engineers-Master-Article/ta-p/1819960)
- [Wireshark 数据包导入 IXIA](https://techzone.cisco.com/t5/9000/8-simple-steps-to-replay-Wireshark-pcap-file-through-IXIA/ta-p/1574481)

## 为什么需要做 SPAN/tcpdump
- 业务有延迟，间歇性丢包 (ELAM 不适用）
- 如果在 server，switch/router 等都没有发现 error counter 和 error log，可以借助抓包来缩小故障范围
  - 耗时费力，客户不容易准备环境，TAC 不容易分析数据包；如果有其他方式可选，尽量不要走到这一步
  - 抓包的话，尽量在涉及到的 server，交换机等设备一起抓包；并且保证所有设备的时钟 **NTP 同步**
- 做流量分析，或者业务需求需要做备份 (sflow, netflow)

## Wireshark 使用技巧
- 从 TAC 日常工作中可能遇到的场景出发，这个章节只讲一些技巧，具体栗子可以参考 packets analysis 章节
  - 业务延迟 (Retransmission)
  - 业务 (TCP) 被 reset
- display filter 和排序

### File
- <kbd> Export Specified Packets </kbd>，按需导出报文，比如 Displayed, Selected，Range 等
- <kbd> Export Packets Dissections </kbd>，把报文导出成不同格式，比如 text, CSV, JSON，方便 Ctrl + F 搜索。另一种实现方法是通过 **tshark**，读取特定的报文然后 grep
```bash
cd '/mnt/c/Users/fushuang/OneDrive - Cisco/Documents/work-docs/ACI/packets-capture'
ls -l
tshark -r TLS-Decrypt-gitlab.pcapng | head
tshark -r TLS-Decrypt-gitlab.pcapng -Y frame.number==4            // TLS Client Hello
tshark -r TLS-Decrypt-gitlab.pcapng -Y frame.number==4 -O tls     // 只把 TLS 的详细信息打印出来，其他 L2/L3/L4 只展示 summary

luke:packets-capture$ tshark -r TLS-Decrypt-gitlab.pcapng -Y frame.number==4 -O tls | grep server_name -A 6
            Extension: server_name (len=25)
                Type: server_name (0)
                Length: 25
                Server Name Indication extension
                    Server Name list length: 23
                    Server Name Type: host_name (0)
                    Server Name length: 20
                    Server Name: gitlab-sjc.cisco.com
```

### Time Display Format
- <kbd>View -> Time Display Format</kbd>
- 一般选择 UTC Date and Time of the Day；如果抓包持续时间在同一天，可以选 Time of the Day
- 多个设备同时抓包，横向对比，NTP 时钟的误差一般是几百毫秒

### Time delta - Frame and TCP
- 微信公众号一个 [帖子](https://mp.weixin.qq.com/s/4Msyec4sEQTgxMeFUXlIRg)
- **Frame**
  - 在 <kbd>Frame</kbd> 这一层，两个维度
    - Time delta from previous captured frame   (`frame.time_delta`)
    - Time delta from previous displayed frame  (`frame.time_delta_displayed`) // 如果有 display filter，通常参考这个数值
  - 含义是距离上一个报文的时间，包括了 client/server 处理时间 + 网络传输时间
  - 一个 [案例](https://scripts.cisco.com/app/quicker_csone/?sr=695420786#a096R0000339xXYQAY)
- **TCP**
  - 在 TCP 的 <kbd> Timestamps </kbd> 这一层，有两个维度
    - Time since first frame in this TCP stream     (`tcp.time_relative`) // 同一条 TCP Stream，和第一个 TCP 报文的时间差（不一定是 TCP 三次握手的 SYN，取决于抓包开始的时间）
    - Time since previous frame in this TCP stream  (`tcp.time_delta`)    // 同一条 TCP Stream，前后两个报文的时间差；如果时间差比较大，可能就有业务访问慢的问题。
  - How long it took for the SYN to ACK handshake   (`tcp.analysis.initial_rtt`) // “初始往返时间 iRTT”(Initial Round Trip Time), TCP 三次握手建立连接的时间差，可以作为该条 TCP stream 判断后续 TCP 数据包交互 RTT 时间、TCP 传输延迟等情况的一个参考基准。
![picture 11](./assest/img/tcp-analysis-initial-rtt.png)  

### Apply as Column
- <kbd>Edit -> Appearance -> Columns</kbd>，可以添加 Columns
- 或者直接从某个 packets 的具体 columns，右键单击， 选择 <kbd>Apply as Column</kbd>
- 对于曾经设置为 Column 的选项，可以在任意 Column 右键单击，然后添加 or 取消对应 Column
- 比如把 `frame.time_delta_displayed` 作为单独一列（从高到低排序），可以更方便的做对比，发现一些线索。

### Analyze
- <kbd>Display Filter Expression</kbd>，可以直接搜索 display filter
  - 也可以参考 Wireshark [文档](https://wiki.wireshark.org/DisplayFilters)
  - 或者直接在 display filter 输入，会有提示
- <kbd>Prepare as Filter</kbd>，逐一选中特定的字段，组合一个 filter
- <kbd>Expert Information</kbd> 针对 TCP/HTTP 等协议的一个概览，举个栗子
![picture 15](./assest/img/expert-information.png)  

### Statistics
- 关于 <kbd>Statistics</kbd> 的 [可选功能](https://www.wireshark.org/docs/wsug_html_chunked/ChStatistics.html) 的一些简单介绍，使用场景。

| item                    | function                                                                                                                                                                                            |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Capture File Properties | 抓包文件预览，包含了抓包时长，packets size, 抓包设备软硬件信息 (if available)                                                                                                                       |
| Protocol Hierachy       | 数据包在不同协议的分布，比如 IP, TCP, UDP(DNS), ICMP 占百分比                                                                                                                                       |
| Conversations           | 交互的 IP 地址对的数据包数量，size 的统计，效果和 **Endpoint** 类似                                                                                                                                 |
| Endpoint                | 查看哪些 IP/MAC 交互，[占用的带宽最多](https://www.golinuxcloud.com/measure-bandwidth-wireshark/)                                                                                                   |
| Packets Length          | 数据包长度的统计，burst rate                                                                                                                                                                        |
| I/O Graphs              | 流量趋势（比如业务慢）; 有没有 [burst traffic](https://www.cisco.com/c/en/us/support/docs/lan-switching/switched-port-analyzer-span/116260-technote-wireshark-00.html)                              |
| TCP Stream Graphs       | TCP stream 的统计，比如 Sequence number 随着时间的增长趋势，Throughput, RTT, Window Scaling（滑动窗口）等。[进阶版](https://www.packetsafari.com/blog/2021/10/31/wireshark-tcp-graphs/)，如果感兴趣 |

- 命令 `capinfos`
```bash
luke@ubuntu20:~/wireshark$ capinfos TLS-Decrypt-gitlab.pcapng
File name:           TLS-Decrypt-gitlab.pcapng
File type:           Wireshark/... - pcapng
File encapsulation:  Ethernet
File timestamp precision:  microseconds (6)
Packet size limit:   file hdr: (not set)
Number of packets:   4,073
File size:           4,357 kB
Data size:           4,218 kB                    <<< 抓包数据量
Capture duration:    97.158168 seconds           <<< 抓包持续时间
First packet time:   2023-05-28 20:42:11.392512
Last packet time:    2023-05-28 20:43:48.550680
Data byte rate:      43 kBps                     <<< 流量速率
Data bit rate:       347 kbps
Average packet size: 1035.79 bytes
Average packet rate: 41 packets/s
Strict time order:   True
Capture hardware:    11th Gen Intel(R) Core(TM) i7-11850H @ 2.50GHz (with SSE4.2) <<< 抓包设备硬件信息
Capture oper-sys:    64-bit Windows (22H2), build 22621
Capture application: Dumpcap (Wireshark) 4.0.2 (v4.0.2-0-g415456d13370)
Number of interfaces in file: 1
Interface #0 info:
                     Name = \Device\NPF_{38354A0C-5E92-415C-BFE4-AF056BF4A261}
                     Description = Ethernet 5                                <<< 抓包网卡
                     Encapsulation = Ethernet (1 - ether)
                     Capture length = 262144
                     Time precision = microseconds (6)
                     Time ticks per second = 1000000
                     Time resolution = 0x06
                     Operating system = 64-bit Windows (22H2), build 22621   <<< 抓包设备 OS
                     Number of stat entries = 1
                     Number of packets = 4073
```

## 分析报文
- 如果条件允许 & 有必要，在所有涉及到的设备/位置做抓包；针对不同抓包文件做对比。设备之间 clock 需要 NTP 同步
- 从 general 到 detail，可以先查看 <kbd>Statistics</kbd> 的一些信息，然后查看/对比具体报文。

### MAC address
- Destination & Source MAC，Wireshark 可以解析 well-known 的设备 MAC，比如 Destination: Cisco_f8:19:ff (00:22:bd:f8:19:ff)
- [网站查询](https://mac.bmcx.com/) MAC 归属

### TTL
- 数据包每经过一次三层网络设备，TTL -1
- 一般情况下，设备始发流量的 TTL 固定，Linu 64 or 255, Windows 255, Firewall 128
- 基于 packets 的 TTL，可以大致判断抓包位置，比如下面截图里面能看到 client --> server 方向 TTL 128，说明抓包位置在 client 或者靠近 client 一侧
- 场景：client 向 AWS 的虚拟机/EC2 上传文件，通过 EC2 public IP 直接上传可以成功，通过 EC2 DNS name 上传会失败，client 收到 TCP RST 导致业务断开，<kbd>如何确认始发 RST 的设备是 EC2 </kbd>，而不是中间的某个第三方 (Firewall，上网行为管理）或者 ISP/运营商 的设备
- 在 AWS 遇到的一个案例，过滤条件 `frame.number == 3701 || frame.number == 3717 || frame.number == 3718 || frame.number == 3739 || frame.number ==  4681 || frame.number == 4684 || frame.number == 4910 || frame.number == 9641 || frame.number == 9652 || frame.number == 12163 || frame.number == 12164 || frame.number == 12192`
  
![picture 4](./assest/img/ttl-and-rtt.png)  

<details>
<summary> <kbd>如何确认发起 RST 的设备是 server</kbd> </summary>

1. 对比 __TCP 三次握手__ 的 SYN, ACK，以及 RST 报文的 **TTL**      // 容易操作，易于理解

2. 对比 __非 TCP 三次握手__ 的 SYN, ACK，以及 RST 报文的 **RTT**   // 有时候差别不太明显

ACK & RST 的 TTL 应该相同，表示始发设备相同，并不是中间第三方设备伪造。如果 TTL 不同，比如截图里面的 TTL 124，推测发送 RST 的设备距离 client 有 128 - 124 = 4 跳，可以通过 `traceroute/tracert` 来查看中间设备的 IP。真正的 EC2 server 距离 client 有 255 - 235 = 20 跳。另一个 tips，可以让客户_绕过公司内网，比如使用手机热点来尝试_。

ACK & RST 的 RTT 应该接近，因为经过相同网络路径转发，通常 RTT 变化不大；不要对比 TCP 三次握手的 ACK，建立 TCP 连接时候资源消耗比较大，RTT 偏大
</details>

### Identification
- 十六进制，比如 Identification: 0x8f00 (36608)；十进制范围在 0 - 65535
- 同一个 TCP stream 如果持续时间比较长，或者交互很快，Identification 会循环使用
- 主要作用：identifies fragmented packet；以及在多个设备同时抓包，如何找到同一个报文 (`ip.id`相同，时间戳差异毫秒级）
- 一个 [案例](https://scripts.cisco.com/app/quicker_csone/?sr=695420786#a096R000033NkjyQAC)，client 10.191.84.x 向 MySQL 服务器 10.191.64.x 发起请求，通常这个请求应该在 1-2 分钟内完成；把一部分 client 从老机房迁移到 ACI 机房以后，这个请求需要 5-10 分钟才能完成。
![picture 8](./assest/img/ip-id.png)  

<details>
<summary> <kbd> 截图里面的一些信息 </kbd> </summary>

从 DB 侧和 client 侧 leaf SPAN 去看，数据包转发延迟是 0.000,007 秒内；

Client 端 有一些报文没有收到，比如 ip.id 65277，以及重传的 ip.id 65278 等。需要查看是 client 侧 leaf 丢包，还是 client 收到了但是没处理 (client tcpdump 抓包位置可能看不到类似报文）

Client 端抓包的 ip.id 65276, length 6749，和前面 leaf SPAN 的 length 1514 不同，是 fragmented packets 重组的结果

</details>

### DNS
- 一个 [案例](https://scripts.cisco.com/app/quicker_csone/?sr=695433466#a096R000033GrKiQAK)，VMware 容器云，Pods 之间通过 ACI 打通底层网络，client/MySQL 到 coreDNS 之间偶尔出现 DNS 解析失败
- 通过在 VMware 的 VMNIC, Pod 以及 ACI leaf 抓包，需要分析 DNS query & response，在哪一个环节出问题。
  - DNS query 是否都到达了 coreDNS
  - 如果 query 都到达了 coreDNS，那么是否都得到了 response
  - 如果 coreDNS 都发出了 response，那么 response 是否正确，或者在哪里丢包了
- 和 VMware 一起分析，发现是某些 DNS query 没有收到 response。于是给 ChatGPT 提了一个问题，尝试找到所有出问题的报文：display filter for Wireshark to find DNS query without response，ChatGPT 给了误导性回复 `dns.flags.response == 0 && dns.flags.rcode == 0`
- 在 leaf 的 ERSPAN 里面使用 `dns.flags.response == 0 && dns.flags.rcode == 0` 过滤，结果为空，不符合预期。自己动手 Google，发现 display filter 应该是 `dns && (dns.flags.response == 0) && ! dns.response_in and not icmp`
- 不要轻信 ChatGPT，仅供参考。

<details>
<summary> 按照事后诸葛亮的角度来分析正确的 Wireshark display filter </summary>

`dns`，限定数据包范围是 DNS

`dns.flags.response == 0`，限定 DNS Message 为 Query
  
<img src="./assest/img/dns-query.png" width="500" />

`! dns.response.in`，限定 DNS Query 没有 response

<img src="./assest/img/dns-response.png" width="500">

错误答案的问题点
  
<img src="./assest/img/dns-response-dns-rcode.png" width="500">

</details>

### TCP MSS
- MSS(MTU - 20/IP - 20/TCP) 在哪个阶段协商的 ?
  - TCP 三次握手的 SYN 阶段
  - 中间的网络设备有能力去修改 MSS，比如 `ip tcp adjust-mss`; [中间设备修改 MSS 和修改 MTU，有什么不同](https://community.cisco.com/t5/routing/mtu-vs-tcp-adjust-mss/td-p/1020075) ?
    - 修改 MTU，影响的是 Layer3/IP 层数据包的长度，以及在 IP 层是否产生分片；如果你设置的 MTU 比较大，而互联网某个位置的 MTU 小然后需要分片，但是 packet DF = 0 不允许分片，就会导致丢包
    - 修改 MSS，影响的是 Layer4/TCP 层数据包的长度，更安全可靠
  - 可以参考 TTL 的 Wireshark 抓包
![picture 13](./assest/img/tcp-mss.png)  

- MSS 有什么作用 ?
  - TCP payload 大于 MTU，如何分片，每一个分片的大小。IP 层不负责上层协议的分片
  - TCP 滑动窗口，如果初始的 window size 太小，那么 IP + TCP = 40 bytes 的开销就占比很大。sender/receiver 可以根据 MSS 或者 1/2 window 来选择初始发送的数据量
  - TCP 拥塞处理，慢启动，初始的 cwnd 通常是 MSS or 10 x MSS

### TCP Flags
- 一个 [案例](https://scripts.cisco.com/app/quicker_csone/?sr=695420786#a096R000033ADDwQAO)
- TCP Flags，主要关注 **SYN, ACK, PSH, RST, URG, ECN, CWR**
- TCP 三次握手
- TCP 四次挥手
- 扩展：为什么握手是三次，挥手/断开需要四次 ?
```bash
Flags: 0x0c2 (SYN, ECE, CWR)
    1.   .... .... = Reserved: Not set
    ...0 .... .... = Accurate ECN: Not set
    .... 1... .... = Congestion Window Reduced: Set  // TCP congestion window was reduced due to congestion in the network
    .... .1.. .... = ECN-Echo: Set                   // Explicit Congestion Notification (ECN), detected congestion
    .... ..0. .... = Urgent: Not set
    .... ...0 .... = Acknowledgment: Not set
    .... .... 0... = Push: Not set
    .... .... .0.. = Reset: Not set
    .... .... ..1. = Syn: Set                        // Connection establish request (SYN): server port 10086]
    .... .... ...0 = Fin: Not set
    [TCP Flags: ····CE····S·]
```

### TCP Stream id - Follow TCP Stream
- TCP stream 从三次握手到四次挥手，是一个正常的过程
- 中间可能有重传，reset

### TCP Spurious Retransmission
- 一个 [案例](https://scripts.cisco.com/app/quicker_csone/?sr=695420786#a096R00003366oRQAQ)
- 什么情况下会重传/retransmission ?
- TCP 重传有可能是一个正常现象，要结合当时的具体情况去分析。但是如果存在大量重传报文，就有必要进一步分析了

| 场景           | 可能的原因                                                                                     |
| -------------- | ---------------------------------------------------------------------------------------------- |
| 发送方主动重传 | RTO(Retransmission TimeOut)；没有收到 ACK(client 未发送 ACK，或者 drop)，ACK 收到的慢了        |
| 接收方要求重传 | TCP 数据块丢失/packets drop，SACK 要求重传；FACK                                               |
| 网络           | 先发后至的 packets/out-of-order，比如 data 64-100 被收到但是 1-63 还未收到；congestion/latency |
| 缓存           | 上层 app 来不及处理，缓存被清空的；还有一种可能是 client/app 单线程，处理慢                      |

### TCP Window Full & ZeroWindow
- 一个 [案例](https://scripts.cisco.com/app/quicker_csone/?sr=695420786#a096R000033A0taQAC)
- **TCP 要解决可靠传输 & packets 乱序 & 故障可靠通知**，所以 TCP 要了解网络的带宽，client/server 处理 packets 的速度等，避免拥塞/丢包/重传。
- sliding window/滑动窗口是 TCP 流控的一个方式
- 如果 client/server 处理 packets 速度慢，buffer 容易打满，可以通过 Window Full & ZeroWindow 告知对方，暂缓发送
- ZWP(Zero Window Probe)，零窗口指针，报文不携带实际 data，目的是获取对方实时的 window size；不同 OS 对于 ZWP 的实现不同，可能会保持 TCP stream 等待，也可能 RST

### SSL/TLS certificate handshake
- SSL/TLS 协商过程
- SSL/TLS 扩展，比如 SNI, ALPN(upgrade to HTTP/2)
- 扩展：怎么确定 SSL/TLS certification 合法有效  ?

### SSL/TLS SNI
- SNI (Server Name Indication)，属于 SSL/TLS 的一个扩展，用途是指定被访问的 server 的 domain name
- 有什么用处 ?
  - 为了节省 public IP，常见场景是同一个 public IP 可能对应着不同的域名，比如 zhihu.com, bilili.com；当 server 收到 client request，需要根据 SNI 来判断被访问的是哪一个域名。
- Server 提供多个域名服务，其中一个可选方式是 x509 的 SAN (Subject Alternative Name)，对于 SSL/TLS 证书来说，可以支持 abc.com 以及 tv.abc.com
- [区分 SNI, SAN](https://serverfault.com/questions/807959/what-is-the-difference-between-san-and-sni-ssl-certificates)

### SSL/TLS decrypt
- TAC 不常见，比如需要查看 Layer7/HTTP 层的信息，但是 client 和 server 通过 HTTPS 通信，报文被加密了。
- 有没有可能解密 HTTPS ?
  - 对于 Windows 电脑来说，有成熟可复制的 [方法](https://resources.infosecinstitute.com/topic/decrypting-ssl-tls-traffic-with-wireshark/)。这个方法针对 Firefox/Chrome 浏览器，并不针对 curl/postman/apache 等工具。
- 做了一个 demo，流量很大，单独过滤几个代表性的 packets `frame.number == 1 || frame.number == 2 || frame.number == 3 || frame.number == 4 || frame.number == 5 || frame.number == 6 || frame.number == 11 || frame.number == 12 || frame.number == 13 || frame.number == 14 || frame.number == 17 || frame.number == 22 ||  frame.number == 1082 || frame.number == 1353 || frame.number == 1422 || frame.number == 1439  || frame.number == 4051 || frame.number == 4071 || frame.number == 4072`

### HTTP/HTTPS
- Wireshark - Follow HTTP Stream，实际效果是 follow TCP stream，会展示一部分 HTTP 概览
- 浏览器 HAR(HTTP Archive)，当 client 利用浏览器发起 HTTP 请求，可以收集 HAR 用于分析，并且可以保存下来发送给 TAC，比如
  - HTTP request 是否被 redirect
  - HTTP response 是什么
  - HTTP header 都有什么，是否都是合法合规的 header
  - 是否存在 CORS 问题
  - 每个阶段 (DNS 解析，TCP 建立连接，SSL/TLS 协商，HTTP 请求/响应） 消耗的时间，用来判断延迟主要在哪一部分
  - 举个栗子，以 chrome 访问 [gitlab](https://gitlab-sjc.cisco.com) 为例，大约 0.6 秒打开网页，其中 99%的延迟是 Waiting for server response
![picture 3](./assest/img/chrome-har.png)  

- 扩展：使用 `curl` 查看延迟
```bash
luke@ubuntu20:~$ curl -kso /dev/null https://cloud.ik3cloud.com  -w "==============\n\n time_dnslookup: %{time_namelookup}\n time_connect: %{time_connect}\n time_appconnect: %{time_appconnect}\n time_pretransfer: %{time_pretransfer}\n time_starttransder: %{time_starttransfer}\n total time: %{time_total}\n size: %{size_download}\n HTTPCode=%{http_code}\n\n"
==============
# 每个阶段的含义，可以直接从 man curl 里面搜索

 time_dnslookup: 0.105737
 time_connect: 0.236909     <<< The  time, in seconds, it took from the start until the TCP connect to the remote host was completed. TCP 三次握手建立的时间
 time_appconnect: 2.609156  <<< The time, in seconds, it took from the start until the SSL/SSH/etc connect/handshake to  the  remote host was completed. TCP 之上的 SSL/TLS/SSH 等建立连接的时间。这个栗子里面，大部分的延迟是因为 SSL/TLS 协商
 time_pretransfer: 2.609217
 time_starttransder: 2.969912
 total time: 2.970005
 size: 137
 HTTPCode=200
```
- [Chrome 的 Inspect -Network 如何使用](https://developer.chrome.com/docs/devtools/network/reference/?utm_source=devtools#timing-explanation)
