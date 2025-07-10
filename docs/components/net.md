# net

net组件为RT-Thread提供了网络支持。

## SAL

子组件SAL提供了一个套接字的抽象层，同过它 RT-Thread 系统能够适配下层不同的网络协议栈，并提供给上层统一的网络编程接口，方便不同协议栈的接入，可以适配更多的网络协议栈类型，避免系统对单一网络协议栈的依赖，该组件完成对不同网络协议栈或网络实现接口的抽象并对上层提供一组标准的 BSD Socket API，套接字抽象层为上层应用层提供接口有`accept`、`connect`、`send`、`recv`等。这样用户需要关心和使用网络应用层提供的网络接口，而无需关心底层具体网络协议栈类型和实现，方便开发者完成协议栈的适配和网络相关的开发。SAL 组件提供了抽象、统一多种网络协议栈接口。

```c
int socket(int domain, int type, int protocol);
int connect(int s, const struct sockaddr *name, socklen_t namelen);
int sal_connect(int socket, const struct sockaddr *name, socklen_t namelen);
int bind(int s, const struct sockaddr *name, socklen_t namelen);
int listen(int s, int backlog);
int send(int s, const void *dataptr, size_t size, int flags);
int recv(int s, void *mem, size_t len, int flags);
int sendto(int s, const void *dataptr, size_t size, int flags, const struct sockaddr *to, socklen_t tolen);
int recvfrom(int s, void *mem, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen);
int closesocket(int s);
```

SAL提供了对TCP和UDP的接口支持。`send`对应TCP协议的发送，`sendto`则是UDP协议的发送。

## LWIP

子组件LWIP则提供了一个轻量级的 TCP/IP 协议栈，实现了TCP/IP 协议栈的一部分内容，可以作为SAL组件`socket`的协议参数。lwip 所实现的，是 TCP/IP 协议栈的一部分内容。

LWIP组件实现了一下协议

### ARP协议

```c
/* 查找 ARP 映射表中 ipaddr 条目，并返回相对位置 */
static s8_t etharp_find_entry(const ip4_addr_t *ipaddr, u8_t flags, struct netif* netif);
/* 尝试发送 IP 数据包， 单播，多播或者广播数据 */
err_t etharp_output(struct netif *netif, struct pbuf *q, const ip4_addr_t *ipaddr);
/* 查询 ARP 表，不存在则调用 etharp_request 获取，存在则发送数据 */
err_t etharp_query(struct netif *netif, const ip4_addr_t *ipaddr, struct pbuf *q);
/* 尝试发送 ARP 请求数据包 */
err_t etharp_request(struct netif *netif, const ip4_addr_t *ipaddr);
/* 解析 ARP 数据包 */
void etharp_input(struct pbuf *p, struct netif *netif);
```

LWIP实现了 ARP 数据包的发送，解析，查找功能；一个网络中，设备不可能是一直都不会变的，IP 与 MAC 的对应关系，是会随着时间改变而改变的。因此，LWIP也实现了ARP表是需要定时更新功能。

### TCP协议

LWIP实现了TCP三次握手、四次挥手以及超时重传等机制。TCP在发起一次传输时会开启一个定时器，如果在定时器超时时未收到应答就会进行重传。

TCP控制结构如下：

```c
/** the TCP protocol control block */
struct tcp_pcb {
/** common PCB members */
  /* ip addresses in network byte order *
  ip_addr_t local_ip; 
  ip_addr_t remote_ip; 
  /* Socket options */  
  u8_t so_options;      
  /* Type Of Service */ 
  u8_t tos;              
  /* Time To Live */     
  u8_t ttl               
  /* link layer address resolution hint */ \
  IP_PCB_ADDRHINT

/** protocol specific PCB members */
  type *next; /* for the linked list */ 
  void *callback_arg; 
  enum tcp_state state; /* TCP state */     //记录TCP连接所处的状态
  u8_t prio; 
  /* ports are in host byte order */ 
  u16_t local_port

  /* ports are in host byte order */
  u16_t remote_port;

  tcpflags_t flags;

  /* the rest of the fields are in host byte order
     as we have to do some math with them */

  /* Timers */
  u8_t polltmr, pollinterval;
  u8_t last_timer;
  u32_t tmr;

  /* receiver variables */
  u32_t rcv_nxt;   /* next seqno expected */
  tcpwnd_size_t rcv_wnd;   /* receiver window available */
  tcpwnd_size_t rcv_ann_wnd; /* receiver window to announce */
  u32_t rcv_ann_right_edge; /* announced right edge of window */

  /* Retransmission timer. */
  s16_t rtime;

  u16_t mss;   /* maximum segment size */

  /* RTT (round trip time) estimation variables */
  u32_t rttest; /* RTT estimate in 500ms ticks */
  u32_t rtseq;  /* sequence number being timed */
  s16_t sa, sv; /* @todo document this */

  s16_t rto;    /* retransmission time-out */
  u8_t nrtx;    /* number of retransmissions */

  /* fast retransmit/recovery */
  u8_t dupacks;
  u32_t lastack; /* Highest acknowledged seqno. */

  /* congestion avoidance/control variables */
  tcpwnd_size_t cwnd;
  tcpwnd_size_t ssthresh;

  /* sender variables */
  u32_t snd_nxt;   /* next new seqno to be sent */
  u32_t snd_wl1, snd_wl2; /* Sequence and acknowledgement numbers of last
                             window update. */
  u32_t snd_lbb;       /* Sequence number of next byte to be buffered. */
  tcpwnd_size_t snd_wnd;   /* sender window */
  tcpwnd_size_t snd_wnd_max; /* the maximum sender window announced by the remote host */

  tcpwnd_size_t snd_buf;   /* Available buffer space for sending (in bytes). */
#define TCP_SNDQUEUELEN_OVERFLOW (0xffffU-3)
  u16_t snd_queuelen; /* Number of pbufs currently in the send buffer. */

#if TCP_OVERSIZE
  /* Extra bytes available at the end of the last pbuf in unsent. */
  u16_t unsent_oversize;
#endif /* TCP_OVERSIZE */

  /* These are ordered by sequence number: */
  struct tcp_seg *unsent;   /* Unsent (queued) segments. */
  struct tcp_seg *unacked;  /* Sent but unacknowledged segments. */
#if TCP_QUEUE_OOSEQ
  struct tcp_seg *ooseq;    /* Received out of sequence segments. */
#endif /* TCP_QUEUE_OOSEQ */

  struct pbuf *refused_data; /* Data previously received but not yet taken by upper layer */

#if LWIP_CALLBACK_API || TCP_LISTEN_BACKLOG
  struct tcp_pcb_listen* listener;
#endif /* LWIP_CALLBACK_API || TCP_LISTEN_BACKLOG */

#if LWIP_CALLBACK_API
  /* Function to be called when more send buffer space is available. */
  tcp_sent_fn sent;
  /* Function to be called when (in-sequence) data has arrived. */
  tcp_recv_fn recv;
  /* Function to be called when a connection has been set up. */
  tcp_connected_fn connected;
  /* Function which is called periodically. */
  tcp_poll_fn poll;
  /* Function to be called whenever a fatal error occurs. */
  tcp_err_fn errf;
#endif /* LWIP_CALLBACK_API */

#if LWIP_TCP_TIMESTAMPS
  u32_t ts_lastacksent;
  u32_t ts_recent;
#endif /* LWIP_TCP_TIMESTAMPS */

  /* idle time before KEEPALIVE is sent */
  u32_t keep_idle;
#if LWIP_TCP_KEEPALIVE
  u32_t keep_intvl;
  u32_t keep_cnt;
#endif /* LWIP_TCP_KEEPALIVE */

  /* Persist timer counter */
  u8_t persist_cnt;
  /* Persist timer back-off */
  u8_t persist_backoff;

  /* KEEPALIVE counter */
  u8_t keep_cnt_sent;

#if LWIP_WND_SCALE
  u8_t snd_scale;
  u8_t rcv_scale;
#endif
};
```

### UDP协议

UDP协议的控制块：

```c
struct udp_pcb {
  IP_PCB; //通用IP控制块

  struct udp_pcb *next; //下一节点的指针，用于构成控制块链表

  u8_t flags; //控制块状态

  u16_t local_port, remote_port;  //本地端口号、远程端口号

  udp_recv_fn recv; //处理网络接收数据的回调

  void *recv_arg;   //用户自定义参数，接收回调入参
};
```

LWIP实现了以下的UDP接口：

```c
struct udp_pcb* udp_new(void);
void udp_remove(struct udp_pcb *pcb);
err_t udp_bind(struct udp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port);
err_t udp_connect(struct udp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port);
void udp_disconnect(struct udp_pcb *pcb);
err_t udp_send(struct udp_pcb *pcb, struct pbuf *p);
err_t udp_sendto(struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *dst_ip, u16_t dst_port);

typedef void (*udp_recv_fn)(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port);
void udp_recv(struct udp_pcb *pcb, udp_recv_fn recv,void *recv_arg);
```

实现了UDP的创建、删除、绑定、连接、发送和接受数据等功能。

除此之外，LWIP还实现了IP、ICMP、DHCP等协议栈。

## AT

AT 组件是对 AT Server 和 AT Client 的实现，组件完成 AT 命令的发送、命令格式及参数判断、命令的响应、响应数据的接收、响应数据的解析、URC 数据处理等整个 AT 命令数据交互流程。通过 AT 组件，设备可以作为 AT Client 使用串口连接其他设备发送并接收解析数据。
