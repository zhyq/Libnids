/*
  Copyright (c) 1999 Rafal Wojtczuk <nergal@7bulls.com>. All rights reserved.
  See the file COPYING for license details.
*/

#ifndef _NIDS_NIDS_H
# define _NIDS_NIDS_H

# include <sys/types.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
# include <netinet/ip.h>
# include <netinet/tcp.h>
# include <pcap.h>


//add: 2014 1 25   1
#include<pthread.h>
#include<unistd.h>
#include<string.h>
#include<sys/sem.h>
#include<semaphore.h>

sem_t sem_full;
sem_t  sem_empty;
pthread_t th_catch,th_pro1,th_pro2,th_pro3;
int thread_error;
void * thCatch(void *arg);
void *thPro1(void *arg);
void *thPro2(void *arg);
void *thPro3(void *arg);
void *tret;
//end add


# ifdef __cplusplus
extern "C" {
# endif

# define NIDS_MAJOR 1
# define NIDS_MINOR 25

# define CPU_SET(cpu, cpusetp)   __CPU_SET_S (cpu, sizeof (cpu_set_t), cpusetp)  
# define CPU_CLR(cpu, cpusetp)   __CPU_CLR_S (cpu, sizeof (cpu_set_t), cpusetp)  
# define CPU_ISSET(cpu, cpusetp) __CPU_ISSET_S (cpu, sizeof (cpu_set_t),cpusetp)  
# define CPU_ZERO(cpusetp)   __CPU_ZERO_S (sizeof (cpu_set_t), cpusetp)      
   #define __USE_GNU
#include <sched.h> 



enum
{
  NIDS_WARN_IP = 1,
  NIDS_WARN_TCP,
  NIDS_WARN_UDP,
  NIDS_WARN_SCAN
};

enum
{
  NIDS_WARN_UNDEFINED = 0,
  NIDS_WARN_IP_OVERSIZED,
  NIDS_WARN_IP_INVLIST,
  NIDS_WARN_IP_OVERLAP,
  NIDS_WARN_IP_HDR,
  NIDS_WARN_IP_SRR,
  NIDS_WARN_TCP_TOOMUCH,
  NIDS_WARN_TCP_HDR,
  NIDS_WARN_TCP_BIGQUEUE,
  NIDS_WARN_TCP_BADFLAGS
};

# define NIDS_JUST_EST 1
# define NIDS_DATA 2
# define NIDS_CLOSE 3
# define NIDS_RESET 4
# define NIDS_TIMED_OUT 5
# define NIDS_EXITING   6	/* nids is exiting; last chance to get data */

# define NIDS_DO_CHKSUM  0
# define NIDS_DONT_CHKSUM 1

struct tuple4
{
  u_short source;
  u_short dest;
  u_int saddr;
  u_int daddr;
};

struct half_stream
{
  // 记录该半链接的状态，可以为FIN_SENT等
  char state;
  // 由用户注册的函数负责修改，告诉libnids是否需要监听正常tcp报文
  char collect;
  // 由用户注册的函数负责修改，告诉libnids是否需要监听正常tcp报文
  char collect_urg;

  // 指向一个缓存，该缓存保存了已被确认的tcp报文字节内容
  char *data;
  // count - offset = 当前data中的内容长度
  int offset;
  int count;
  // 最新收到的报文的大小
  int count_new;
  // 记录data所指向的内存的实际大小
  int bufsize;
  // 记录list链表占用的总大小
  int rmem_alloc;

  // 
  int urg_count;
  u_int acked;
  // libnids监听到一个tcp报文，这个报文的seq字段值就会立即填入
  // 对应半连接的seq域中
  u_int seq;
  // libnids监听到一个tcp报文，这个报文的ack字段值就会立即填入
  // 对应半连接的ack_seq域中
  u_int ack_seq;
  // 本半链接第一个字节序号
  u_int first_data_seq;
  // 指向本半链接收到的报文中，紧急数据的起始位置
  u_char urgdata;
  // 一个标志，在notify函数中会使用到，记录是否收到了一个新的紧急报文
  u_char count_new_urg;
  // 一个标志，记录本半链接是否看到了紧急数据
  // 如果为0表示没有看到，如果为1表示有紧急数据没有处理
  u_char urg_seen;
  // 指向刚刚收到的报文的紧急数据的起始地址
  u_int urg_ptr;
  u_short window;
  // 记录是否启用时间戳
  u_char ts_on;
  // 记录是否使用窗口大小
  u_char wscale_on;
  u_int curr_ts;
  u_int wscale;

  // 指向一个链表，该链表中的每一个节点都是一个tcp报文
  // 这些tcp报文是接收者已经接收到但是没有确认的报文
  struct skbuff *list;
  // 用来在尾部插入新的报文用的
  struct skbuff *listtail;
};


struct tcp_stream
{
  // 四元组地址
  struct tuple4 addr;
  // tcp 的一个状态
  char nids_state;
  // 与这个tcp相关的所有监听函数
  struct lurker_node *listeners;
  // 半连接
  struct half_stream client;
  struct half_stream server;
  // 链表域
  struct tcp_stream *next_node;
  struct tcp_stream *prev_node;
  // 记录本tcp在tcp表中的hash值
  int hash_index;
  // 
  struct tcp_stream *next_time;
  struct tcp_stream *prev_time;
  // 记录本次回调用户的注册函数会读取多少字节的数据
  int read;
  // 下一个可用的空的tcp节点
  struct tcp_stream *next_free;
  void *user;
  // 时间戳
  long ts;
};

struct nids_prm
{
  int n_tcp_streams;
  int n_hosts;
  char *device;
  char *filename;
  int sk_buff_size;
  int dev_addon;
  void (*syslog) ();
  int syslog_level;
  int scan_num_hosts;
  int scan_delay;
  int scan_num_ports;
  void (*no_mem) (char *);
  int (*ip_filter) ();
  char *pcap_filter;
  int promisc;
  int one_loop_less;
  int pcap_timeout;
  int multiproc;
  int queue_limit;
  int tcp_workarounds;
  pcap_t *pcap_desc;
  int tcp_flow_timeout;
};

struct tcp_timeout
{
  // 记录当前的timeout链表属于哪一个tcp
  struct tcp_stream *a_tcp;
  // 
  struct timeval timeout;
  // 组成链表，每一个节点对应一个tcp，多个节点对应多个tcp
  struct tcp_timeout *next;
  struct tcp_timeout *prev;
};

// modified - 2014-01-25
struct fifo_node
{
	struct ip *data;
	int skblen;
};

struct nids_fifo
{
	struct fifo_node * head;
	struct fifo_node * tail;
	struct fifo_node * start;
	struct fifo_node * end;
	int fifo_len;
};
// modified end


int nids_init (void);
void nids_register_ip_frag (void (*));
void nids_unregister_ip_frag (void (*));
void nids_register_ip (void (*));
void nids_unregister_ip (void (*));
void nids_register_tcp (void (*));
void nids_unregister_tcp (void (*x));
void nids_register_udp (void (*));
void nids_unregister_udp (void (*));
void nids_killtcp (struct tcp_stream *);
void nids_discard (struct tcp_stream *, int);
int nids_run (void);
void nids_exit(void);
int nids_getfd (void);
int nids_dispatch (int);
int nids_next (void);
void nids_pcap_handler(u_char *, struct pcap_pkthdr *, u_char *);
struct tcp_stream *nids_find_tcp_stream(struct tuple4 *);
void nids_free_tcp_stream(struct tcp_stream *);

extern struct nids_prm nids_params;
extern char *nids_warnings[];
extern char nids_errbuf[];
extern struct pcap_pkthdr *nids_last_pcap_header;
extern u_char *nids_last_pcap_data;
extern u_int nids_linkoffset;
extern struct tcp_timeout *nids_tcp_timeouts;

struct nids_chksum_ctl {
	u_int netaddr;
	u_int mask;
	u_int action;
	u_int reserved;
};
extern void nids_register_chksum_ctl(struct nids_chksum_ctl *, int);

# ifdef __cplusplus
}
# endif

#endif /* _NIDS_NIDS_H */
