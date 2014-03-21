/*
  Copyright (c) 1999 Rafal Wojtczuk <nergal@7bulls.com>. All rights reserved.
  See the file COPYING for license details.
 */

#include <config.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

#include "checksum.h"
#include "scan.h"
#include "tcp.h"
#include "util.h"
#include "nids.h"
#include "hash.h"

// 定义用来处理tcp的核的个数
#define TCP_CORE_NUM 3

#if ! HAVE_TCP_STATES
enum
{
    TCP_ESTABLISHED = 1,
    TCP_SYN_SENT,
    TCP_SYN_RECV,
    TCP_FIN_WAIT1,
    TCP_FIN_WAIT2,
    TCP_TIME_WAIT,
    TCP_CLOSE,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK,
    TCP_LISTEN,
    TCP_CLOSING			/* now a valid state */
};

#endif

#define FIN_SENT 120
#define FIN_CONFIRMED 121
#define COLLECT_cc 1
#define COLLECT_sc 2
#define COLLECT_ccu 4
#define COLLECT_scu 8

#define EXP_SEQ (snd->first_data_seq + rcv->count + rcv->urg_count)

// 在libnids中定义的回调函数链表
extern struct proc_node *tcp_procs;

// 这是一个hash表，用来管理所有tcp链接
static struct tcp_stream **tcp_stream_table;
// 记录hash表大小
static int tcp_stream_table_size;
// 这个链表管理了所有tcp_stream节点,无论是否free
static struct tcp_stream *streams_pool[TCP_CORE_NUM];
// 记录当前除了free_streams外还有几个tcp节点，记录活跃的tcp数量
static int tcp_num[TCP_CORE_NUM];
// 记录最多允许多少个tcp,它的值应该是 tcp_stream_table_size * 3 /4
static int max_stream;
// tcp_latest总是指向最后建立的tcp节点，tcp_oldest总是指向最先建立的tcp节点
// 注意，tcp节点还有一个time链表
// 这个数组的初始化需要在tcp_int函数中执行
static struct tcp_stream *tcp_latest[TCP_CORE_NUM], *tcp_oldest[TCP_CORE_NUM];
// 管理空闲的tcp节点
static struct tcp_stream *free_streams[TCP_CORE_NUM];
// 保存原始的ip头
static struct ip *ugly_iphdr[TCP_CORE_NUM];
// 保存一个超时队列，如果启用此功能，每个tcp在四次挥手后不会立即释放，
// 而是加入该队列直到超时，该队列是按照超时计时器升序排列的。
struct tcp_timeout *nids_tcp_timeouts = 0;


/**
	入参:
		h : 需要净化的半连接。

	功能:
		将所给的半连接中的list全部清除。

	注意:
		这个函数与后面的prune_queue函数非常相似。
		那个函数有两个参数，那个函数是在list满了的情况下将list清空。
		而且会调用警报函数，所以需要增加一个this_tcphdr作为参数。

	- Comment by shashibici 2014/03/07
**/
static void purge_queue(struct half_stream * h)
{
	struct skbuff *tmp, *p = h->list;

	// 清空所有队列
	while (p)
	{
		free(p->data);
		tmp = p->next;
		free(p);
		p = tmp;
	}

	// 设置为空
	h->list = h->listtail = 0;
	// list占用的真实大小也设为0
	h->rmem_alloc = 0;
}


static void
add_tcp_closing_timeout(struct tcp_stream * a_tcp)
{
	struct tcp_timeout *to;
	struct tcp_timeout *newto;

	if (!nids_params.tcp_workarounds)
		return;
	newto = malloc(sizeof (struct tcp_timeout));
	if (!newto)
		nids_params.no_mem("add_tcp_closing_timeout");
	newto->a_tcp = a_tcp;
	newto->timeout.tv_sec = nids_last_pcap_header->ts.tv_sec + 10;
	newto->prev = 0;

	// 寻找并释放
	for (newto->next = to = nids_tcp_timeouts; to; newto->next = to = to->next)
	{
		if (to->a_tcp == a_tcp)
		{
			free(newto);
			return;
		}
		if (to->timeout.tv_sec > newto->timeout.tv_sec)
			break;
		newto->prev = to;
	}
	if (!newto->prev)
		nids_tcp_timeouts = newto;
	else
		newto->prev->next = newto;
	if (newto->next)
		newto->next->prev = newto;
}


static void
del_tcp_closing_timeout(struct tcp_stream * a_tcp)
{
	struct tcp_timeout *to;

	if (!nids_params.tcp_workarounds)
		return;
	// 从[nids_tcp_timeouts]中寻找包含[a_tcp]的节点
	for (to = nids_tcp_timeouts; to; to = to->next)
	{
		if (to->a_tcp == a_tcp)
			break;
	}
	if (!to)
		return;
	if (!to->prev)
		nids_tcp_timeouts = to->next;
	else
		to->prev->next = to->next;
	if (to->next)
		to->next->prev = to->prev;
	free(to);
}


/**
	参数:
		a_tcp:  需要释放的tcp节点

	说明:
		本函数分为若6个骤步骤 -- 清除list、从table中摘下、清除data、从time中摘下、
		删除所有listener、收尾工作
		1) 执行函数purge_queue来清除所有等待确认的tcp报文(list链表中)
		2) 从[tcp_stream_table]将tcp节点摘下来，使之不在活跃
		3) 释放data空间(存放已经确认了的按序的tcp报文)
		4) 将节点从time链表上摘下来
		5) 删除该tcp的所有listener
		6) 将这个tcp节点挂载到[free_streams]链表头，表示它现在是一个空闲的节点了。

	- Comment by shashibici 2014/03/21
	
**/
void
nids_free_tcp_stream(struct tcp_stream * a_tcp)
{
	int hash_index = a_tcp->hash_index;
	int icore = a_tcp->icore;
	// 注意: 后面的代码显示，lurker_node其实就代表了a_tcp的一个listener.
	// (本函数倒数第二部分)
	struct lurker_node *i, *j;

	// 这里默认不会执行，因为没有使用workaround特性
	del_tcp_closing_timeout(a_tcp);
	// 首先清空该tcp两端的list队列，也就是把那些等待确认的报文清除
	purge_queue(&a_tcp->server);
	purge_queue(&a_tcp->client);

	// 将当前node删除，把下一个node的prev指针指向当前node的前一个node
	if (a_tcp->next_node)
	{
		a_tcp->next_node->prev_node = a_tcp->prev_node;
	}
	// 将当前node删除，把上一个node的next指向当前node的下一个node
	if (a_tcp->prev_node)
	{
		a_tcp->prev_node->next_node = a_tcp->next_node;
	}
	else
	{
		// 如果atcp->prev_node是空的，说明已经是链表头，这是一个hash链表。
		tcp_stream_table[hash_index] = a_tcp->next_node;
	}
	// 释放data域的数据，该数据包含了已经确认的tcp报文
	if (a_tcp->client.data)
	{
		free(a_tcp->client.data);
	}
	if (a_tcp->server.data)
	{
		free(a_tcp->server.data);
	}

	// 将a_tcp从time链表中摘下来
	if (a_tcp->next_time)
	{
		a_tcp->next_time->prev_time = a_tcp->prev_time;
	}
	if (a_tcp->prev_time)
	{
		a_tcp->prev_time->next_time = a_tcp->next_time;
	}

	// 修改tcp_latest tcp_oldes指针
	if (a_tcp == tcp_oldest[icore])
	{
		tcp_oldest[icore] = a_tcp->prev_time;
	}
	if (a_tcp == tcp_latest[icore])
	{
		tcp_latest[icore] = a_tcp->next_time;
	}
	// 释放所有a_tcp的listeners
	i = a_tcp->listeners;
	while (i)
	{
		j = i->next;
		free(i);
		i = j;
	}

	// 将a_tcp挂到free_streams的[表头]
	a_tcp->next_free = free_streams[icore];
	free_streams[icore] = a_tcp;

	// 当前tcp数量-1
	tcp_num[icore]--;
}


/**
	参数:
		now :  刚刚捕获的包的时间戳

	说明:
		- 调用方法: tcp_check_timeouts(&hdr->ts);
		- 调用时机: 在pcap抓到一个包了之后会立即调用此函数。

		- 可以这样认为，libnids的[最小处理时间单位]是[一个pcap包时间间隔].
		  也就是说，只有当libnids从pcap处接收到一个包之后才会检查libnids
		  目前所维护的各个tcp的计时器(这些计时器由nids_tcp_tmieouts指出).
		  这个函数的作用就是替libnids执行这样一个检查操作，而libnids只需要在
		  合适的时机调用这个函数就行了。
		
		- 这个函数的执行思路是:
			-- 首先将当前包的时间[now.tv_sec]依次与[nids_tcp_timeouts]中\
			   各个节点的[timeout.tv_sec]相比较.
			-- 由于[nids_tcp_timeouts]中的节点是按照[timeout.tv_sec]关键字
			   升序排列，当遇到一个[timeout.tv_sec] > [now.tv_sec]时就可以
			   确定之后的所有节点的[timeout.tv_sec]都不小于[now.tv_sec]，于是
			   便可以返回了。
			-- 如果遇到[timeout.tv_sec] <= [now.tv_sec]的节点，说明这个节点
			   对应的tcp已经超时了(now.tv_sec代表的就是当前时间--当前包的时间)，
			   此时需要将超时的tcp释放掉(释放之前遍历一次listeners).

		- 对nids_tcp_timeouts的理解:
			--  [nids_tcp_timeouts]链表中保存的是一个个的[timeout]节点。
				这些节点在[add_tcp_closing_timeout]函数中被添加到
				[nids_tcp_timeouts]链表上，按照升序的方式插入(用了for循环).
			--  可见[nids_tcp_timeouts]链表中记录的都是已经经过四次挥手
				而准备释放了的tcp链接们。
			--  为什么需要搞这么一个[nids_tcp_timeouts]而不是直接释放掉
				已经完成四次挥手的一个tcp呢?
			--  在四次挥手后不立即删除tcp是考虑到在不久的将来，client与server
				可能会再次请求建立一条一模一样的tcp(地址四元组完全一样的tcp)。
				仅此而已.

	- Comment by shashibici 2014/03/21
			
**/
void
tcp_check_timeouts(struct timeval *now)
{

	// tcp_timeout结构，是一个链表，该链表中的主体是a_tcp,然后还有pre、next
	// 两个链表域
	struct tcp_timeout *to;
	struct tcp_timeout *next;
	struct lurker_node *i;

	// 遍历nids_tcp_timeouts链表
	for (to = nids_tcp_timeouts; to; to = next)
	{
		// 如果当前包的时间值没有超过[to]中记录的timeout值，直接返回
		if (now->tv_sec < to->timeout.tv_sec)
			return;
		// 否则将[to]对应的tcp状态设置为[NIDS_TIMED_OUT]
		to->a_tcp->nids_state = NIDS_TIMED_OUT;
		// 将[to]所对应的tcp中所有listeners执行一遍然后释放[to]对应的tcp
		for (i = to->a_tcp->listeners; i; i = i->next)
			(i->item) (to->a_tcp, &i->data);
		next = to->next;
		nids_free_tcp_stream(to->a_tcp);
	}
}


// 根据一个四元组的地址，生成一个hash索引。
// 为什么要生成hash索引? 因为同一个四元组可以构建多条tcp，这些tcp被组织在一个hash表项中
static int
mk_hash_index(struct tuple4 addr)
{
	int hash=mkhash(addr.saddr, addr.source, addr.daddr, addr.dest);
	return hash % tcp_stream_table_size;
}


// 获得tcp报头的一些信息
static int get_ts(struct tcphdr * this_tcphdr, unsigned int * ts)
{
	int len = 4 * this_tcphdr->th_off;
	unsigned int tmp_ts;
	unsigned char * options = (unsigned char*)(this_tcphdr + 1);
	int ind = 0, ret = 0;
	while (ind <=  len - (int)sizeof (struct tcphdr) - 10 )
		switch (options[ind])
		{
		case 0: /* TCPOPT_EOL */
			return ret;
		case 1: /* TCPOPT_NOP */
			ind++;
			continue;
		case 8: /* TCPOPT_TIMESTAMP */
			memcpy((char*)&tmp_ts, options + ind + 2, 4);
			*ts=ntohl(tmp_ts);
			ret = 1;
			/* no break, intentionally */
		default:
			if (options[ind+1] < 2 ) /* "silly option" */
				return ret;
			ind += options[ind+1];
		}

	return ret;
}


// 获得报头的一些信息
static int get_wscale(struct tcphdr * this_tcphdr, unsigned int * ws)
{
	int len = 4 * this_tcphdr->th_off;
	unsigned int tmp_ws;
	unsigned char * options = (unsigned char*)(this_tcphdr + 1);
	int ind = 0, ret = 0;
	*ws=1;
	while (ind <=  len - (int)sizeof (struct tcphdr) - 3 )
		switch (options[ind])
		{
		case 0: /* TCPOPT_EOL */
			return ret;
		case 1: /* TCPOPT_NOP */
			ind++;
			continue;
		case 3: /* TCPOPT_WSCALE */
			tmp_ws=options[ind+2];
			if (tmp_ws>14)
				tmp_ws=14;
			*ws=1<<tmp_ws;
			ret = 1;
			/* no break, intentionally */
		default:
			if (options[ind+1] < 2 ) /* "silly option" */
				return ret;
			ind += options[ind+1];
		}

	return ret;
}


/**
	参数:
		this_tcphdr: 指向一个tcp报文
		this_iphdr:  指向一个ip报文，该报文已经由多个ip分组组成
		icore:       指出当前哪一个核处理该tcp

	说明:
		
**/
static void
add_new_tcp(struct tcphdr * this_tcphdr, struct ip * this_iphdr, int icore)
{
	struct tcp_stream *tolink;
	struct tcp_stream *a_tcp;
	int hash_index;
	struct tuple4 addr;

	// 利用地址获得hash值
	addr.source = ntohs(this_tcphdr->th_sport);
	addr.dest = ntohs(this_tcphdr->th_dport);
	addr.saddr = this_iphdr->ip_src.s_addr;
	addr.daddr = this_iphdr->ip_dst.s_addr;
	
	hash_index = mk_hash_index(addr);

	// 如果tcp的数量过多
	if (tcp_num[icore] > max_stream)
	{
		// 这是一个a_tcp中的listener
		struct lurker_node *i;
		// 保存最老的tcp的client的状态
		int orig_client_state=tcp_oldest[icore]->client.state;
		// 设置最老的tcp为[时间到了，不能再待了]。
		tcp_oldest[icore]->nids_state = NIDS_TIMED_OUT;
		// 遍历执行这个最老的tcp中的所有listener函数
		for (i = tcp_oldest[icore]->listeners; i; i = i->next)
		{
			(i->item) (tcp_oldest[icore], &i->data);
		}
		// 将最老的tcp释放了(当然是需要修改time链表的)，这个函数里面tcp_num--
		nids_free_tcp_stream(tcp_oldest[icore]);
		// 如果这个最老的tcp的client没有成功发送过syn，那么server必定没有
		// TCP_CLOSING.此时需要发出警报
		if (orig_client_state!=TCP_SYN_SENT)
		{
			// tcp太多啦!
			// FIXME: 为什么不用[this_iphdr]?
			nids_params.syslog(NIDS_WARN_TCP, NIDS_WARN_TCP_TOOMUCH, ugly_iphdr[icore], this_tcphdr);
		}
	}

	// 获得free_streams链表头
	a_tcp = free_streams[icore];
	if (!a_tcp)
	{
		fprintf(stderr, "gdb me ...\n");
		pause();
	}
	// 将free_streams头节点取下来，并且将刚取下来的节点放在a_tcp中
	free_streams[icore] = a_tcp->next_free;
	// tcp_num数量增加
	tcp_num[icore]++;

	// 找到hash表项
	tolink = tcp_stream_table[hash_index];
	// 将a_tcp所指内存清空，也就是将刚从[free_streams]链表头摘下来的节点清空
	memset(a_tcp, 0, sizeof(struct tcp_stream));
	// 初始化一个tcp链接
	a_tcp->hash_index = hash_index;
	a_tcp->addr = addr;
	// client建立链接
	a_tcp->client.state = TCP_SYN_SENT;
	// 更新client端的发送序号，为下一个将要发送的序号，也是server应该ACK的序号
	a_tcp->client.seq = ntohl(this_tcphdr->th_seq) + 1;
	// 保存客户端第一个序列号
	a_tcp->client.first_data_seq = a_tcp->client.seq;
	// 记录client窗口大小
	a_tcp->client.window = ntohs(this_tcphdr->th_win);
	// 获得ts
	a_tcp->client.ts_on = get_ts(this_tcphdr, &a_tcp->client.curr_ts);
	// 获得wscale
	a_tcp->client.wscale_on = get_wscale(this_tcphdr, &a_tcp->client.wscale);
	// 设置服务器端为close
	a_tcp->server.state = TCP_CLOSE;
	// 设置处理的核
	a_tcp->icore = icore;

	// 将a_tcp挂载hash表对应项的链表表头，并且添加到hash中
	a_tcp->next_node = tolink;
	a_tcp->prev_node = 0;
	// 记录当前时间，[nids_last_pcap_header]就是刚从pcap处获得的包
	// 把tcp的第一个报文的时间设置为这个tcp的时间
	a_tcp->ts = nids_last_pcap_header->ts.tv_sec;
	// 如果该hash项已经有tcp节点了，那么挂载到它前面
	if (tolink)
	{
		tolink->prev_node = a_tcp;
	}
	tcp_stream_table[hash_index] = a_tcp;

	/**
		注意:
			下面这一段代码在多线程条件下很可能会产生问题。
			因此需要设置一个数组

			struct tcp_stream * tcp_latest[TCP_CORE_NUM]
			struct tcp_stream * tcp_oldest[TCP_CORE_NUM]

			每一个tcp_latest或tcp_oldest所指的链都是不同的，一个核有一个
	**/
	// 添加到time链表中
	a_tcp->next_time = tcp_latest[icore];
	a_tcp->prev_time = 0;
	// 如果oldest是空，那么，当前就是最老的，否则不是最老的
	if (!tcp_oldest[icore])
		tcp_oldest[icore] = a_tcp;
	// 如果latest不为空，那么把latest前面那个设为刚才加入的这个
	if (tcp_latest[icore])
		(tcp_latest[icore])->prev_time = a_tcp;
	// 刚才加入的，设为latest
	tcp_latest[icore] = a_tcp;
}


/**
	入参:
		rcv    : 报文接收者，一个tcp半链接
		data   : 指向需要加入buffer的数据
		datalen: 需要加入buffer的数据长度

	功能:
		分配足够的空间，
		将参数中data所指向长度为datalen的数据，拷贝到所分配的空间中。
		这个空间由rcv->data所指向。

	注意: 
		这个函数修改了rcv->count、rcv->count_new 和 rcv->bufsize
		其他任何变量都没有修改，包括rcv->offset 或 rcv->urg_ptr等
		
	- Comment by shashibici 2014/03/07
	
**/
static void
add2buf(struct half_stream * rcv, char *data, int datalen)
{
	int toalloc;

	// cout - offset 恰好等于当前data中存在的字节数
	// 如果再添加datalen数量的字节数，需要检测 rcv的buffer是否够大
	// 如果不够大,需要额外分配
	if (datalen + rcv->count - rcv->offset > rcv->bufsize)
	{
		// 如果还没有给data指针分配空间(这只发生在刚开始时)
		if (!rcv->data)
		{
			// 如果当前报文需要保存的内容
			// 小于2048就当成2048,否则另外计算
			if (datalen < 2048)
				toalloc = 4096;
			else
				toalloc = datalen * 2;
			rcv->data = malloc(toalloc);
			rcv->bufsize = toalloc;
		}
		// 否则已经分配了,这发生在收到后续报文的情况
		else
		{
			/* 这个空间分配策略看起来像是一个"二进制递增算法" */
			
			// 如果本次需要保存的数据，比当前的总大小要小，
			// 那么只需要在分配当前那么大的缓存空间即可，
			// 此情况下，会剩余些许空间留到下一个报文用
			if (datalen < rcv->bufsize)
			{
				toalloc = 2 * rcv->bufsize;
			}
			// 否则需要分配更多的空间。
			else
			{
				toalloc = rcv->bufsize + 2*datalen;
			}
			// realloc重新分配,
			// 如果堆空间足够，直接在原空间维追加;否则重新生成空间，拷贝并释放原空间
			rcv->data = realloc(rcv->data, toalloc);
			rcv->bufsize = toalloc;
		}
		// 如果没有分配成功
		if (!rcv->data)
			nids_params.no_mem("add2buf");
	}

	// 否则够大，直接执行这里
	// (count-offset)是data中现有的数据量， data+(count-offset)是在现有数据量末尾位置
	// 所以是将新来的数据，加到末尾
	memcpy(rcv->data + rcv->count - rcv->offset, data, datalen);
	// 修改刚刚到来的数据的计数器:count_new
	rcv->count_new = datalen;
	rcv->count += datalen;

	/*  注意: 这个函数并没有修改 offset 这个变量，只是修改了 count 这个变量*/
	
}


/**
	入参:
		a_tcp  : 一个tcp链接
		mask   : 这是一个记号，它的值只能是下面的一种
				{	
					COLLECT_cc  = 00000001B, 
					COLLECT_sc  = 00000010B,
					COLLECT_ccu = 0000100B,
					COLLECT_scu = 0001000B
				}

	功能:

	 1、设想这么一个应用场景:
	 	
	 	- 在一个网络入侵检测系统中，攻击者每一次攻击都会不可避免地产生一个
	 	  紧急报文(包含urg标记的报文)。
	 	- 检测系统为了在平常的时候减少检测开销，仅仅监听那些包含urg的报文，
	 	  对于正常的报文并不会收集并处理。
	 	- 检测系统在收到urg报文之后，会分析该报文的特征，如果符合某个特征，
	 	  就可以判断发生了网络攻击。
	 	- 一旦判断发生了网络工具，检测系统为了收集攻击者的更多信息，必须将
	 	  网络中的所有tcp报文都收集起来，并且做进一步的分析处理。

	 2、在上面的场景中，应用程序(我们可称之为"网警")可能可以按如下思路实现:

		- 每当网络中有一个新的tcp链接建立时，网警会执行语句
				a_tcp->client.collect_urg++;
				a_tcp->server.collect_urg++;
	 	  确保libnids会为他监听该tcp链接中所有包含urg标记的报文
	 	- 当有一个报文由libnids上传给网警的时候，网警会判断这个报文时候包含
	 	  urg标记。如果包含urg标记，那么他会解析这个包，依据包的特征决定是否需要
	 	  启动警报。如果不包含rug标记，说明这是一个正常的包，毫无疑问此时一定是网警
	 	  已经启动了警报(启动警报以后，libnids才会将正常的包送给网警)，此时需要分析
	 	  这个正常的包，进一步确定攻击者特征。
		- 启动警报。当网警发现了一个包含攻击特征的urg报文后，会执行下面语句启动警报
				a_tcp->client.collect++;
				a_tcp->server.collect++;
				alarm = true;
		- 当一次攻击威胁被解除之后，网警应该解除警报，恢复到仅仅监听包含urg的报文
		  的状态。他可以执行如下语句来解除警报
		  		a_tcp->client.collect--;
		  		a_tcp->server.collect--;
		  		alarm = false;
		- 之后网警回复正常，即仅仅监听并处理包含urg的报文

	 3、在上面的场景中，libnids中的ride_lurkers函数是怎样做的呢?

	  	- 每当收到一个属于a_tcp链接的tcp报文，ride_lurkers就会被调用一次。
	  	- 特别需要注意第二个参数mask,这个参数会根据ride_lurkers被调用的时机
	  	  和位置的不同有所不同。例如libnids在确收到一个包含urg标记的报文时，
	  	  会用如下语句进行调用
	  	  		mask = COLLECT_ccu;
	  	  		ride_lurkers(a_tcp, mask);
	  	  上面语句说明，libnids此时收到的一个报文，其接收者是client,而且这个报文
	  	  是一个包含有urg标记的报文，ride_lurkers函数要做的就是去所有的注册函数中
	  	  找一下，有哪一个注册函数的whatto域是与mask(此例中即COLLECT_ccu)相一致的，
	  	  如果找到，就调用这个函数。
	  	- ride_lurkers在处理某一个注册函数的whatto标志的时候，采用的是"与或开关"法。
	  	  如果whatto的某一位被置成1，则表明这个注册函数希望处理某一类型对应的报文。
	  	  例如在上个例子中，
	  	       mask为COLLECT_ccu(0x04),它和whatto相与，仅当whatto的倒数第三位为1
	  	       的时候结果才是true,才能够执行if.
	  	  如果whatto和COLLECT_ccu(0x04)相或，那么就是把whatto的倒数第三位置为1；
	  	  如果whatto和COLLECT_ccu(0x04)取反相与，那么就是把whatto倒数第三位清0。
		- 因此每一个lurker_node都能够通过其whatto字段来判断自己适合于处理哪一种
		  类型的报文，而不适合处理哪一种类型的报文。需要注意的是，每一个lurker_node
		  节点就代表了一个用户注册的注册函数，其中的item域就是指向用户注册函数的指针。

	注意:
		lurker_node 和 proc_node的区别。
		- proc_node仅仅是将用户注册的函数组织了起来。
		- lurker_node 是针对每一个tcp链接而言的，每一个tcp链接都有一个lurker_node的
		  链表结构，当该tcp释放了之后，其中的lurker_node将会全部释放。
		- 可以在这么说，proc_node是每一个注册函数的家，当不同的tcp需要用到同一个注册
		  函数的时候，这些tcp就需要给注册函数一个临时的家，临时的家就是lurker_node.

	- Comment by shashibic 2014/03/07
	
**/
static void
ride_lurkers(struct tcp_stream * a_tcp, char mask)
{
	struct lurker_node *i;
	// collect collect_urg
	char cc, sc, ccu, scu;

	// 遍历所有的监听这
	for (i = a_tcp->listeners; i; i = i->next)
		// 如果当前监听者i 的whatto 与 mask 相一致(相与后为1)
		// 那么当前监听者就是处理这个mask所对应的动作的。
		if (i->whatto & mask)
		{
			// 下面这几个变量: cc、sc、ccu、scu要么为0，要么为1
			cc = a_tcp->client.collect;
			sc = a_tcp->server.collect;
			ccu = a_tcp->client.collect_urg;
			scu = a_tcp->server.collect_urg;

			// 执行监听者函数，它其实就是用户注册的某一个函数
			(i->item) (a_tcp, &i->data);

			// 再次判断a_tcp中相应的标记是否变化。
			// 下面的if条件成立说明:用户将相应的值增加了
			if (cc < a_tcp->client.collect)
				i->whatto |= COLLECT_cc;
			if (ccu < a_tcp->client.collect_urg)
				i->whatto |= COLLECT_ccu;
			if (sc < a_tcp->server.collect)
				i->whatto |= COLLECT_sc;
			if (scu < a_tcp->server.collect_urg)
				i->whatto |= COLLECT_scu;
			// 下面的if条件成立说明:用户减少了相应的值
			if (cc > a_tcp->client.collect)
				i->whatto &= ~COLLECT_cc;
			if (ccu > a_tcp->client.collect_urg)
				i->whatto &= ~COLLECT_ccu;
			if (sc > a_tcp->server.collect)
				i->whatto &= ~COLLECT_sc;
			if (scu > a_tcp->server.collect_urg)
				i->whatto &= ~COLLECT_scu;
		}
}


/**
	入参:
		a_tcp : 触发回调的tcp链接
		rcv   : 触发回调的接收者

	功能:
		分两种情况讨论:
		1、如果有紧急报文。
		- 设置whatto为紧急报文标志，以告诉ride_lurker回调的目的是处理紧急报文。
		- 然后调用ride_lurker函数进行用户注册函数的回调。
		- 检查listener链表看是否有监听者需要删除，此删除不可逆。
		
		2、如果没有紧急报文
		- 设置whatto为正常报文标志，以高速ride_lurker回调的目的是处理正常报文。
		- 然后调用ride_lurker函数进行用户注册函数的回调。
		- 检查listener链表看是否有监听者需要删除，次删除不可逆。

	注意:
		在2、中，虽然有一个while循环，但是默认地，这个循环只会执行一次，
		而且不鼓励将one_loop_less设为非0.

	- Comment by shashibici 2014/03/07
	
**/
static void
notify(struct tcp_stream * a_tcp, struct half_stream * rcv)
{
	struct lurker_node *i, **prev_addr;
	char mask;

	// 如果有新的紧急包
	if (rcv->count_new_urg)
	{
		// 如果不监听紧急包
		if (!rcv->collect_urg)
			return;
		// 判断是client还是server
		if (rcv == &a_tcp->client)
			mask = COLLECT_ccu;
		else
			mask = COLLECT_scu;
		// 执行maks
		ride_lurkers(a_tcp, mask);
		// 跳转到"删除listeners", 不执行下面的if
		goto prune_listeners;
	}
	// 如果接收者对正常的报文感兴趣，那么执行对正常报文的处理
	if (rcv->collect)
	{
		if (rcv == &a_tcp->client)
			mask = COLLECT_cc;
		else
			mask = COLLECT_sc;
		do
		{
			int total;
			// 首先计算当前buffer中的字节数量(count-offset)
			// 然后记录下这个数值
			a_tcp->read = rcv->count - rcv->offset;
			total=a_tcp->read;

			/*
				这里需要特别注意，ride_lurkers会回调用户的注册函数。
				于是在用户注册的函数中，就有可能修改a_tcp->read这个数值。
				例如，若用户读取了n个字节，那么这个a_tcp->read就有可能修改为n。
			*/
			ride_lurkers(a_tcp, mask);
			
			// 如果count_new>0
			if (a_tcp->read > (total - rcv->count_new))
				rcv->count_new = total-a_tcp->read;
			// 把data向后read为起始地址的内容，移动到data处
			if (a_tcp->read > 0)
			{
				memmove(rcv->data, rcv->data + a_tcp->read, 
					    rcv->count - rcv->offset - a_tcp->read);
				
				rcv->offset += a_tcp->read;
			}
		}
		/* 注意: one_loop_less 默认情况下为0，也就是不会循环执行*/
		while (nids_params.one_loop_less && a_tcp->read>0 && rcv->count_new);
		// we know that if one_loop_less!=0, we have only one callback to notify
		// 移动完了之后 设置count_new
		rcv->count_new=0;
	}
	
prune_listeners:
	prev_addr = &a_tcp->listeners;
	i = a_tcp->listeners;

	// 遍历所有的listener,
	// 如果有某个listener的whatto为0，说明它已经没有用了，那么要删掉
	while (i)
	{
		if (!i->whatto)
		{
			*prev_addr = i->next;
			free(i);
			i = *prev_addr;
		}
		else
		{
			prev_addr = &i->next;
			i = i->next;
		}
	}
}


/**
	入参:
		a_tcp   : 当前正在处理的tcp
		rcv     : 接收者，半tcp
		snd     : 发送者，半tcp
		data    : 指向报文的指针
		datalen : 整个报文的长度，或者是data的有效长度
		this_seq: 从报文头抽取出来的，当前报文第一个字节的序号
		fin     : 从报文头抽取出来的，当前报文的fin标记
		urg     : 从报文头抽取出来的，当前报文的urg标记
		urg_prt : 从报文头抽取出来的，当前报文的urg_prt的值

	功能:
		lost    : 记录前面有多少字节已经是被确认过的
		to_copy : 记录紧急指针之前有多少正常的数据
		to_copy2: 记录紧急指针之后又多少正常的数据

		函数的执行分为两大分支:
			(1)该报文包含合法有效的紧急报文;
			(2)该报文没有包含合法有效的紧急报文;

		下面分情况解释这两种情况下函数的行为:
		1、收到的报文包含合法有效的紧急报文。
			在这种情况下，函数会用三个主要步骤来处理这个报文:
			1) 先处理紧急报文之前的有效数据。将这部分数据添加到
			   data所指向的缓存中，然后调用notify函数。
			2) 然后处理紧急报文数据。将这部分数据拷贝到data所指向
			   的缓存中，然后调用notify函数。
			3) 最后处理紧急报文后的有效数据。将这部分数据添加到
			   data所指向的缓存中，然后调用notify函数。
		2、收到的报文没有包含合法有效的紧急报文。
			在这种情况下，函数会直接将有效数据添加到data所指向的
			缓存中，然后调用notify函数。

		最后在数据被处理完了之后，函数会执行一个listener清除，将
		whatto为0的listener清除，此操作不可逆。
		也就是说如果一个listener被删除了，那么在这个tcp链接生命周期内都不会
		再次被添加进来了。

	注:  "有效内容"是指，在确认序列之后的那些字节序内容，已经被确认了的内容
		不算"有效内容"。

	- Comment by shashibici. 2014/03/07.

**/
static void
add_from_skb(struct tcp_stream * a_tcp, struct half_stream * rcv,
             struct half_stream * snd,
             u_char *data, int datalen,
             u_int this_seq, char fin, char urg, u_int urg_ptr)
{
	// 记录本报文中需要丢掉多少字节
	u_int lost = EXP_SEQ - this_seq;
	int to_copy, to_copy2;

	// 如果是一个紧急包，而且紧急指针的指向的位置是我们所期待的，
	// 而且 (接收者还没有发现这个紧急报文， 或者紧急指针比原来紧急指针还要大)
	// 那么执行下面的if条件，更新urg_seen 以及 urg_ptr.
	if (urg && after(urg_ptr, EXP_SEQ - 1) &&
	        (!rcv->urg_seen || after(urg_ptr, rcv->urg_ptr)))
	{
		rcv->urg_ptr = urg_ptr;
		rcv->urg_seen = 1;
	}

	// 如果接收者看到了这个紧急报文 &&
	// 紧急报文的开始在扔掉的那一部分报文之后，即这是我们需要的紧急报文内容 &&
	// 紧急指针不超过当前报文
	if (rcv->urg_seen && after(rcv->urg_ptr + 1, this_seq + lost) &&
	        before(rcv->urg_ptr, this_seq + datalen))
	{
		// 首先计算紧急内容之前的有效内容
		to_copy = rcv->urg_ptr - (this_seq + lost);
		// 如果有内容需要拷贝
		if (to_copy > 0)
		{
			// collect变量用来记录是否接受正常的报文
			// 非0表示接受，0表示不接受正常报文
			if (rcv->collect)
			{
				// 如果接收，则把当前包中，紧急指针之前的内容添加到buffer中
				// 这个buffer是half_stream中的一个data指针所指向的内存
				add2buf(rcv, (char *)(data + lost), to_copy);
				notify(a_tcp, rcv);
			}
			// 否则表示接收端不接受正常数据，即不调用notify函数
			else
			{
				// 只是把正常数据的数量记录一下，没有添加到buffer中
				rcv->count += to_copy;
				// 修改offset标记
				rcv->offset = rcv->count; /* clear the buffer */
			}
		}

		/* 经过以上过程，已经将紧急指针之前的正常内容拷贝到了buffer中了*/

		// 将rcv->urgdata指向真正的紧急数据开始的位置
		// 下面这个写法等价于:
		/*
			rcv->urgdata = data+(rcv->urg_ptr - this_seq);
		*/
		rcv->urgdata = data[rcv->urg_ptr - this_seq];
		// 标记有新的紧急数据到来
		rcv->count_new_urg = 1;
		// 调用notify函数，该函数最终会调用用户注册的回调函数
		notify(a_tcp, rcv);
		// 调用完通知函数，重新设置紧急标志
		rcv->count_new_urg = 0;
		// 设置为"接收者没有看到紧急数据"，即为下一个包做准备
		rcv->urg_seen = 0;
		// 修改紧急报文计数器
		rcv->urg_count++;
		// 计算紧急报文指针后面还有多少字节需要拷贝
		to_copy2 = this_seq + datalen - rcv->urg_ptr - 1;
		// 如果有字节需要拷贝
		if (to_copy2 > 0)
		{
			// 如果接收者需要接受正常报文，那么则拷贝
			if (rcv->collect)
			{
				add2buf(rcv, (char *)(data + lost + to_copy + 1), to_copy2);
				// 再次调用notify函数，该函数最终会回调用户的注册函数
				// 请注意，此时rcv->count_urg_new 为0。
				// 会被当成普通报文处理
				notify(a_tcp, rcv);
			}
			// 否则只做统计，不拷贝，也不调用回调函数
			else
			{
				rcv->count += to_copy2;
				rcv->offset = rcv->count; /* clear the buffer */
			}
		}
	}

	// 否则当前报文没有包含合法有效的 "紧急内容"
	// 当做正常报文处理
	else
	{
		// 如果出去丢掉的内容，还有内容
		if (datalen - lost > 0)
		{
			// 如果接收者需要接受正常报文
			if (rcv->collect)
			{
				add2buf(rcv, (char *)(data + lost), datalen - lost);
				// 没有合法的紧急报文，那么就当做是普通报文调用notify.
				// 注意，此时rcv->count_urg_new为0.
				notify(a_tcp, rcv);
			}
			// 否则接收者不接受正常报文，不拷贝也不回调用户注册的函数
			else
			{
				rcv->count += datalen - lost;
				rcv->offset = rcv->count; /* clear the buffer */
			}
		}
	}

	/*  上面的过程是将报文依据 "是否包含紧急报文" 这个标准，做了分情况处理
		处理的结果，主要是将刚刚收到的有效报文拷贝到buffer中.

		下面将是具体解析这个报文，判断是否包含"挥手"信息，然后做具体处理
		例如设置一下snd->state和rcv->state.
	*/
	
	if (fin)
	{
		// 如果包含挥手信息，说明发送者已经发送了
		snd->state = FIN_SENT;
		// 如果接收者已经为TCP_CLOSING 说明接收者也已经发送过fin了
		// 那么就是等待关闭整个tcp
		if (rcv->state == TCP_CLOSING)
			add_tcp_closing_timeout(a_tcp);
	}
}


/**
	入参:
		a_tcp        需要处理的tcp链接
		this_tcphdr  指向刚捕获的tcp报文头部的指针
		sed          发送者
		rcv          接收者
		data         指向刚捕获的tcp报文内容起始地址的指针
		datalen      需要申请的空间大小
		skblen       刚刚捕获的tcp报文的内容的长度

	功能:
		分情况，将刚刚捕获的tcp报文内容添加到rcv中。
		rcv有两个指针会用到，分别是"char *data" 和 "skbuff *list"
		data指针指向的是已经被确认了的tcp报文，
		list是一个链表头，该链表其实就是接收方的缓冲窗口，存放的是接收到但是没有
		被确认的报文。

	注意:
		该函数对接收到的报文分三种情况讨论。
		1)	接收到的报文的序号小于接收方上一次ack的序号，也就说收到了一个已经被确认
			过了的报文。
		2) 	接收到的报文的序号小于接收方上一次ack的序号，但是加上报文的长度之后，
			其序号超过接收方上一次ack的序号，也就是说这个报文中有一部分没有被确认。
		3)	接收到的报文序号大于或等于接收方上一次ack的序号，也就是说收到了一个
			报文，该报文是等待确认的报文。

	- Comment by shashibici 2014/03/07.
**/
static void
tcp_queue(struct tcp_stream * a_tcp, struct tcphdr * this_tcphdr,
          struct half_stream * snd, struct half_stream * rcv,
          char *data, int datalen, int skblen
         )
{
	u_int this_seq = ntohl(this_tcphdr->th_seq);
	struct skbuff *pakiet, *tmp;

	/*
	 * Did we get anything new to ack?
	 */

	// EXP_SEQ表示接收方期望的发送方序列号。
	// this_seq是刚刚捕获的这个包的序列号。
	// if (this_seq < EXP_SEQ)表示，当前抓到的包是一个重发的包。
	// if (this_seq == EXP_SEQ) 表示，当前抓到的包是一个期望的包。
	if (!after(this_seq, EXP_SEQ))
	{
		// 如果 当前报文的序号+报文的长度+(1或0) > 上一次发出的ack
		// 说明 这个包有一部分需要处理，即添加到rcv->data中
		// 注意: 这个"一部分"的长度恰好就是 this_seq + datalen - EXP_SEQ,
		// 如果this_seq == EXP_SEQ 那么就是整个报文都需要添加到rcv->data中
		if (after(this_seq + datalen + (this_tcphdr->th_flags & TH_FIN), EXP_SEQ))
		{
			/* the packet straddles our window end */
			get_ts(this_tcphdr, &snd->curr_ts);
			add_from_skb(a_tcp, rcv, snd, (u_char *)data, datalen, this_seq,
			             (this_tcphdr->th_flags & TH_FIN),
			             (this_tcphdr->th_flags & TH_URG),
			             ntohs(this_tcphdr->th_urp) + this_seq - 1);
			/*
			 * Do we have any old packets to ack that the above
			 * made visible? (Go forward from skb)
			 */
			pakiet = rcv->list;
			// 遍历rec->list链表，如果遇到不感兴趣的包直接清理掉；
			// 遇到部分感兴趣的包，留下感兴趣的部分然后清理掉；
			// 一直到遇到一个完全感兴趣的包，退出遍历。
			// "感兴趣"是指包的起始序号大于被确认过的序号(该包完全没被确认)
			// "部分感兴趣"是指包的前一部分已被确认而后半部分没被确认。
			// "不感兴趣"是指整个包已经被确认过。
			while (pakiet)
			{
				if (after(pakiet->seq, EXP_SEQ))
					break;
				// 如果第一个参数 大于 第二个参数 则为真，执行if.
				if (after(pakiet->seq + pakiet->len + pakiet->fin, EXP_SEQ))
				{
					add_from_skb(a_tcp, rcv, snd, pakiet->data,
					             pakiet->len, pakiet->seq, pakiet->fin, pakiet->urg,
					             pakiet->urg_ptr + pakiet->seq - 1);
				}
				rcv->rmem_alloc -= pakiet->truesize;
				// 如果找打的包，前驱不为空，说明不是第一个包
				if (pakiet->prev)
				{
					pakiet->prev->next = pakiet->next;
				}
				// 否则说明是第一个
				else
				{
					rcv->list = pakiet->next;
				}
				// 如果后面不为空，说明不是最后一个
				if (pakiet->next)
				{
					pakiet->next->prev = pakiet->prev;
				}
				// 否则是最后一个
				else
				{
					rcv->listtail = pakiet->prev;
				}
				tmp = pakiet->next;
				free(pakiet->data);
				free(pakiet);
				pakiet = tmp;
			}
		}
		else
		{
			// !after((this_seq, EXP_SEQ))为真  并且
			// after(this_seq + datalen + (this_tcphdr->th_flags & TH_FIN), EXP_SEQ) 为假
			// 表示完全不感兴趣,直接返回。
			return;
		}
		
	}
	// 这个else中处理 "完全感兴趣"的包。
	else
	{
		struct skbuff *p = rcv->listtail;

		pakiet = mknew(struct skbuff);
		// 真实的数据长度
		pakiet->truesize = skblen;
		rcv->rmem_alloc += pakiet->truesize;
		// 这一个包占的长度
		pakiet->len = datalen;
		// 分配一个包所占的长度的空间
		pakiet->data = malloc(datalen);
		// 如果非配失败则打印错误(并退出)
		if (!pakiet->data)
			nids_params.no_mem("tcp_queue");
		// 否则拷贝数据
		memcpy(pakiet->data, data, datalen);
		// 设置挥手标志
		pakiet->fin = (this_tcphdr->th_flags & TH_FIN);
		/* Some Cisco - at least - hardware accept to close a TCP connection
		 * even though packets were lost before the first TCP FIN packet and
		 * never retransmitted; this violates RFC 793, but since it really
		 * happens, it has to be dealt with... The idea is to introduce a 10s
		 * timeout after TCP FIN packets were sent by both sides so that
		 * corresponding libnids resources can be released instead of waiting
		 * for retransmissions which will never happen.  -- Sebastien Raveau
		 */
		 // 如果这是一个挥手
		if (pakiet->fin)
		{
			// 设置发送者状态为关闭
			snd->state = TCP_CLOSING;
			// 如果接收方已经发送了挥手 或者 接收方已经确认了挥手
			if (rcv->state == FIN_SENT || rcv->state == FIN_CONFIRMED)
				// 会将这个tcp放到一个等待关闭队列中。计时器到了就会关闭
				add_tcp_closing_timeout(a_tcp);
		}
		// 设置标志
		pakiet->seq = this_seq;
		pakiet->urg = (this_tcphdr->th_flags & TH_URG);
		pakiet->urg_ptr = ntohs(this_tcphdr->th_urp);
		// 将当前的报文包插入到list合适的位置，使得seq递增有序
		for (;;)
		{
			// 如果来到了队头，或者 发现了一个list节点p,它的seq不超过当前seq
			if (!p || !after(p->seq, this_seq))
				// 那么就终止循环
				break;
			// 否则由队尾向队头继续搜索
			p = p->prev;
		}

		// 如果是空，表示这一个刚收到的包，比原来list中所有包的seq都小
		// 所以应该插在队头
		if (!p)
		{
			// 将当前包插入到合适的位置
			pakiet->prev = 0;
			pakiet->next = rcv->list;
			if (rcv->list)
				rcv->list->prev = pakiet;
			rcv->list = pakiet;
			if (!rcv->listtail)
				rcv->listtail = pakiet;
		}
		// 否则不是空，那么一定找到了一个合适的位置
		// 所以插入到合适的位置
		else
		{
			pakiet->next = p->next;
			p->next = pakiet;
			pakiet->prev = p;
			if (pakiet->next)
				pakiet->next->prev = pakiet;
			else
				rcv->listtail = pakiet;
		}
	}
}


/**
	入参:
		rcv :         报文接收者
		this_tcphdr : 当前收到的报文的头

	功能:
		将rcv中的list链表全部删除，原因是list队列满了。
		
	注意:
		这个函数与tcp.c开头的一个purge_queue函数非常相似，千万不要弄错。
		那个函数只有一个参数，那就是需要"净化"的半连接，那个函数不会发出报警
		所以不需要tcp头。

	- Comment by shashibici 2014/03/07
**/

static void
prune_queue(struct half_stream * rcv, struct tcphdr * this_tcphdr, int icore)
{
	struct skbuff *tmp, *p = rcv->list;

	nids_params.syslog(NIDS_WARN_TCP, NIDS_WARN_TCP_BIGQUEUE, ugly_iphdr[icore], this_tcphdr);
	while (p)
	{
		free(p->data);
		tmp = p->next;
		free(p);
		p = tmp;
	}
	rcv->list = rcv->listtail = 0;
	rcv->rmem_alloc = 0;
}

static void
handle_ack(struct half_stream * snd, u_int acknum)
{
	int ackdiff;

	ackdiff = acknum - snd->ack_seq;
	if (ackdiff > 0)
	{
		snd->ack_seq = acknum;
	}
}
#if 0
static void
check_flags(struct ip * iph, struct tcphdr * th)
{
	u_char flag = *(((u_char *) th) + 13);
	if (flag & 0x40 || flag & 0x80)
		nids_params.syslog(NIDS_WARN_TCP, NIDS_WARN_TCP_BADFLAGS, iph, th);
//ECN is really the only cause of these warnings...
}
#endif



struct tcp_stream *
find_stream(struct tcphdr * this_tcphdr, struct ip * this_iphdr,
            int *from_client)
{
	struct tuple4 this_addr, reversed;
	struct tcp_stream *a_tcp;

	this_addr.source = ntohs(this_tcphdr->th_sport);
	this_addr.dest = ntohs(this_tcphdr->th_dport);
	this_addr.saddr = this_iphdr->ip_src.s_addr;
	this_addr.daddr = this_iphdr->ip_dst.s_addr;
	a_tcp = nids_find_tcp_stream(&this_addr);
	if (a_tcp)
	{
		*from_client = 1;
		return a_tcp;
	}
	
	reversed.source = ntohs(this_tcphdr->th_dport);
	reversed.dest = ntohs(this_tcphdr->th_sport);
	reversed.saddr = this_iphdr->ip_dst.s_addr;
	reversed.daddr = this_iphdr->ip_src.s_addr;
	a_tcp = nids_find_tcp_stream(&reversed);
	if (a_tcp)
	{
		*from_client = 0;
		return a_tcp;
	}
	return 0;
}



struct tcp_stream *
nids_find_tcp_stream(struct tuple4 *addr)
{
	int hash_index;
	struct tcp_stream *a_tcp;

	hash_index = mk_hash_index(*addr);
	for (a_tcp = tcp_stream_table[hash_index];
	        a_tcp && memcmp(&a_tcp->addr, addr, sizeof (struct tuple4));
	        a_tcp = a_tcp->next_node);
	return a_tcp ? a_tcp : 0;
}

/**
	参数:
		a_tcp: 给定一个a_tcp找到它的icore号。

	返回:
		icore号，如果成功；
		-1，如果失败
**/
static int
find_icore(struct tcp_stream * a_tcp)
{
	int icore;
	struct tcp_stream *t_tcp;
	
	for (icore = 0; icore < TCP_CORE_NUM; icore++)
	{
		for (t_tcp = tcp_latest[icore]; t_tcp; t_tcp = t_tcp->next_time)
		{
			if (a_tcp->addr.source == t_tcp->addr.source &&
				a_tcp->addr.dest == t_tcp->addr.dest &&
				a_tcp->addr.saddr == t_tcp->addr.saddr &&
				a_tcp->addr.daddr == t_tcp->addr.daddr)
			{
				return icore;
			}
		}
	}
	fprintf(stderr,"gdb me in find_core ...\n");
	pause();
	return -1;
}

/**
	作用:
		释放所有申请的空间，并且清空所有指针
**/
void tcp_exit(void)
{
	int i;
	struct lurker_node *j;
	struct tcp_stream *a_tcp, *t_tcp;

	// [streams_pool] 中所有的元素要么全部为0，要么都不为0
	// 因此只需要判断第一个元素即可。
	if (!tcp_stream_table || !(streams_pool[0]))
	{
		return;
	}
	// 对每一个hash项，遍历其中的tcp链表，逐一释放
	for (i = 0; i < tcp_stream_table_size; i++)
	{
		a_tcp = tcp_stream_table[i];
		while(a_tcp)
		{
			t_tcp = a_tcp;
			a_tcp = a_tcp->next_node;
			for (j = t_tcp->listeners; j; j = j->next)
			{
				t_tcp->nids_state = NIDS_EXITING;
				(j->item)(t_tcp, &j->data);
			}
			// 每次循环释放一个tcp节点
			nids_free_tcp_stream(t_tcp);
		}
	}
	// 释放table空间
	free(tcp_stream_table);
	tcp_stream_table = NULL;
	// 释放所有的tcp节点空间
	for (i = 0; i < TCP_CORE_NUM; i++)
	{
		free(streams_pool[i]);
		streams_pool[i] = NULL;
	}
	/* FIXME: anything else we should free? */
	/* yes plz.. */
	for (i = 0; i< TCP_CORE_NUM; i++)
	{
		tcp_latest[i] = tcp_oldest[i] = NULL;
		tcp_num[i] = 0;
	}
}


// 每当有一个tcp完整的报文被接收，就会调用这个函数
// 过程是这样的:
//
//   1、首先pcap中注册着一个回调函数: nids_pcap_handler,参数就是刚刚
//   接收到那个数据链路层包。这个函数在pcap接收到数据链路层的包的时候被回调。
//
//   2、在nids_pcap_handler中会把数据链路包的内容取出来，判断是否为一个ip分组
//   如果是一个ip分组，就会保存在 cap_queue 队列中(多线程时)，然后直接调用
//   call_ip_frag_procs 函数，参数就是pcap捕获的，经过简单处理分类的数据链路层包。
//
//   3、在call_ip_frag_procs函数中，会首先调用所有用户注册的ip_frag处理函数，
//   参数是刚刚捕获的包，最后调用libnids.c文件中的gen_ip_frag_proc函数，
//   参数是刚刚捕获的包。 是一个ip分组
//
//   4、在gen_ip_frag_proc函数中，会先处理一下传进来的ip分组，然后将处理过的ip包
//   作为参数，调用ip_defrag_stub函数，参数是刚刚处理过的ip分组(包)
//
//   5、在ip_defrag_stub函数中，会调用ip_defrag 函数将刚才的包，与已经重组了一部分
//   了的分组，进行重组，如果重组形成一个完整的ip报文，会返回一个 IPF_NEW；
//   或者还没有组装成一个完整的ip报文，返回IPF_NOTF；
//   或者出错，返回IPF_ISF；
//   
//
//   6、回到gen_ip_frag_proc中，如果是IPF_ISF，则直接返回，否则继续调用ip_procs
//   中的所有函数。首先是用户注册的ip处理函数，最后是libnids.c中的gen_ip_proc
//   函数，参数是捕获的包数据，以及缓冲长度。
//   
//   7、在gen_ip_proc函数中，会根据ip上层包的类型，调用process_tcp函数(如果是tcp)，
//   参数是捕获的数据报，以及缓冲长度。
// 
//   8、在process_tcp函数中，会解析这是怎样的一个tcp，然后进行相应的操作。
//      并且会在适当是时候调用 tcp的listeners以及 用户注册的tcp回调函数
//
//   - Comment by shashibic 2014/03/07
//
void
process_tcp(u_char * data, int skblen, int icore)
{

	/*************   首先进行tcp报文完整性检测   ***************/
	
    //http://blog.sina.com.cn/s/blog_5ceeb9ea0100wy0h.html
    //tcp头部数据结构
	struct ip *this_iphdr = (struct ip *)data;
	struct tcphdr *this_tcphdr = (struct tcphdr *)(data + 4 * this_iphdr->ip_hl);
	int datalen, iplen;
	int from_client = 1;
	unsigned int tmp_ts;
	struct tcp_stream *a_tcp;
	struct half_stream *snd, *rcv;

	ugly_iphdr[icore] = this_iphdr;
	//ntohl()是将一个无符号长整形数从网
	//络字节顺序转换为主机字节顺序。
	//个人理解:因为电脑有大小端问题，这样
	//统一成网络字节顺序能够屏蔽机器的差异进行通信。
	iplen = ntohs(this_iphdr->ip_len);//len 长度 hl头部长度
	if ((unsigned)iplen < 4 * this_iphdr->ip_hl + sizeof(struct tcphdr))
		//如果ip数据报长度少于最小的长度(tcp只有头部,无数据)
	{
		//系统打印出错日志
		nids_params.syslog(NIDS_WARN_TCP, NIDS_WARN_TCP_HDR, this_iphdr,
		                   this_tcphdr);
		return;
	} // ktos sie bawi

	datalen = iplen - 4 * this_iphdr->ip_hl - 4 * this_tcphdr->th_off;
	//th_off TCP头长度
	if (datalen < 0)
	{
		nids_params.syslog(NIDS_WARN_TCP, NIDS_WARN_TCP_HDR, this_iphdr,
		                   this_tcphdr);
		return;
	} // ktos sie bawi
    //如果原ip和目的ip都为0
	if ((this_iphdr->ip_src.s_addr | this_iphdr->ip_dst.s_addr) == 0)
	{
		nids_params.syslog(NIDS_WARN_TCP, NIDS_WARN_TCP_HDR, this_iphdr,
		                   this_tcphdr);
		return;
	}
	if (!(this_tcphdr->th_flags & TH_ACK))
		/*如果没有th_ack 包，则进行扫描是否有攻击包*/
		detect_scan(this_iphdr);//探测ip头部
	if (!nids_params.n_tcp_streams) return;
	if (my_tcp_check(this_tcphdr, iplen - 4 * this_iphdr->ip_hl,
	                 this_iphdr->ip_src.s_addr, this_iphdr->ip_dst.s_addr))
	{
		//检验序列
		nids_params.syslog(NIDS_WARN_TCP, NIDS_WARN_TCP_HDR, this_iphdr,
		                   this_tcphdr);
		//return;
	}

	
	 /*************    下面开始判断是否第一次握手     ***************/

	if (!(a_tcp = find_stream(this_tcphdr, this_iphdr, &from_client)))
	{
		// 找到hash表中的tcp
		// 如果进来执行，呢么就是第一次握手
		if ((this_tcphdr->th_flags & TH_SYN) &&
		        !(this_tcphdr->th_flags & TH_ACK) &&
		        !(this_tcphdr->th_flags & TH_RST))
			add_new_tcp(this_tcphdr, this_iphdr, icore);//
		return;
	}

	/*************    下面开始判断是否第二次握手     ***************/

	// 否则如果执行这里，就说明已经存在了一个tcp
	// 识别并记录发送方与接收方
	if (from_client)  //如果来自用户
	{
		snd = &a_tcp->client;//client为发送方
		rcv = &a_tcp->server;//服务器为接收方
	}
	else  //否则相反
	{
		rcv = &a_tcp->client;
		snd = &a_tcp->server;
	}

	// 第二次握手协议都会执行这一段
	if ((this_tcphdr->th_flags & TH_SYN))  //如果SYN==1 表示同步信号
	{
		// 如果来自client 那么就是重复的第一次握手。
		if (from_client)
		{
			// [nids_last_pcap_header]表示最新抓到的pcap包.
			// 如果打开了超时功能，并且最新抓到的包超过了上一个包+时间限制,则认为最新的包超时
			if (nids_params.tcp_flow_timeout > 0 &&
			        (nids_last_pcap_header->ts.tv_sec > a_tcp->ts + nids_params.tcp_flow_timeout))
			{
				// 执行到这里面，说明这个包是超时了的
				// 如果这个包既不是回应包也不是重置包，那么就手动重置。
				if (!(this_tcphdr->th_flags & TH_ACK) && !(this_tcphdr->th_flags & TH_RST))
				{
					/************
						执行到这个if里面的条件是:
						   有握手信号
						&& 来自client(也就是重复发起第一次握手)
						&& 这个包是超时的包
						&& 没有应答信息
						&& 没有重置信息.
						-------
						说明了:
						这个包确实是一个第一次握手(因为它没有应答没有重置)，
						但是这一个包或许在很久以前就发出来了，只是路径弯曲
						直到现在才被收到。
						这只能有一个解释:原来的tcp已经通过四次挥手被释放了，
						但是a_tcp这个变量并没有立即销毁，而依然存在(这在后面
						的代码中有体现)，我想就是为了等待这种情况的发生。
						仔细想来，在两个端口之间，原来的tcp已经释放，一段时间
						后又要求建立一个tcp链接，那么这个要求和可能就是[超时]
						的一个请求(因为这个间隔是两个tcp之间的间隔，不能紧密
						得像在一个tcp中那样，故和可能是一个[超时]的表现)。
					************/
					// 释放原来的tcp空间(在上一个tcp挥手完毕之后并不会
					// 被立即释放，这从后面的代码可以看到)
					nids_free_tcp_stream(a_tcp);
					// 当作第一次握手一样处理，添加一个新的tcp
					// 不用find_tcp_stream了，因为刚刚才释放，必然找不到
					add_new_tcp(this_tcphdr, this_iphdr, icore);//加载新的tcp
				}//end if

				/***********
					跳过上面的if直接执行这里则满足条件:
					   有握手信号
					&& 来自client
					&& 这个包是超时的
					&& 这个包有ACK 或者 这个包有RST.
					----------
					说明了:
					这个包不可能是一个合法的第一次握手(因为它包含了
					ACK或者RST)，
					因此无论如何都会直接把它丢弃掉
				************/
			}
			/*********
				如果跳过上面的if直接执行这里则满足条件:
				   有握手信号
				&& 来自client的
				&& 没有超时
				-------
				说明了:
				client在很短的时间内连续发出了握手请求。
				但是很显然，如果程序执行到这一步，这个tcp已经处理了
				第一次握手请求(libnids在处理第一次握手请求的时候就是
				在table中创建了一个a_tcp节点).
				因此，直接丢弃这个请求。
			************/
			return;
		}

		/**************
			如果跳过上面的if直接执行到这里则满足:
			   这个包带有一个握手请求。
			&& 这个包来自于server
			----------
			说明了:
			这必然是从server端发出的一个握手请求(也有可能是超时的),
			那么仅有的可能就是--第二次握手。
		****************/

		// 如果client 刚刚发送syn 并且 服务器没打开 并且 ACK==1 那么它是第二次握手
		// 参考: add_new_tcp函数 和 "TCP/IP三次握手协议"
		if (a_tcp->client.state != TCP_SYN_SENT ||
		        a_tcp->server.state != TCP_CLOSE || !(this_tcphdr->th_flags & TH_ACK))
			return;

		/**********
			如果执行到这里则满足:
				这个包上有握手请求
			&&  这个包来自于server
			&&  client已经发送了syn
			&&  server的tcp状态是close的
			&&  这个包有ACK标记
			----
			说明了:
			这必定是一个[第二次握手]，[第二次握手]恰好满足
			上面的条件。	
		**********/
		// 当且仅当是第二次握手(来自server端)才会往下执行
		// 根据[add_new_tcp]函数对第一次握手的处理可以看到，client.seq表示的是client
		// 将要发送的下一个序号，如果server并不是应答以期望这个序号，说明出错了。
		// 因为tcp此时还没建立，server不能期望之前的序号，也不能期望之后的序号。
		// 如果出现，说明这是一个不合法的包，可能是因为网络延时，上一个周期遗留下的。
		if (a_tcp->client.seq != ntohl(this_tcphdr->th_ack))
			return;
		/**
			执行到这里后，不但要满足上面的条件，而且需要满足:
				server应答的序号恰好就是client上次发出的序号+1.
		**/
		/**
			这里是将pcap最新抓到的包的时间保存在a_tcp中
			注意，这并不是tcp的计时器，而是下层(例如数据链路层)
			的时间.
		**/
		a_tcp->ts = nids_last_pcap_header->ts.tv_sec;
		// 原来[server.state]是[TCP_CLOSE]，现在修改了
		a_tcp->server.state = TCP_SYN_RECV;
		// 把[server.seq]设置为server的下一个将要发送的序号，也是client下次应答的序号
		// 当下一个server的包来临时，如果序号不对，做相应处理
		a_tcp->server.seq = ntohl(this_tcphdr->th_seq) + 1;
		// [server.firstdata]尽在这里做了初始化,记录的是
		// server端的第一个序号
		a_tcp->server.first_data_seq = a_tcp->server.seq;
		/*************
			这里是保存了server端此次应答的序号(即server期待
			client发送的下一个序号，它应该恰好等于[client.seq]).
			在下次libnids收到一个包，并且那个包是来自client
			的时候，会检查那个包中的[this_tcphdr->th_seq]值:
			
			- 如果那个包中的[this_tcphdr->th_seq] < 现在的
			[server.ack_seq]，说明那个包已经被server确认了，
			直接丢弃。

			- 如果那个包中的[this_tcphdr->th_seq] >= 现在的
			[server.ack_seq]，说明那个包还没有被server确认，
			需要添加到[server.data]或者[server.list]中
			前者保存已经按序确认了的报文，后者保存可以接受
			但还没有确认的报文
		***********/
		a_tcp->server.ack_seq = ntohl(this_tcphdr->th_ack);
		// 保存此次server告诉client的窗口大小
		a_tcp->server.window = ntohs(this_tcphdr->th_win);

		// 
		if (a_tcp->client.ts_on)
		{
			// 保存时间戳
			a_tcp->server.ts_on = get_ts(this_tcphdr, &a_tcp->server.curr_ts);
			if (!a_tcp->server.ts_on)
				a_tcp->client.ts_on = 0;
		}
		// 否则client是关闭的话，server也要关掉
		else 
		{
			a_tcp->server.ts_on = 0;
		}

		// 把网络包中的对应值,wscale保存下来
		if (a_tcp->client.wscale_on)
		{
			a_tcp->server.wscale_on = get_wscale(this_tcphdr, &a_tcp->server.wscale);
			if (!a_tcp->server.wscale_on)
			{
				a_tcp->client.wscale_on = 0;
				a_tcp->client.wscale  = 1;
				a_tcp->server.wscale = 1;
			}
		}
		else
		{
			a_tcp->server.wscale_on = 0;
			a_tcp->server.wscale = 1;
		}
		return;
	}
	// 以上一个if是第二次握手

	/*************    下面开始判断是否第三次握手     ***************/
	
	//--------------------------------
	// 否则执行下面代码,不是第一次也不是第二次握手
	// 不满足一些条件，就return
	if (
		// 不满足 (没有数据并且序号相同)
	    ! (  !datalen && ntohl(this_tcphdr->th_seq) == rcv->ack_seq  )
	    &&
	    //  发送的序列不在接受的范围之内 (超过窗口上限或低于窗口下限)
	    ( !before(ntohl(this_tcphdr->th_seq), rcv->ack_seq + rcv->window*rcv->wscale) ||
	      before(ntohl(this_tcphdr->th_seq) + datalen, rcv->ack_seq)
	    )
	)
		// 那么丢弃
		return;
	
	// 否则不返回
	
	// 如果有严重错误而导致reset则执行下面代码
	if ((this_tcphdr->th_flags & TH_RST))
	{
		// 如果在数据传输阶段
		if (a_tcp->nids_state == NIDS_DATA)
		{
			struct lurker_node *i;
			// 首先修改状态为reset
			a_tcp->nids_state = NIDS_RESET;
			// 然后遍历该tcp的所有监听者函数
			for (i = a_tcp->listeners; i; i = i->next)
				(i->item) (a_tcp, &i->data);
		}
		// 释放该tcp并返回
		nids_free_tcp_stream(a_tcp);
		return;
	}

	
	/* PAWS check */
	// 防绕回检测，如果是绕回，直接return
	if (rcv->ts_on && get_ts(this_tcphdr, &tmp_ts) &&
	        before(tmp_ts, snd->curr_ts))
		return;

	// 首先判断，这个tcp报文必须包含应答信息
	if ((this_tcphdr->th_flags & TH_ACK))
	{
		// 这个if如果成立，则唯一确定了必须是第三次握手
		// 参考: TCP-IP 详解卷1第18章
		if (from_client && a_tcp->client.state == TCP_SYN_SENT &&
		        a_tcp->server.state == TCP_SYN_RECV)
		{
			// 如果应答序号是正确的，才会执行下面的if语句
			if (ntohl(this_tcphdr->th_ack) == a_tcp->server.seq)
			{
				// 修改客户端的状态
				a_tcp->client.state = TCP_ESTABLISHED;
				// 把包中的ack记录下来，放到client中
				a_tcp->client.ack_seq = ntohl(this_tcphdr->th_ack);
				// 更新tcp的时间戳
				a_tcp->ts = nids_last_pcap_header->ts.tv_sec;

				/*********************************************************************
				下面这一段加了花括号代码的功能:
					首先必须明确，libnids一定是收到了一个来自client的第三次握手报文才会
					执行下面这一段代码，收到其他时候的报文都不会执行下面的代码的。

					所以可以这么理解，下面的代码是一个tcp链接刚刚建立的时候，第一次调用
					用户注册的回调函数。

					tcp链接在建立时，第一次握手和第二次握手不会回调用户注册的函数。
					
					tcp在第三次握手之前，如果有一方发出reset信号，也会回调用户注册的函数
					但是在那之后，整个tcp都会被销毁。

					下面这段代码就是遍历一次用户注册的回调函数，每遍历一个，就将它添加到
					listener链表中。主要有for循环实现。
				***********************************************************************/
				
				// 为什么这里需要加大括号?
				// 因为需要使用局部变量 i j data
				{
					struct proc_node *i;
					struct lurker_node *j;
					void *data;

					// 修改server端的状态
					a_tcp->server.state = TCP_ESTABLISHED;
					// 修改tcp的状态，刚刚建立
					a_tcp->nids_state = NIDS_JUST_EST;
					// 循环回调所有用户已经注册了的tcp回调函数
					for (i = tcp_procs; i; i = i->next)
					{
						// 这个变量用来记录用户的动作
						char whatto = 0;
						// 首先记录原来的 client.collect.
						// server.cllect 等的值，
						// 然后在用户的回调函数中会依据用户的喜好决定
						// 是否修改client.collect或者server.collect.的值。
						char cc = a_tcp->client.collect;
						char sc = a_tcp->server.collect;
						char ccu = a_tcp->client.collect_urg;
						char scu = a_tcp->server.collect_urg;

						/**
							这是用户注册的函数第一次被调用
							而且请注意此时 a_tcp->nids_state = NIDS_JUST_EST;
							所以在用户的回调函数中，需要有类似如下语句
								if (a_tcp->nids_state == NIDS_JUST_EST)
								{
									这里填写本注册函数的操作目的，例如专门处理urg报文，
									那么只需要将a_tcp->client.collect_urg++ 以及
									a_tcp->server.collect_urg++即可。
								}
							如果没有在一开始的时候，把目的说清楚，那么这个回调函数
							就不会被注册到libnids当中，今后是永远不会被回调的，只有在
							一开始的时候被回调一下。

							另外，如果在后续的处理当中，把某个注册函数中的所有目的指标
							都清除了，那么这个回调函数就会被彻底清除，以后再也无法被回调了。
							在上述例子中，如果将 a_tcp->client.collect_urg 与
							a_tcp->server.collect_urg都减少，并且没有其他的变量被设置，
							那么libnids会认为这个注册函数已经没有利用价值了，于是会从
							listener链表中除掉，以后再也没有机会加到listener链表中了，
							除非建立了一个新的tcp链接。(参考 notify函数)
							
						**/
						(i->item) (a_tcp, &data);

						/* 根据用户回调函数的修改，判断用户需要做什么事，从而
						   设置whatto。*/
						// 如果用户增加了client.collect的大小，
						// 说明用户希望接收客户端的普通包
						// 于是置位whatto最低位。
						if (cc < a_tcp->client.collect)
							whatto |= COLLECT_cc;
						// 如果用户增加了client.collect_urg的大小
						// 说明用户希望接收客户端紧急包
						// 于是置位whatto 次次低位。
						if (ccu < a_tcp->client.collect_urg)
							whatto |= COLLECT_ccu;
						// 下面类似，将whatto的不同位置为1
						if (sc < a_tcp->server.collect)
							whatto |= COLLECT_sc; 
						if (scu < a_tcp->server.collect_urg)
							whatto |= COLLECT_scu;

						// 默认为假,不执行
						if (nids_params.one_loop_less)
						{
							if (a_tcp->client.collect >=2)
							{
								a_tcp->client.collect=cc;
								whatto&=~COLLECT_cc;
							}
							if (a_tcp->server.collect >=2 )
							{
								a_tcp->server.collect=sc;
								whatto&=~COLLECT_sc;
							}
						}

						// 如果用户需要做某些事情，那么whatto就不会为空
						// 申请一个listener并且挂到头
						if (whatto)
						{
							// 生成一个listener并将用户注册的函数作为
							// 这个listener的函数，
							// 这个listener会挂载到对应的a_tcp上
							j = mknew(struct lurker_node);
							j->item = i->item;
							j->data = data;
							j->whatto = whatto;
							j->next = a_tcp->listeners;
							a_tcp->listeners = j;
						}
					}
					
					// 如果没有listener 就释放次tcp并返回
					// 因为这个tcp不用监听
					if (!a_tcp->listeners)
					{
						nids_free_tcp_stream(a_tcp);
						return;
					}

					// 否则将nids_stat设置为NIDS_DATA
					// 表示已经有数据到来了，但是数据还没有被用户处理
					a_tcp->nids_state = NIDS_DATA;
				}
				/**
					注意上面这一段加了花括号的代码，正常执行完毕之后会将
					a_tcp的状态改为NIDS_DATA,说明已经收到而来一个报文
					当然这个报文已经被回调函数处理了。
					这个状态只是为了给后续libnids接收报文做一个标志--说明这个tcp
					已经完成了握手阶段，进入数据传输阶段了。
				**/
				
			}
			// return;
		}
		
	}


	/**
	   注意: 执行完上述语句，process_tcp并没有结束。

	   - 首先，上述过程执行之后，如果是第三次握手的话用户注册的回调函数已经被执行了。
	   - 然后才执行下面的代码，下面的代码是将刚刚接收到的这个tcp报文
	     进行判断，是否需要保存到a_tcp的缓冲区中，或者是否是挥手报文。
	**/
	

	/********** 下面是对数据报文的处理，包含了判断是否四次挥手 ***************/
	/**
	从代码上看:
		- 如果数据报为第一次握手，那么在上面处理完后会return
		- 如果数据报为第二次握手，那么在上面处理完后也会 return
		- 如果数据报为第三次握手，那么在上面处理完后不会立即return而会继续往这里执行

	这符合TCP/IP的协议规范:
		- 第三次握手能够携带数据。
		- 若第三次握手携带了数据，那么会在这个process_tcp中连续两次回调用户注册函数
		  具体过程是这样的:
		  1) 第一次回调的时候，是"第三次握手"这个理由回调，在上面的for循环，在这次
		     调用时，会设置三个状态(在上述代码的for循环前)。
		     	a_tcp->client.state = TCP_ESTABLISHED;
				a_tcp->server.state = TCP_ESTABLISHED;
				a_tcp->nids_state = NIDS_JUST_EST;
			 此时回调用户注册函数的结果是，用户认为tcp刚刚建立，会做些初始化工作。
		  2) 第二次回调的时候，是"收到新报文"这个理由回调，在上面最后一句赋值语句
		  	 得以体现。
		  	 	a_tcp->nids_state = NIDS_DATA;
		  	 正是因为设置了这一个状态，那么在接下来的代码中使用notify回调用户注册
		  	 的函数时，用户会认为tcp已经建立了，并且当前有一个报文被监听到。

	注: 
		- 仅在收到的报文是第三次握手时，才会在process_tcp函数中出现两次回调
		  用户函数的现象，第一次是由上面的for循环完成，第二次有下面的tcp_queue完成。
		- 在普通情况下，接收到一个报文，在process_tcp函数中仅回调一次用户注册函数。
		- 在收到第三次握手时报文时，第一次回调用户注册函数的同时，会给这个tcp注册
		  一个listener链表，链表中每一个节点代表了一个用户注册的函数。如果一个用户
		  注册函数在这个时候，没有将
		  		client->collect
		  		client->urg_collect
		  		server->collect
		  		server->urg_collect
		  四个中的任何一个置位，那么这个用户写的回调函数将不会注册到这个tcp的listener
		  链表中，而且以后再也没有机会注册这个函数了!!
		  同样地，如果用户写的回调函数，不慎将这四个变量都设置成了0，那么在一次回调
		  过后，这个可怜的回调函数就会从listener链表中删除，并且没有机会再添加回去了!!
		  
	**/

	// 判断是否满足四次握手
	// 在这个if中，如果满足了"完成了四次握手"这个条件，则关闭并释放。
	if ((this_tcphdr->th_flags & TH_ACK))
	{
		// 更新ack
		handle_ack(snd, ntohl(this_tcphdr->th_ack));
		// 如果接收方，发送了挥手请求
		if (rcv->state == FIN_SENT)
			// 接收方的状态修改为挥手确认
			rcv->state = FIN_CONFIRMED;
		// 如果收发双方都已经确认挥手，那么就释放tcp
		if (rcv->state == FIN_CONFIRMED && snd->state == FIN_CONFIRMED)
		{
			struct lurker_node *i;
			// 修改tcp的状态为close
			a_tcp->nids_state = NIDS_CLOSE;
			// 遍历执行所有listener
			for (i = a_tcp->listeners; i; i = i->next)
				(i->item) (a_tcp, &i->data);
			// 释放tcp
			nids_free_tcp_stream(a_tcp);
			return;
		}
	}


	/**
		如果上面没有完成四次挥手，那么就会继续往下走，进入下面这个非常关键的if.
		下面代码的详情请参考 tcp_queue函数注释。
	**/
	// 否则不满足四次挥手的条件，那么就要处理这一个报文
	// 很可能就是放入缓存中。
	if (datalen + (this_tcphdr->th_flags & TH_FIN) > 0)
	{
		tcp_queue(a_tcp, this_tcphdr, snd, rcv,
		          (char *) (this_tcphdr) + 4 * this_tcphdr->th_off,
		          datalen, skblen);
	}
	
	// 发送窗口更新为当前数据包的窗口大小
	snd->window = ntohs(this_tcphdr->th_win);
	// 如果接收方的内存大于65535则释放掉所有占用的内存。
	if (rcv->rmem_alloc > 65535)
		prune_queue(rcv, this_tcphdr, icore);
	// 如果没有监听者，则释放tcp连接，否则不释放。
	if (!a_tcp->listeners)
		nids_free_tcp_stream(a_tcp);
}


void
nids_discard(struct tcp_stream * a_tcp, int num)
{
	if (num < a_tcp->read)
		a_tcp->read = num;
}

void
nids_register_tcp(void (*x))
{
	register_callback(&tcp_procs, x);
}

void
nids_unregister_tcp(void (*x))
{
	unregister_callback(&tcp_procs, x);
}

/**
	初始化所有tcp.c中需要初始化的全局变量

	- Written by shashibici 2014/03/21
**/
static inline void
init_tcp_globles()
{
	int i;
	
	for (i = 0; i < TCP_CORE_NUM; i++)
	{
		tcp_oldest[i] = 0;
		tcp_latest[i] = 0;
		tcp_num[0] = 0;
	}
}
	

/**
	parameters:
		size  :  spsecify the size for tcp_stream table.

	returning:
		return 0 if successful and -1 if fialed.

	Note:
		There are 4 steps.
		- Firstly, allocate tcp_stream_table.
		- Second, allocate "steams_pool" and add it to "free_streams".
		- Third, initialize hash.
		- Fourth, free "nids_tcp_timeouts" if necessary.

	------------------------------------------------------------------
	[tcp_stream_table]并不需要局部化，只需要保证每一个hash项能够占用不同
	的cache line即可。因为不同的线程访问的必然是不同hash项。

	[tcp_stream_table_size]并不需要局部化。因为它在整个项目中除了本函数内
	会初始化，其他任何时候都是只读的。

	[max_stream]并不需要局部化。因为它在整个项目中除了本函数内会初始化，
	其他任何时候都是只读的。

	[streams_pool]可以局部化
		struct tcp_stream* streams_pools[3].
	[free_streams]可以局部化
		struct tcp_stream* frees_streams[3]
	每一个核对应一个 streams_pools-frees_streams对，如此一来，需要进行
	很多的修改。

	[nids_tcp_timeouts] 不需要理会，因为libnids的运行参数告诉我们，并不需要
	用到nids_tcp_timeouts--workarounds参数被设为0。
	
	- Comment by shashibici 2014/03/21
	
*/
int
tcp_init(int size)
{
	
	int i,j;
	struct tcp_timeout *tmp;

	// 初始化本源文件中的所有全局变量
	init_tcp_globles();
	
	// return if no tcp
	if (!size) 
		return 0;

	// set tcp table size;
	tcp_stream_table_size = size;
	
	// allocate a set of memory initialized with 0, as tcp_table
	tcp_stream_table = calloc(tcp_stream_table_size, sizeof(char *));
	if (!tcp_stream_table)
	{
		nids_params.no_mem("tcp_init");
		return -1;
	}

	// set max hash factor
	max_stream = 3 * tcp_stream_table_size / 4;

	// allocate tcp_stream nodes
	for (i = 0; i < TCP_CORE_NUM; i++)
	{
		streams_pool[i] = (struct tcp_stream *) malloc((max_stream + 1) * sizeof(struct tcp_stream));
		// 如果分配失败，那么释放掉之前已经分配了的内存
		if (!streams_pool[i])
		{
			while (i > 0)
			{
				free(streams_pool[i-1]);
				i--;
			}
			nids_params.no_mem("tcp_init");
			return -1;
		}
	}
	
	// 为每一个核初始化一个对应的streams_pool和free_streams链表
	for (i = 0; i < TCP_CORE_NUM; i++)
	{
		for (j = 0; j < max_stream; j++)
		{
			streams_pool[i][j].next_free = &(streams_pool[i][j + 1]);
		}
		streams_pool[i][max_stream].next_free = 0;
		// 将链表放到合适的free指针上
		free_streams[i] = streams_pool[i];
	}

	init_hash();

	// free all nids_tcp_timouts
	while (nids_tcp_timeouts)
	{
		tmp = nids_tcp_timeouts->next;
		free(nids_tcp_timeouts);
		nids_tcp_timeouts = tmp;
	}
	return 0;
}

#if HAVE_ICMPHDR
#define STRUCT_ICMP struct icmphdr
#define ICMP_CODE   code
#define ICMP_TYPE   type
#else
#define STRUCT_ICMP struct icmp
#define ICMP_CODE   icmp_code
#define ICMP_TYPE   icmp_type
#endif

#ifndef ICMP_DEST_UNREACH
#define ICMP_DEST_UNREACH ICMP_UNREACH
#define ICMP_PROT_UNREACH ICMP_UNREACH_PROTOCOL
#define ICMP_PORT_UNREACH ICMP_UNREACH_PORT
#define NR_ICMP_UNREACH   ICMP_MAXTYPE
#endif


void
process_icmp(u_char * data)
{
	struct ip *iph = (struct ip *) data;
	struct ip *orig_ip;
	STRUCT_ICMP *pkt;
	struct tcphdr *th;
	struct half_stream *hlf;
	int match_addr;
	struct tcp_stream *a_tcp;
	struct lurker_node *i;

	int from_client;
	/* we will use unsigned, to suppress warning; we must be careful with
	   possible wrap when substracting
	   the following is ok, as the ip header has already been sanitized */

	// icmp 直接封装在ip层上，去掉ip头就是icmp包
	// len就是icmp的内容的长度
	unsigned int len = ntohs(iph->ip_len) - (iph->ip_hl << 2);

	// 如果长度不符合，则退出
	if (len < sizeof(STRUCT_ICMP))
		return;
	// data就是一个带ip头的ip包，这是指针运算，取ip头之后的那一部分
	pkt = (STRUCT_ICMP *) (data + (iph->ip_hl << 2));
	// 计算校验和，错误则返回
	if (ip_compute_csum((char *) pkt, len))
		return;
	// icmp包不是报告"目的不可达",则返回
	if (pkt->ICMP_TYPE != ICMP_DEST_UNREACH)
		return;
	// 否则是目的不可达

	
	/* ok due to check 7 lines above */
	len -= sizeof(STRUCT_ICMP);
	// sizeof(struct icmp) is not what we want here

	if (len < sizeof(struct ip))
		return;

	// orig_ip是出问题的ip的头(目的不可达的icmp的内容。)
	// 参考:http://wenku.baidu.com/link?url=7v9LjU1shidls6JHAGDThlZY5ml4GYK25v8On-Fxa6MDwViRtkNOdJGqvBiFSkEzQLOtZ3tlmnKyvSTjKJ1XQoP84nAvNXb9XVHOaEzaiOm
	orig_ip = (struct ip *) (((char *) pkt) + 8);
	// len是icmp除去icmp包头的那一部分的长度
	// 如果此长度小于规定的长度(问题ip的头+问题ip数据的前8字节)，则出错
	if (len < (unsigned)(orig_ip->ip_hl << 2) + 8)
		return;
	
	/* subtraction ok due to the check above */
	// len减去问题ip头的长度
	len -= orig_ip->ip_hl << 2;

	// 如果是端口不可达
	if (     (pkt->ICMP_CODE & 15) == ICMP_PROT_UNREACH ||
	        (pkt->ICMP_CODE & 15) == ICMP_PORT_UNREACH)
	        // 则地址是对的
		match_addr = 1;
	else
		// 否则地址是错的
		match_addr = 0;

	
	if (pkt->ICMP_CODE > NR_ICMP_UNREACH)
		return;

	// 是一种错误情况，应该返回
	if (match_addr && (iph->ip_src.s_addr != orig_ip->ip_dst.s_addr))
		return;
	// 如果不是运载tcp的ip，那么丢弃，返回
	if (orig_ip->ip_p != IPPROTO_TCP)
		return;

	// 否则就是针对tcp的
	// 问题ip包紧跟着头部后面的内容，即tcp头
	th = (struct tcphdr *) (((char *) orig_ip) + (orig_ip->ip_hl << 2));
	// 如果本地没有这么一个tcp连接，则纯属无中生有，返回
	if (!(a_tcp = find_stream(th, orig_ip, &from_client)))
		return;

	/*-----------------------------------------------------
	a_tcp->addr.dest是16位的， iph->ip_dst.s_addr是32位的???
	前者是一个端口号，后者是一个ip地址
	------------------------------------------------------*/	
	if (a_tcp->addr.dest == iph->ip_dst.s_addr)
		hlf = &a_tcp->server;
	else
		hlf = &a_tcp->client;
	/*-------------------------------------------------------
	-------------------------------------------------------*/
	// 如果已经发送并且接到挥手了，就返回
	if (hlf->state != TCP_SYN_SENT && hlf->state != TCP_SYN_RECV)
		return;
	// 否则出错，处理方法是强制reset
	a_tcp->nids_state = NIDS_RESET;
	// reset的操作时，释放连接，但是在此之前要遍历每一个listener
	for (i = a_tcp->listeners; i; i = i->next)
		(i->item) (a_tcp, &i->data);
	nids_free_tcp_stream(a_tcp);
}
