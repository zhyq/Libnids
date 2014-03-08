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

extern struct proc_node *tcp_procs;

static struct tcp_stream **tcp_stream_table;
static struct tcp_stream *streams_pool;
static int tcp_num = 0;
static int tcp_stream_table_size;
static int max_stream;
static struct tcp_stream *tcp_latest = 0, *tcp_oldest = 0;
static struct tcp_stream *free_streams;
static struct ip *ugly_iphdr;
struct tcp_timeout *nids_tcp_timeouts = 0;

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

	// 初始化为0
	h->list = h->listtail = 0;
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
	for (to = nids_tcp_timeouts; to; to = to->next)
		if (to->a_tcp == a_tcp)
			break;
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


void
nids_free_tcp_stream(struct tcp_stream * a_tcp)
{
	int hash_index = a_tcp->hash_index;
	// 注意: 后面的代码显示，lurker_node其实就代表了a_tcp的一个listener.(本函数倒数第二部分)
	struct lurker_node *i, *j;

	del_tcp_closing_timeout(a_tcp);
	// 首先清空该tcp两端的队列
	purge_queue(&a_tcp->server);
	purge_queue(&a_tcp->client);

	// 将当前node删除，把下一个node的prev指针指向当前node的前一个node
	if (a_tcp->next_node)
		a_tcp->next_node->prev_node = a_tcp->prev_node;
	// 将当前node删除，把上一个node的next指向当前node的下一个node
	if (a_tcp->prev_node)
		a_tcp->prev_node->next_node = a_tcp->next_node;
	else
		// 如果atcp->prev_node是空的，说明已经是链表头，这是一个hash链表。
		tcp_stream_table[hash_index] = a_tcp->next_node;

	// 释放数据
	if (a_tcp->client.data)
		free(a_tcp->client.data);
	if (a_tcp->server.data)
		free(a_tcp->server.data);

	// 将a_tcp从另一条链表中摘下来
	if (a_tcp->next_time)
		a_tcp->next_time->prev_time = a_tcp->prev_time;
	if (a_tcp->prev_time)
		a_tcp->prev_time->next_time = a_tcp->next_time;

	// 由这一段代码可知，每个新的tcp会加在time链表的表头。
	if (a_tcp == tcp_oldest)
		tcp_oldest = a_tcp->prev_time;
	if (a_tcp == tcp_latest)
		tcp_latest = a_tcp->next_time;

	// 释放所有a_tcp的listeners
	i = a_tcp->listeners;
	while (i)
	{
		j = i->next;
		free(i);
		i = j;
	}

	// 将a_tcp挂到free_streams的表头
	a_tcp->next_free = free_streams;
	free_streams = a_tcp;

	// 全局tcp数量-1
	tcp_num--;
}



void
tcp_check_timeouts(struct timeval *now)
{

	// tcp_timeout结构，是一个链表，该链表中的主体是a_tcp,然后还有pre、next两个链表域
	struct tcp_timeout *to;
	struct tcp_timeout *next;
	struct lurker_node *i;

	// 遍历nids_tcp_timeouts链表
	for (to = nids_tcp_timeouts; to; to = next)
	{
		if (now->tv_sec < to->timeout.tv_sec)
			return;
		to->a_tcp->nids_state = NIDS_TIMED_OUT;
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



//
static void
add_new_tcp(struct tcphdr * this_tcphdr, struct ip * this_iphdr)
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
	if (tcp_num > max_stream)
	{
		// 这是一个a_tcp中的listener
		struct lurker_node *i;
		// 保存最老的tcp, 并且自动认为最老的tcp已经超时
		int orig_client_state=tcp_oldest->client.state;
		tcp_oldest->nids_state = NIDS_TIMED_OUT;
		// 遍历执行这个最老的tcp中的所有listener函数
		for (i = tcp_oldest->listeners; i; i = i->next)
			(i->item) (tcp_oldest, &i->data);
		// 将最老的tcp释放了(当然是需要修改time链表的)，这个函数里面tcp_num--
		nids_free_tcp_stream(tcp_oldest);
		// 如果这个最老的tcp不是syn挥手过了，那么提示警告
		if (orig_client_state!=TCP_SYN_SENT)
			// tcp, tcp太多啦
			nids_params.syslog(NIDS_WARN_TCP, NIDS_WARN_TCP_TOOMUCH, ugly_iphdr, this_tcphdr);
	}

	// 获得free_streams链表头
	a_tcp = free_streams;
	if (!a_tcp)
	{
		fprintf(stderr, "gdb me ...\n");
		pause();
	}
	// 将free_streams头节点取下来，并且将刚取下来的节点放在a_tcp中
	free_streams = a_tcp->next_free;
	// tcp_num数量增加
	tcp_num++;

	// 找到hash表项
	tolink = tcp_stream_table[hash_index];
	// 将a_tcp所指内存清空
	memset(a_tcp, 0, sizeof(struct tcp_stream));
	// 初始化一个tcp链接
	a_tcp->hash_index = hash_index;
	a_tcp->addr = addr;
	// client建立链接
	a_tcp->client.state = TCP_SYN_SENT;
	// 构造需要请求的下一个seq
	a_tcp->client.seq = ntohl(this_tcphdr->th_seq) + 1;
	// 记录下第一个序列
	a_tcp->client.first_data_seq = a_tcp->client.seq;
	// 记录client窗口大小
	a_tcp->client.window = ntohs(this_tcphdr->th_win);
	// 获得ts
	a_tcp->client.ts_on = get_ts(this_tcphdr, &a_tcp->client.curr_ts);
	// 获得wscale
	a_tcp->client.wscale_on = get_wscale(this_tcphdr, &a_tcp->client.wscale);
	// 设置服务器端为close
	a_tcp->server.state = TCP_CLOSE;

	// 将a_tcp挂载hash表对应项的链表表头，并且添加到hash中
	a_tcp->next_node = tolink;
	a_tcp->prev_node = 0;
	a_tcp->ts = nids_last_pcap_header->ts.tv_sec;
	if (tolink)
		tolink->prev_node = a_tcp;
	tcp_stream_table[hash_index] = a_tcp;

	// 添加到time链表中
	a_tcp->next_time = tcp_latest;
	a_tcp->prev_time = 0;
	// 如果oldest是空，那么，当前就是最老的，否则不是最老的
	if (!tcp_oldest)
		tcp_oldest = a_tcp;
	// 如果latest不为空，那么把latest前面那个设为刚才加入的这个
	if (tcp_latest)
		tcp_latest->prev_time = a_tcp;
	// 刚才加入的，设为latest
	tcp_latest = a_tcp;
}


// rcv可能是接收端
// 这个函数是将新来的数据，添加到某一个tcp端(client或者server)的缓存中
static void
add2buf(struct half_stream * rcv, char *data, int datalen)
{
	int toalloc;

	// cout - offset 恰好等于当前data中存在的字节数
	// 如果再添加datalen数量的字节数，需要检测 rcv的buffer是否够大
	// 如果不够大
	if (datalen + rcv->count - rcv->offset > rcv->bufsize)
	{
		// 如果没有分配
		if (!rcv->data)
		{
			// 如果小于2048就当成2048,否则另外计算
			if (datalen < 2048)
				toalloc = 4096;
			else
				toalloc = datalen * 2;
			rcv->data = malloc(toalloc);
			rcv->bufsize = toalloc;
		}
		// 否则已经分配了
		else
		{
			// 只需要追加分配
			if (datalen < rcv->bufsize)
				toalloc = 2 * rcv->bufsize;
			else
				toalloc = rcv->bufsize + 2*datalen;
			// realloc重新分配
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
	// 修改刚刚到来的数据-- count_new
	rcv->count_new = datalen;
	rcv->count += datalen;
}



static void
ride_lurkers(struct tcp_stream * a_tcp, char mask)
{
	struct lurker_node *i;
	// collect collect_urg
	char cc, sc, ccu, scu;

	// 遍历所有的监听这
	for (i = a_tcp->listeners; i; i = i->next)
		if (i->whatto & mask)
		{
			cc = a_tcp->client.collect;
			sc = a_tcp->server.collect;
			ccu = a_tcp->client.collect_urg;
			scu = a_tcp->server.collect_urg;

			// 执行监听者函数
			(i->item) (a_tcp, &i->data);
			
			if (cc < a_tcp->client.collect)
				i->whatto |= COLLECT_cc;
			if (ccu < a_tcp->client.collect_urg)
				i->whatto |= COLLECT_ccu;
			if (sc < a_tcp->server.collect)
				i->whatto |= COLLECT_sc;
			if (scu < a_tcp->server.collect_urg)
				i->whatto |= COLLECT_scu;
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
	// 如果有新的包
	if (rcv->collect)
	{
		if (rcv == &a_tcp->client)
			mask = COLLECT_cc;
		else
			mask = COLLECT_sc;
		do
		{
			int total;
			// 在buffer中的数量
			a_tcp->read = rcv->count - rcv->offset;
			total=a_tcp->read;

			// 设置mask
			ride_lurkers(a_tcp, mask);
			// 如果count_new>0
			if (a_tcp->read>total-rcv->count_new)
				rcv->count_new=total-a_tcp->read;
			// 把data向后read为起始地址的内容，移动到data处
			if (a_tcp->read > 0)
			{
				memmove(rcv->data, rcv->data + a_tcp->read, rcv->count - rcv->offset - a_tcp->read);
				rcv->offset += a_tcp->read;
			}
		}
		while (nids_params.one_loop_less && a_tcp->read>0 && rcv->count_new);
// we know that if one_loop_less!=0, we have only one callback to notify
		// 移动完了之后 设置count_new
		rcv->count_new=0;
	}
	
prune_listeners:
	prev_addr = &a_tcp->listeners;
	i = a_tcp->listeners;

	// 遍历所有的listener,如果listener为空，则释放，否则跳过
	while (i)
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



static void
add_from_skb(struct tcp_stream * a_tcp, struct half_stream * rcv,
             struct half_stream * snd,
             u_char *data, int datalen,
             u_int this_seq, char fin, char urg, u_int urg_ptr)
{
	// 记录丢包数量
	u_int lost = EXP_SEQ - this_seq;
	int to_copy, to_copy2;

	// after函数:检查前一个参数是否比后一个参数大
	if (urg && after(urg_ptr, EXP_SEQ - 1) &&
	        (!rcv->urg_seen || after(urg_ptr, rcv->urg_ptr)))
	{
		rcv->urg_ptr = urg_ptr;
		rcv->urg_seen = 1;
	}
	
	if (rcv->urg_seen && after(rcv->urg_ptr + 1, this_seq + lost) &&
	        before(rcv->urg_ptr, this_seq + datalen))
	{
		to_copy = rcv->urg_ptr - (this_seq + lost);
		if (to_copy > 0)
		{
			if (rcv->collect)
			{
				add2buf(rcv, (char *)(data + lost), to_copy);
				notify(a_tcp, rcv);
			}
			else
			{
				rcv->count += to_copy;
				rcv->offset = rcv->count; /* clear the buffer */
			}
		}
		rcv->urgdata = data[rcv->urg_ptr - this_seq];
		rcv->count_new_urg = 1;
		notify(a_tcp, rcv);
		rcv->count_new_urg = 0;
		rcv->urg_seen = 0;
		rcv->urg_count++;
		to_copy2 = this_seq + datalen - rcv->urg_ptr - 1;
		if (to_copy2 > 0)
		{
			if (rcv->collect)
			{
				add2buf(rcv, (char *)(data + lost + to_copy + 1), to_copy2);
				notify(a_tcp, rcv);
			}
			else
			{
				rcv->count += to_copy2;
				rcv->offset = rcv->count; /* clear the buffer */
			}
		}
	}
	else
	{
		if (datalen - lost > 0)
		{
			if (rcv->collect)
			{
				add2buf(rcv, (char *)(data + lost), datalen - lost);
				notify(a_tcp, rcv);
			}
			else
			{
				rcv->count += datalen - lost;
				rcv->offset = rcv->count; /* clear the buffer */
			}
		}
	}
	if (fin)
	{
		snd->state = FIN_SENT;
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
				if (pakiet->prev)
					pakiet->prev->next = pakiet->next;
				else
					rcv->list = pakiet->next;
				if (pakiet->next)
					pakiet->next->prev = pakiet->prev;
				else
					rcv->listtail = pakiet->prev;
				
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
		// 
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


static void
prune_queue(struct half_stream * rcv, struct tcphdr * this_tcphdr)
{
	struct skbuff *tmp, *p = rcv->list;

	nids_params.syslog(NIDS_WARN_TCP, NIDS_WARN_TCP_BIGQUEUE, ugly_iphdr, this_tcphdr);
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


void tcp_exit(void)
{
	int i;
	struct lurker_node *j;
	struct tcp_stream *a_tcp, *t_tcp;

	if (!tcp_stream_table || !streams_pool)
		return;
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
			nids_free_tcp_stream(t_tcp);
		}
	}
	free(tcp_stream_table);
	tcp_stream_table = NULL;
	free(streams_pool);
	streams_pool = NULL;
	/* FIXME: anything else we should free? */
	/* yes plz.. */
	tcp_latest = tcp_oldest = NULL;
	tcp_num = 0;
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
void
process_tcp(u_char * data, int skblen)
{
//http://blog.sina.com.cn/s/blog_5ceeb9ea0100wy0h.html
//tcp头部数据结构
	struct ip *this_iphdr = (struct ip *)data;
	struct tcphdr *this_tcphdr = (struct tcphdr *)(data + 4 * this_iphdr->ip_hl);
	int datalen, iplen;
	int from_client = 1;
	unsigned int tmp_ts;
	struct tcp_stream *a_tcp;
	struct half_stream *snd, *rcv;

	ugly_iphdr = this_iphdr;
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
#if 0
	check_flags(this_iphdr, this_tcphdr);
//ECN
#endif
	if (!(a_tcp = find_stream(this_tcphdr, this_iphdr, &from_client)))
	{
		// 找到hash表中的tcp
		// 如果进来执行，呢么就是第一次握手
		if ((this_tcphdr->th_flags & TH_SYN) &&
		        !(this_tcphdr->th_flags & TH_ACK) &&
		        !(this_tcphdr->th_flags & TH_RST))
			add_new_tcp(this_tcphdr, this_iphdr);//
		return;
	}

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
			// if timeout since previous
			if (nids_params.tcp_flow_timeout > 0 &&
			        (a_tcp->ts + nids_params.tcp_flow_timeout < nids_last_pcap_header->ts.tv_sec))
			{
				if (!(this_tcphdr->th_flags & TH_ACK) && !(this_tcphdr->th_flags & TH_RST))
				{

					// cleanup previous
					nids_free_tcp_stream(a_tcp);//释放tcp空间
					// start new
					add_new_tcp(this_tcphdr, this_iphdr);//加载新的tcp
				}//end if
			}
			return;
		}

		// 否则是server的。
		
		// 如果client 刚刚发送syn 并且 服务器没打开 并且 ACK==1 那么它是第二次握手
		// 参考: add_new_tcp函数 和 "TCP/IP三次握手协议"
		if (a_tcp->client.state != TCP_SYN_SENT ||
		        a_tcp->server.state != TCP_CLOSE || !(this_tcphdr->th_flags & TH_ACK))
			return;

		// 当且仅当是第二次握手(来自server端)才会往下执行

		// 序列不是想要的，也会返回
		// seq 作为下一个将要发送的序号(每次更新之后会等于对方的ack)
		// 如果不是按序发送，则返回。
		if (a_tcp->client.seq != ntohl(this_tcphdr->th_ack))//不是想要的序列，丢弃
			return;

		// 否则不返回，执行下面语句
		// time stemp
		a_tcp->ts = nids_last_pcap_header->ts.tv_sec;
		a_tcp->server.state = TCP_SYN_RECV;
		// seq = y
		a_tcp->server.seq = ntohl(this_tcphdr->th_seq) + 1;//seq+1
		// y就是firstdata
		a_tcp->server.first_data_seq = a_tcp->server.seq;
		// ack_seq = x+1
		a_tcp->server.ack_seq = ntohl(this_tcphdr->th_ack);
		// window
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

	// 
	if ((this_tcphdr->th_flags & TH_ACK))
	{
		// 如果是第三次握手连接,可以开始发数据了
		if (from_client && a_tcp->client.state == TCP_SYN_SENT &&
		        a_tcp->server.state == TCP_SYN_RECV)
		{

			// 
			if (ntohl(this_tcphdr->th_ack) == a_tcp->server.seq)
			{
				// 修改客户端的状态
				a_tcp->client.state = TCP_ESTABLISHED;
				// 把包中的ack记录下来，放到client中
				a_tcp->client.ack_seq = ntohl(this_tcphdr->th_ack);
				// 跟新tcp的时间戳
				a_tcp->ts = nids_last_pcap_header->ts.tv_sec;
				
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
						char whatto = 0;
						char cc = a_tcp->client.collect;
						char sc = a_tcp->server.collect;
						char ccu = a_tcp->client.collect_urg;
						char scu = a_tcp->server.collect_urg;

						// 执行用户注册的某一个tcp回调函数
						(i->item) (a_tcp, &data);
						// 设置whatto
						if (cc < a_tcp->client.collect)
							whatto |= COLLECT_cc;
						if (ccu < a_tcp->client.collect_urg)
							whatto |= COLLECT_ccu;
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


						// 申请一个listener并且挂到头
						if (whatto)
						{
							j = mknew(struct lurker_node);
							j->item = i->item;
							j->data = data;
							j->whatto = whatto;
							j->next = a_tcp->listeners;
							a_tcp->listeners = j;
						}
					}

					// 所有tcp回调函数都已经执行完了


					// 如果没有listener 就释放次tcp并返回
					if (!a_tcp->listeners)
					{
						nids_free_tcp_stream(a_tcp);
						return;
					}

					// 否则继续处理数据
					a_tcp->nids_state = NIDS_DATA;
				}
			}
			// return;
		}
		
	}


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

	
	//四次握手释放
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
		prune_queue(rcv, this_tcphdr);
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

int
tcp_init(int size)
{
	int i;
	struct tcp_timeout *tmp;

	if (!size) return 0;
	tcp_stream_table_size = size;
	tcp_stream_table = calloc(tcp_stream_table_size, sizeof(char *));
	if (!tcp_stream_table)
	{
		nids_params.no_mem("tcp_init");
		return -1;
	}
	max_stream = 3 * tcp_stream_table_size / 4;
	streams_pool = (struct tcp_stream *) malloc((max_stream + 1) * sizeof(struct tcp_stream));
	if (!streams_pool)
	{
		nids_params.no_mem("tcp_init");
		return -1;
	}
	for (i = 0; i < max_stream; i++)
		streams_pool[i].next_free = &(streams_pool[i + 1]);
	streams_pool[max_stream].next_free = 0;
	free_streams = streams_pool;
	init_hash();
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
