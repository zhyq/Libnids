/*
  This file is taken from Linux 2.0.36 kernel source.
  Modified in Jun 99 by Nergal.
*/

#include <config.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "checksum.h"
#include "ip_fragment.h"
#include "tcp.h"
#include "util.h"
#include "nids.h"

#define IP_CE		0x8000	/* Flag: "Congestion" */
#define IP_DF		0x4000	/* Flag: "Don't Fragment" */
#define IP_MF		0x2000	/* Flag: "More Fragments" */
#define IP_OFFSET	0x1FFF	/* "Fragment Offset" part */

#define IP_FRAG_TIME	(30 * 1000)	/* fragment lifetime */

#define UNUSED 314159
#define FREE_READ UNUSED
#define FREE_WRITE UNUSED
#define GFP_ATOMIC UNUSED
#define NETDEBUG(x)

struct sk_buff
{
	char *data;
	int truesize;
};

struct timer_list
{
	struct timer_list *prev;
	struct timer_list *next;
	int expires;
	// 这个回调函数被初始化为 ip_expire
	void (*function)();
	// data是指向 struct ipq 的一个指针，在后面的代码中可以看到
	unsigned long data;
	// struct ipq *frags;
};

// 来自同一个ip主机的fragments
// 这个结构的主体是 struct ip *ipqueue
struct hostfrags
{
	// 会指向这个hostfrag所从属的ipqueue
	struct ipq *ipqueue;
	int ip_frag_mem;
	u_int ip;
	int hash_index;
	struct hostfrags *prev;
	struct hostfrags *next;
};

/* Describe an IP fragment. */
// 保存一个ip碎片，主要结构是sk_buff
struct ipfrag
{
	int offset;			/* offset of fragment in IP datagram    */
	int end;			/* last byte of data in datagram        */
	int len;			/* length of this fragment              */
	struct sk_buff *skb;		/* complete received fragment           */
	unsigned char *ptr;		/* pointer into real fragment data      */
	struct ipfrag *next;		/* linked list pointers                 */
	struct ipfrag *prev;
};

/* Describe an entry in the "incomplete datagrams" queue. */
struct ipq
{
	unsigned char *mac;		/* pointer to MAC header                */
	struct ip *iph;		/* pointer to IP header                 */
	int len;			/* total length of original datagram    */
	short ihlen;			/* length of the IP header              */
	short maclen;			/* length of the MAC header             */
	
	// 指向一个与这个queue对应的timer_list
	struct timer_list timer;	/* when will this queue expire?         */
	
	// 指向一个ipfrag链表，链表中每一个节点保存一个ip碎片
	struct ipfrag *fragments;	/* linked list of received fragments    */
	
	// 指向一个hostfrag链表
	struct hostfrags *hf;

	
	struct ipq *next;		/* linked list pointers                 */
	struct ipq *prev;
	// struct device *dev;	/* Device - for icmp replies */
};

/*
  Fragment cache limits. We will commit 256K at one time. Should we
  cross that limit we will prune down to 192K. This should cope with
  even the most extreme cases without allowing an attacker to
  measurably harm machine performance.
*/
#define IPFRAG_HIGH_THRESH		(256*1024)
#define IPFRAG_LOW_THRESH		(192*1024)

/*
  This fragment handler is a bit of a heap. On the other hand it works
  quite happily and handles things quite well.
*/
static struct hostfrags **fragtable;
static struct hostfrags *this_host;
static int numpack = 0;
static int hash_size;
static int timenow;
static unsigned int time0;
static struct timer_list *timer_head = 0, *timer_tail = 0;

#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))


// 返回当前时间，毫秒为单位
static int
jiffies()
{
	struct timeval tv;

	if (timenow)
		return timenow;
	
	// 如果timenow为0则会执行这里，获取时间
	gettimeofday(&tv, 0);
	// 秒转换成毫秒,微秒转换成毫秒
	timenow = (tv.tv_sec - time0) * 1000 + tv.tv_usec / 1000;

	return timenow;
}


/* Memory Tracking Functions */
// 原子操作减
static void
atomic_sub(int ile, int *co)
{
	*co -= ile;
}

// 原子操作加
static void
atomic_add(int ile, int *co)
{
	*co += ile;
}

// 释放一个sk_buff结构体大小的内存空间
static void
kfree_skb(struct sk_buff * skb, int type)
{
	// type这个参数是留下来，以后扩展用的，这一个版本没有用到
	(void)type;
	free(skb);
}


// 显示错误信息，并且推出
static void
panic(char *str)
{
	fprintf(stderr, "%s", str);
	exit(1);
}


// 操作timer_list链表，在链表为加入一个timer结构体
static void
add_timer(struct timer_list * x)
{
	// 如果尾指针不为空
	if (timer_tail)
	{
		timer_tail->next = x;
		x->prev = timer_tail;
		x->next = 0;
		timer_tail = x;
	}
	else
	{
		x->prev = 0;
		x->next = 0;
		timer_tail = timer_head = x;
	}
}


// 从timer_list链表中删除给定的timer
static void
del_timer(struct timer_list * x)
{
	// 如果不是链表头
	if (x->prev)
		x->prev->next = x->next;
	// 否则是链表头
	else
		timer_head = x->next;

	// 如果不是链表尾
	if (x->next)
		x->next->prev = x->prev;
	// 否则是链表尾
	else
		timer_tail = x->prev;
}


// 删除来自同一个host的所有fragments
// 首先修改对应的host_frag结构中记录ip_frag_mem的大小，然后释放掉这个skb结构体
static void
frag_kfree_skb(struct sk_buff * skb, int type)
{
	if (this_host)
		atomic_sub(skb->truesize, &this_host->ip_frag_mem);
	kfree_skb(skb, type);
}

// 释放给定指针开始，长度为len的内存，相比于上一个函数，
// 这个函数能够更自由的释放任意大小的内存块。前提是这len长的内存块是同一个malloc分配的
static void
frag_kfree_s(void *ptr, int len)
{
	if (this_host)
		atomic_sub(len, &this_host->ip_frag_mem);
	free(ptr);
}


// 为当前主机 this_host分配一块内存，然后返回指向内存的地址。
// 这里使用了malloc
static void *
frag_kmalloc(int size, int dummy)
{
	void *vp = (void *) malloc(size);
	// 这个参数留着以后扩展用。
	(void)dummy;
	if (!vp)
		return NULL;
	atomic_add(size, &this_host->ip_frag_mem);

	return vp;
}


/* Create a new fragment entry. */
// 返回一个ip碎片结构
// 输入参数是:
//       offset 该碎片在整个ip报文中的偏移量
//       end    该碎片最后一个字节在数据报中的位置
//       skb    该碎片对应的缓存
//       prt    指向该碎片内部某一个字节的指针，可以按字节访问
//
// 
//  注意: 这个ipfrag结构还没有挂载到某一个ipq上面
static struct ipfrag *
ip_frag_create(int offset, int end, struct sk_buff * skb, unsigned char *ptr)
{
	struct ipfrag *fp;

	// 这里调用malloc分配一个ipfrag空间
	fp = (struct ipfrag *) frag_kmalloc(sizeof(struct ipfrag), GFP_ATOMIC);
	if (fp == NULL)
	{
		// NETDEBUG(printk("IP: frag_create: no memory left !\n"));
		nids_params.no_mem("ip_frag_create");
		return (NULL);
	}

	// 将内存填充为0
	memset(fp, 0, sizeof(struct ipfrag));

	/* Fill in the structure. */
	fp->offset = offset;
	fp->end = end;
	fp->len = end - offset;
	fp->skb = skb;
	fp->ptr = ptr;

	/* Charge for the SKB as well. */
	// 该表host的内存字段
	this_host->ip_frag_mem += skb->truesize;

	return (fp);
}


// 生成hash index
// 方法是， ip对应的正数与hash表大小求模
// 结果相同的ip一定会映射到相同的hash表项上，但是不同的ip也有可能映射到相同的hash表项上
static int
frag_index(struct ip * iph)
{
	unsigned int ip = ntohl(iph->ip_dst.s_addr);

	return (ip % hash_size);
}



// 根据所给的ip头，找到与这个ip碎片对应的主机相关信息
// 这个主机相关信息，由全局变量this_host保存
// 成功更新this_host，返回1，否则返回0， this_host也为0
//
// 从这个函数可以看出，每一个host被放在一个hash项中，
// 采用的是链表法解决hash冲突
static int
hostfrag_find(struct ip * iph)
{
	// 首先生成一个hash index
	int hash_index = frag_index(iph);
	struct hostfrags *hf;

	// 将全局变量清零,这个全局变量总是指向当前报文对应的host
	this_host = 0;
	// 
	for (hf = fragtable[hash_index]; hf; hf = hf->next)
		if (hf->ip == iph->ip_dst.s_addr)
		{
			this_host = hf;
			break;
		}
	// 如果找不到，则返回0，否则返回1
	if (!this_host)
		return 0;
	else
		return 1;
}


// 
static void
hostfrag_create(struct ip * iph)
{
	// mknew函数最终调用了malloc以字节为单位分配内存
	struct hostfrags *hf = mknew(struct hostfrags);
	// 生成hash index
	int hash_index = frag_index(iph);

	// 填充hostfrags 结构体
	hf->prev = 0;
	// 插入到hash表头
	hf->next = fragtable[hash_index];
	// 维护双向链表
	if (hf->next)
		hf->next->prev = hf;
	// 挂到hash表上
	fragtable[hash_index] = hf;

	// 填充ip
	hf->ip = iph->ip_dst.s_addr;
	// 数据报队列初始化为空
	hf->ipqueue = 0;
	// 占用内存大小初始化为0
	hf->ip_frag_mem = 0;
	hf->hash_index = hash_index;
	// 设置当前host为刚刚创建的host
	this_host = hf;
}


// 删除当前节点
static void
rmthis_host()
{
	// 获得index
	int hash_index = this_host->hash_index;

	// 从hash 链表上摘下来
	if (this_host->prev)
	{
		this_host->prev->next = this_host->next;
		if (this_host->next)
			this_host->next->prev = this_host->prev;
	}
	else
	{
		fragtable[hash_index] = this_host->next;
		if (this_host->next)
			this_host->next->prev = 0;
	}
	// 释放空间
	free(this_host);
	// 设置为0
	this_host = 0;
}



/*
  Find the correct entry in the "incomplete datagrams" queue for this
  IP datagram, and return the queue entry address if found.
*/
// 给定一个ip头，从当前的host中找到与这个ip头相同的ip报文
// 这类报文具有相同的 1、ip_id； 2、ip源与目的地址； 3、ip上层协议
static struct ipq *
ip_find(struct ip * iph)
{
	struct ipq *qp;
	struct ipq *qplast;

	qplast = NULL;
	// 在当前host对应的queue中遍历
	for (qp = this_host->ipqueue; qp != NULL; qplast = qp, qp = qp->next)
	{
		// id相同、目的与源地址相同、上层协议相同，则满足
		// 注: ip_id是ip碎片标示符，用来进行ip从组的
		// 参考:http://www.360doc.com/content/11/1026/13/7899729_159299493.shtml
		if (iph->ip_id == qp->iph->ip_id &&
		        iph->ip_src.s_addr == qp->iph->ip_src.s_addr &&
		        iph->ip_dst.s_addr == qp->iph->ip_dst.s_addr &&
		        iph->ip_p == qp->iph->ip_p)
		{
			// 一个queue只对应一个timer
			del_timer(&qp->timer);	/* So it doesn't vanish on us. The timer will be reset anyway */
			return (qp);
		}
	}
	return (NULL);
}



/*
  Remove an entry from the "incomplete datagrams" queue, either
  because we completed, reassembled and processed it, or because it
  timed out.
*/
// 从当前host中删除掉一个给定的ip报文队列
static void
ip_free(struct ipq * qp)
{
	struct ipfrag *fp;
	struct ipfrag *xp;

	/* Stop the timer for this entry. */
	del_timer(&qp->timer);

	/* Remove this entry from the "incomplete datagrams" queue. */

	// 如果队列是host中的第一个队列
	if (qp->prev == NULL)
	{
		this_host->ipqueue = qp->next;
		// 如果后面还有，则修改后面一个为第一个
		if (this_host->ipqueue != NULL)
			this_host->ipqueue->prev = NULL;
		// 否则该删除的队列是最后一个，说明host已经没有队列了，删除host
		else
			rmthis_host();
	}
	// 否则不是第一个
	else
	{
		qp->prev->next = qp->next;
		// 如果不是最后一个，修改后一个的指针
		if (qp->next != NULL)
			qp->next->prev = qp->prev;
	}
	
	/* Release all fragment data. */
	// 将这一个队列中所有的fragments全部释放掉
	fp = qp->fragments;
	while (fp != NULL)
	{
		xp = fp->next;
		// 释放ipfrag中的ksb
		frag_kfree_skb(fp->skb, FREE_READ);
		// 再释放ipfrag结构
		frag_kfree_s(fp, sizeof(struct ipfrag));
		fp = xp;
	}
	
	/* Release the IP header. */
	frag_kfree_s(qp->iph, 64 + 8);

	/* Finally, release the queue descriptor itself. */
	frag_kfree_s(qp, sizeof(struct ipq));
}

/* Oops- a fragment queue timed out.  Kill it and send an ICMP reply. */
//  输入:  
//       超时的ip队列的指针
//  输出:
//        无
//
//  注意: 这一个函数并没有发送icmp仅仅是删除了对应的ip队列
static void
ip_expire(unsigned long arg)
{
	struct ipq *qp;

	qp = (struct ipq *) arg;

	/* Nuke the fragment queue. */
	// 将这个ip队列删除掉
	ip_free(qp);
}


/*
  Memory limiting on fragments. Evictor trashes the oldest fragment
  queue until we are back under the low threshold.
*/
//
//
//
static void
ip_evictor(void)
{
	// fprintf(stderr, "ip_evict:numpack=%i\n", numpack);

	// 如果当前host存在，并且当前host的内存大于了下限
	while (this_host && this_host->ip_frag_mem > IPFRAG_LOW_THRESH)
	{
		// 如果对应的ip队列不为空
		if (!this_host->ipqueue)
			// 报错(好像会exit)
			panic("ip_evictor: memcount");
		// 释放当前的ipqueue, 一直到当前host的内存小于下限
		ip_free(this_host->ipqueue);
	}
}


/*
  Add an entry to the 'ipq' queue for a newly received IP datagram.
  We will (hopefully :-) receive all other fragments of this datagram
  in time, so we just create a queue for this datagram, in which we
  will insert the received fragments at their respective positions.
*/
// 疑问: 这一个应该要修改this_host的 ip_frag_mem变量吧????
// 输入:
//      ip头
// 返回:
//      ip队列，这个ip队列已经被挂载到host上了
static struct ipq *
ip_create(struct ip * iph)
{
	struct ipq *qp;
	int ihlen;

	// 调用malloc,申请一个空间
	qp = (struct ipq *) frag_kmalloc(sizeof(struct ipq), GFP_ATOMIC);
	if (qp == NULL)
	{
		// NETDEBUG(printk("IP: create: no memory left !\n"));
		nids_params.no_mem("ip_create");
		return (NULL);
	}
	// 填充为0
	memset(qp, 0, sizeof(struct ipq));

	/* Allocate memory for the IP header (plus 8 octets for ICMP). */
	// 多分配8字节，需要保存ip头以及头后面8字节，因为icmp的内容就是ip头+8字节
	ihlen = iph->ip_hl * 4;
	qp->iph = (struct ip *) frag_kmalloc(64 + 8, GFP_ATOMIC);
	if (qp->iph == NULL)
	{
		//NETDEBUG(printk("IP: create: no memory left !\n"));
		nids_params.no_mem("ip_create");
		frag_kfree_s(qp, sizeof(struct ipq));
		return (NULL);
	}
	// 将ip头+8字节的内容保存在iph变量中。
	// 到时候iph变量就能够直接作为icmp的内容，如果有必要发送icmp的话
	memcpy(qp->iph, iph, ihlen + 8);
	// 队列长度=0， 头长度，碎片队列
	qp->len = 0;
	qp->ihlen = ihlen;
	qp->fragments = NULL;
	// 挂载到当前host上
	qp->hf = this_host;

	/* Start a timer for this entry. */
	// jiffies函数返回当前时间，毫秒为单位
	qp->timer.expires = jiffies() + IP_FRAG_TIME;	/* about 30 seconds     */
	// 设置关联
	qp->timer.data = (unsigned long) qp;	/* pointer to queue     */
	// 注册一个超时函数，当超时的时候，会回调这个函数
	qp->timer.function = ip_expire;	/* expire function      */
	// 将这个timer挂载到queue上
	add_timer(&qp->timer);

	/* Add this entry to the queue. */
	// 将这个队列挂载到当前host上
	qp->prev = NULL;
	qp->next = this_host->ipqueue;
	if (qp->next != NULL)
		qp->next->prev = qp;
	this_host->ipqueue = qp;

	return (qp);
}


/* See if a fragment queue is complete. */
// 输入:
//       一个给定的ip队列
// 返回:
//       完成返回1， 否则返回0
static int
ip_done(struct ipq * qp)
{
	struct ipfrag *fp;
	int offset;

	/* Only possible if we received the final fragment. */
	if (qp->len == 0)
		return (0);

	/* Check all fragment offsets to see if they connect. */
	// 从队列中取出第一个fragment
	fp = qp->fragments;
	offset = 0;
	// 循环遍历队列中的每一个frag
	while (fp != NULL)
	{
		// 可以猜测，一个队列中的fragments是按曾序来排列的
		if (fp->offset > offset)
			return (0);		/* fragment(s) missing */
		// 修改offset为当前碎片最后一个字节
		offset = fp->end;
		// 查看下一个碎片
		fp = fp->next;
	}
	/* All fragments are present. */
	return (1);
}


/*
  Build a new IP datagram from all its fragments.

  FIXME: We copy here because we lack an effective way of handling
  lists of bits on input. Until the new skb data handling is in I'm
  not going to touch this with a bargepole.
*/
//
//  输入:
//        一个给定的ip队列，这个队列应该是完整的
//  返回:
//        一个ip报文
static char *
ip_glue(struct ipq * qp)
{
	char *skb;
	// 指向一个ip，到时候用来给新生成的ip字段赋值
	struct ip *iph;
	// 指向一个ip碎片
	struct ipfrag *fp;
	// 执向一个字节
	unsigned char *ptr;
	// 计数器、长度
	int count, len;

	/* Allocate a new buffer for the datagram. */
	// 长度 = 头长度 + 队列长度, 队列是所有ip碎片，不包括头长度
	len = qp->ihlen + qp->len;

	// 如果大于65535B 太大了，返回
	if (len > 65535)
	{
		// NETDEBUG(printk("Oversized IP packet from %s.\n", int_ntoa(qp->iph->ip_src.s_addr)));
		nids_params.syslog(NIDS_WARN_IP, NIDS_WARN_IP_OVERSIZED, qp->iph, 0);
		ip_free(qp);
		return NULL;
	}

	// 如果使用malloc失败，返回
	if ((skb = (char *) malloc(len)) == NULL)
	{
		// NETDEBUG(printk("IP: queue_glue: no memory for gluing queue %p\n", qp));
		nids_params.no_mem("ip_glue");
		ip_free(qp);
		return (NULL);
	}

	
	/* Fill in the basic details. */
	// 首先将指针，指向skb，一个最新分配的空间
	ptr = (unsigned char *)skb;
	// 将头拷贝过来
	memcpy(ptr, ((unsigned char *) qp->iph), qp->ihlen);
	ptr += qp->ihlen;
	// count应该是用来记录偏移量的
	count = 0;


	/* Copy the data portions of all fragments into the new buffer. */
	// 遍历队列中的所有碎片
	fp = qp->fragments;
	while (fp != NULL)
	{
		// 如果碎片大小为0，  或者，   碎片的偏移量过大， 则出错，释放空间，返回
		if (fp->len < 0 || fp->offset + qp->ihlen + fp->len > len)
		{
			//NETDEBUG(printk("Invalid fragment list: Fragment over size.\n"));
			nids_params.syslog(NIDS_WARN_IP, NIDS_WARN_IP_INVLIST, qp->iph, 0);
			ip_free(qp);
			//kfree_skb(skb, FREE_WRITE);
			//ip_statistics.IpReasmFails++;
			free(skb);
			return NULL;
		}
		// 否则拷贝当前碎片
		memcpy((ptr + fp->offset), fp->ptr, fp->len);
		// 长度增加(通常这个会是fp->end - fp->offset -1)
		count += fp->len;
		fp = fp->next;
	}

	
	/* We glued together all fragments, so remove the queue entry. */
	// 循环结束之后，释放当前队列--因为出列结束而释放
	ip_free(qp);

	/* Done with all fragments. Fixup the new IP header. */
	// 将最新生成的ip结构保存下来
	iph = (struct ip *) skb;
	// 偏移量初始化为0
	iph->ip_off = 0;
	// 计算长度
	iph->ip_len = htons((iph->ip_hl * 4) + count);
	// skb->ip_hdr = iph;

	// 返回生成的ip
	return (skb);
}


/* Process an incoming IP datagram fragment. */
// 每重组一个ip碎片，就会更新对应ipq的timer
//
//
static char *
ip_defrag(struct ip *iph, struct sk_buff *skb)
{
	struct ipfrag *prev, *next, *tmp;
	// 指向一个碎片
	struct ipfrag *tfp;
	// 指向一个队列
	struct ipq *qp;
	// 用来放返回值
	char *skb2;
	// 用来进行字节操作
	unsigned char *ptr;
	int flags, offset;
	int i, ihl, end;

	// 如果成功更新全局变量this_host, 并且skb是有内容的
	if (!hostfrag_find(iph) && skb)
		// 生成一个碎片
		hostfrag_create(iph);

	/* Start by cleaning up the memory. */
	// 如果当前host不为空
	if (this_host)
		// 如果大于上限
		if (this_host->ip_frag_mem > IPFRAG_HIGH_THRESH)
			// 裁剪掉一些ip碎片，直到 ip_frag_mem < IPFRAG_LOW_THRESH
			ip_evictor();

	/* Find the entry of this IP datagram in the "incomplete datagrams" queue. */
	// 如果host存在
	if (this_host)
		// 找到与这个ip头相关的ip队列
		qp = ip_find(iph);
	else
		// 否则设置队列为空
		qp = 0;
	

	/* Is this a non-fragmented datagram? */
	// ip_off是一个16位的字段，高3位用来保存标志信息，低12位用来保存当前碎片的偏移
	offset = ntohs(iph->ip_off);  /* 先把ip_offset这个字段取出来 */
	// 把高3位取出来
	flags = offset & ~IP_OFFSET;
	// 把低13位取出来
	offset &= IP_OFFSET;
	// IP_MF==0表示当前收到是碎片后面没有碎片了，并且当前收到碎片是第一个碎片，
	// 显然当前碎片虽在的ip报文仅仅有一个碎片
	// 那么当前碎片(刚刚收到的碎片)并不需要重组，因此可以返回了
	if (((flags & IP_MF) == 0) && (offset == 0))
	{
		// 如果队列不为空就释放掉
		if (qp != NULL)
			ip_free(qp);		/* Fragmented frame replaced by full unfragmented copy */
		return 0;
	}

	/* ip_evictor() could have removed all queues for the current host */
	// 如果host全部被移出了，那么重新创建一个，针对当前ip头的host
	// 但是，这个host并不会包括任何东西，它是一个空的，没有ip队列
	if (!this_host)
		hostfrag_create(iph);
	// 计算offset和头长度
	// 这个offset是刚刚收到的这个碎片的offset
	offset <<= 3;			/* offset is in 8-byte chunks */
	ihl = iph->ip_hl * 4;


	/*
	  If the queue already existed, keep restarting its timer as long as
	  we still are receiving fragments.  Otherwise, create a fresh queue
	  entry.
	*/
	// 如果队列存在
	if (qp != NULL)
	{
		/* ANK. If the first fragment is received, we should remember the correct
		   IP header (with options) */
		// 如果偏移量为0，可能是该pi报文中的第一个碎片，因此要把前8字节保存下来
		if (offset == 0)
		{
			// 保存头长度
			qp->ihlen = ihl;
			// 拷贝头信息+8字节
			memcpy(qp->iph, iph, ihl + 8);
		}
		// 停止计时
		del_timer(&qp->timer);
		// 重新计时
		qp->timer.expires = jiffies() + IP_FRAG_TIME;	/* about 30 seconds */
		// 设置关联
		qp->timer.data = (unsigned long) qp;	/* pointer to queue */
		// 注册回调函数
		qp->timer.function = ip_expire;	/* expire function */
		// 添加计数器
		add_timer(&qp->timer);
	}
	// 否则队列不存在
	else
	{
		/* If we failed to create it, then discard the frame. */
		// 试图创建一个
		if ((qp = ip_create(iph)) == NULL)
		{
			// 如果创建队列失败，那么释放当前碎片的空间并返回
			kfree_skb(skb, FREE_READ);
			return NULL;
		}
	}

	
	/* Attempt to construct an oversize packet. */
	// 如果头+长度 超长， 释放空间
	if (ntohs(iph->ip_len) + (int) offset > 65535)
	{
		// NETDEBUG(printk("Oversized packet received from %s\n", int_ntoa(iph->ip_src.s_addr)));
		nids_params.syslog(NIDS_WARN_IP, NIDS_WARN_IP_OVERSIZED, iph, 0);
		kfree_skb(skb, FREE_READ);
		return NULL;
	}

	
	/* Determine the position of this fragment. */
	// 刚刚收到的碎片分组 + 刚刚收到的碎片ip包大小 - 刚刚收到的碎片ip包头大小
	// = 刚刚收到的分组的结尾
	end = offset + ntohs(iph->ip_len) - ihl;

	/* Point into the IP datagram 'data' part. */
	// 将指针，指向刚刚收到的碎片ip包的数据开头部分
	// prt 指向肉
	ptr = (unsigned char *)(skb->data + ihl);

	/* Is this the final fragment? */
	// 如果这是最后一个碎片，那么，整个队列的长度，就是当前的end
	// 否则qp->len会在后面更改，因为会有重叠部分
	if ((flags & IP_MF) == 0)
		qp->len = end;

	/*
	  Find out which fragments are in front and at the back of us in the
	  chain of fragments so far.  We must know where to put this
	  fragment, right?
	*/
	prev = NULL;
	// 给定一个offset,在所有的fragments中找到第一个
	// 拥有不小于给定offset的offset的碎片，然后终止循环
	// 由此可以猜测，这一个函数，其实是将某一个新来的碎片插入到
	// 队列合适的位置，保证offset升序排列
	// next 指向的是第一个不小于当前offset的碎片
	// pre指向的是前一个碎片
	for (next = qp->fragments; next != NULL; next = next->next)
	{
		if (next->offset >= offset)
			break;			/* bingo! */
		prev = next;
	}
	/*--------------------------------------------------------------
	注意: 
		next 指向的是第一个排在当前碎片后面的 碎片；
		pre  指向的是第一个排在当前碎片前面的 碎片。
		next 有可能offset与当前碎片的offset一样
	----------------------------------------------------------------*/
	
	
	/*
	  We found where to put this one.  Check for overlap with preceding
	  fragment, and, if needed, align things so that any overlaps are
	  eliminated.
	*/
	// 如果有排在当前碎片前面的分组，并且， 该分组的结束比当前分组的offset大
	// 说明有重叠，应噶修正当前offset，以先来的为准
	if (prev != NULL && offset < prev->end)
	{
		nids_params.syslog(NIDS_WARN_IP, NIDS_WARN_IP_OVERLAP, iph, 0);
		i = prev->end - offset;
		// 将当前收到的碎片的offset增加i
		offset += i;		/* ptr into datagram */
		// 将当前收到的碎片的指正向后移动i
		ptr += i;			/* ptr into fragment data */
	}
	
	/*
	  Look for overlap with succeeding segments.
	  If we can merge fragments, do it.
	*/
	// 现在往后查看是否有重叠的
	// 从next开始
	for (tmp = next; tmp != NULL; tmp = tfp)
	{
		// temp总是等于next
		tfp = tmp->next;
		// 如果next的 offset >= 当前分组的end，那就没有问题
		if (tmp->offset >= end)
			break;			/* no overlaps at all */

		// 否则警报
		nids_params.syslog(NIDS_WARN_IP, NIDS_WARN_IP_OVERLAP, iph, 0);
		// 记录当前的结束与下一个碎片的开始重叠多少
		i = end - next->offset;	/* overlap is 'i' bytes */
		// 将next碎片的长度减少i
		tmp->len -= i;		/* so reduce size of    */
		// 将next碎片的开始增加i
		tmp->offset += i;		/* next fragment        */
		// 将指针也要向后移动i
		tmp->ptr += i;
		/*
		  If we get a frag size of <= 0, remove it and the packet that it
		  goes with. We never throw the new frag away, so the frag being
		  dumped has always been charged for.
		*/
		// 如果此时next碎片的长度小于0， 那么摘掉next节点
		if (tmp->len <= 0)
		{
			if (tmp->prev != NULL)
				tmp->prev->next = tmp->next;
			else
				qp->fragments = tmp->next;

			if (tmp->next != NULL)
				tmp->next->prev = tmp->prev;

			// tfp原来就等于next->next，所以原来的next节点被摘掉了
			next = tfp;		/* We have killed the original "next" frame */

			// 释放掉frag节点对应的内存
			frag_kfree_skb(tmp->skb, FREE_READ);
			// 释放掉frag节点
			frag_kfree_s(tmp, sizeof(struct ipfrag));
		}
	}

	
	/* Insert this fragment in the chain of fragments. */
	tfp = NULL;
	// offset是刚刚接收到的碎片偏移，按字节
	// end   是刚刚接收到的碎片的结束字节
	// skb   是传进来的一个内存空间，应该事先分配好
	// prt   是指向这个碎片第一个数据的指针
	tfp = ip_frag_create(offset, end, skb, ptr);
	/*---------------------------------------------------
	注意:  
		ip_frag_create函数只是创建一个ip_frag，还没有吧
		它挂载到队列中
	-----------------------------------------------------*/

	/*
	  No memory to save the fragment - so throw the lot. If we failed
	  the frag_create we haven't charged the queue.
	*/
	if (!tfp)
	{
		nids_params.no_mem("ip_defrag");
		kfree_skb(skb, FREE_READ);
		return NULL;
	}
	
	/* From now on our buffer is charged to the queues. */
	// 将刚刚创建的ip_frag挂载到队列中去了
	tfp->prev = prev;
	tfp->next = next;
	if (prev != NULL)
		prev->next = tfp;
	else
		qp->fragments = tfp;

	if (next != NULL)
		next->prev = tfp;

	/*
	  OK, so we inserted this new fragment into the chain.  Check if we
	  now have a full IP datagram which we can bump up to the IP
	  layer...
	*/
	// 检查是否完整
	if (ip_done(qp))
	{
		skb2 = ip_glue(qp);		/* glue together the fragments */
		return (skb2);
	}

	// 如果没有完整，那么返回空，继续执行
	return (NULL);
}


// 传入一个ip头 和一个 将要被修改的ip
// 返回适当的信号，说明是否有ip 碎片到来，或者是否需要调用回调函数
// 传入的defrag参数，是一个部分重组了的ip数据报
int
ip_defrag_stub(struct ip *iph, struct ip **defrag)
{
	int offset, flags, tot_len;
	struct sk_buff *skb;

	// 包数量增加
	numpack++;
	// 初始化时间
	timenow = 0;
	// 检查第一个超时计时器是否超时,超时，则进入while循环
	// 为什么只是第一个计时器?
	// 因为新的计时器总是在链表尾加入的，所以前面的一定先超时
	while (timer_head && timer_head->expires < jiffies())
	{
		// 将这个超时计时器对应的host加载到this_host全局变量中
		this_host = ((struct ipq *) (timer_head->data))->hf;
		// 执行回调函数，这个回调函数是:
		// ip_expire， 参数是到期了的ip队列，然后把ip队列删除
		timer_head->function(timer_head->data);
	}

	// 获得16为的标志信息位
	offset = ntohs(iph->ip_off);
	// 高3位是分组标志
	flags = offset & ~IP_OFFSET;
	// 低13位是当前ip分组的偏移量，8字节为单位
	offset &= IP_OFFSET;

	// 如果没有更多分组，并且是第一个分组，说明本ip只有一个碎片
	if (((flags & IP_MF) == 0) && (offset == 0))
	{
		// 不需要缓存
		ip_defrag(iph, 0);
		// 直接调用nofiy通知回调
		return IPF_NOTF;
	}

	// 否则是一个正常碎片， 继续往下执行

	// 刚刚收到的ip的总长度
	tot_len = ntohs(iph->ip_len);
	// 申请一块空间
	// 大小为 ip分组长度 + sk_buff大小，后面的sk_buff空间用来作为
	// ip_defrag函数的第二个参数
	skb = (struct sk_buff *) malloc(tot_len + sizeof(struct sk_buff));
	if (!skb)
		nids_params.no_mem("ip_defrag_stub");
	// skb的data段指向自己的开头+sizeof(struct sk_buff)字节
	// 也就是指向自己后面一个sk_buff空间，这就是为什么它多申请了一个sk_buff空间
	skb->data = (char *) (skb + 1);
	// 将ip分组拷贝到这里，应该是整个ip分组的长度
	memcpy(skb->data, iph, tot_len);
	// 总长度 + 16 + sk_buff保留长度
	skb->truesize = tot_len + 16 + nids_params.dev_addon;
	// +15 然后除以16
	skb->truesize = (skb->truesize + 15) & ~15;
	// + sk_buff的大小，默认为168
	skb->truesize += nids_params.sk_buff_size;

	// 关于ip_defrag 的两个参数
	// 其实是两块相邻的空间， skb->data指向的是skb后一个skb
	// 应该返回一个整理好的碎片组
	if ((*defrag = (struct ip *)ip_defrag((struct ip *) (skb->data), skb)))
		// 如果成功，返回: 有新ip碎片到来
		return IPF_NEW;

	// 否则返回其他，出错
	return IPF_ISF;
}


// 创建hash表
void
ip_frag_init(int n)
{
	struct timeval tv;

	// 获得当前时间
	gettimeofday(&tv, 0);
	// time0 初始化为ip_frag_init调用的时间，单位:秒
	time0 = tv.tv_sec;
	// 初始化hash表，
	// calloc分配空间后，将内容填充为0
	fragtable = (struct hostfrags **) calloc(n, sizeof(struct hostfrags *));
	// 如果失败
	if (!fragtable)
		nids_params.no_mem("ip_frag_init");
	// 否则设置全局变量
	hash_size = n;
}


// 释放hash表
void
ip_frag_exit(void)
{
	// 直接将hash表的空间释放了，其中的指针结构，需要先释放
	// 那些工作在其他地方完成了
	if (fragtable)
	{
		free(fragtable);
		fragtable = NULL;
	}
	/* FIXME: do we need to free anything else? */
}
