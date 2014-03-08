/*
  Copyright (c) 1999 Rafal Wojtczuk <nergal@7bulls.com>. All rights reserved.
  See the file COPYING for license details.
*/

#include<pthread.h>
#include <config.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <alloca.h>
#include <pcap.h>
#include <errno.h>
#include <config.h>

//#if (HAVE_UNISTD_H)
#include <unistd.h>
#include <stdio.h>
//#endif

#include "checksum.h"
#include "ip_fragment.h"
#include "scan.h"
#include "tcp.h"
#include "util.h"
#include "nids.h"

// add: 2014-2-22
// B-Queue
//#define CONS_BATCH
//#define PROD_BATCH
#include "fifo.h"
#define TEST_SIZE 20000

struct queue_t *fifo_queue;
ELEMENT_TYPE inputelement;
ELEMENT_TYPE outputelement;
static unsigned long inputcount;
static unsigned long outputcount;
static long discardcount;

// end add


#ifdef HAVE_LIBGTHREAD_2_0
#include <glib.h>
#endif

#ifdef __linux__
extern int set_all_promisc();
#endif

#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))

#define FIFO_MAX 32

//add: 2014 1 25
//#define _GNU_SOURCE

//#include<string.h>
//#include<sys/sem.h>
#include<semaphore.h>
//#include<sys/types.h>
//#include<sys/sysinfo.h>
//#include<sched.h>
//#include<ctype.h>
//#include<sys/syscall.h>
//end add

//newadd 2014 2 18

int coreNum=0;

//end newadd

// Íâ²¿º¯Êý
extern int ip_options_compile(unsigned char *);
extern int raw_init();
// ÄÚ²¿º¯Êý
static void nids_syslog(int, int, struct ip *, void *);
static int nids_ip_filter(struct ip *, int);
// ÄÚ²¿º¯ÊýÖžÕë
static struct proc_node *ip_frag_procs;
static struct proc_node *ip_procs;
static struct proc_node *udp_procs;
// Íâ²¿¿ÉŒûº¯ÊýÖžÕë
struct proc_node *tcp_procs;
static int linktype;
static pcap_t *desc = NULL;

// modified
static struct nids_fifo *fifo;
static int tcp_put = 0;
static int tcp_get = 0;
// modified 2014-01-26


#ifdef HAVE_LIBGTHREAD_2_0

/* async queue for multiprocessing - mcree */
static GAsyncQueue *cap_queue;

/* items in the queue */
struct cap_queue_item
{
	void *data;
	bpf_u_int32 caplen;
};

/* marks end of queue */
static struct cap_queue_item EOF_item;

/* error buffer for glib calls */
static GError *gerror = NULL;

#endif

char nids_errbuf[PCAP_ERRBUF_SIZE];
// pcap_pkthdrÊÇÒ»žöÊýŸÝÁŽÂ·²ãÖ¡Í·œá¹¹
// ²Î¿Œ:http://blog.csdn.net/yaneng/article/details/4315516
// »òÕß:http://blog.sina.com.cn/s/blog_94d26ea60100w3kt.html
struct pcap_pkthdr * nids_last_pcap_header = NULL;
// ÖžÏò×îÐÂµÄpcap°ü
u_char *nids_last_pcap_data = NULL;
u_int nids_linkoffset = 0;

char *nids_warnings[] =
{
	"Murphy - you never should see this message !",
	"Oversized IP packet",
	"Invalid IP fragment list: fragment over size",
	"Overlapping IP fragments",
	"Invalid IP header",
	"Source routed IP frame",
	"Max number of TCP streams reached",
	"Invalid TCP header",
	"Too much data in TCP receive queue",
	"Invalid TCP flags"
};

// ÕâÀï¶šÒåÒ»žö nids_params±äÁ¿£¬ÆäËûÎÄŒþÒ²ÊÇ¿ÉŒûµÄ¡£
struct nids_prm nids_params =
{
	1040,			/* n_tcp_streams */
	256,			/* n_hosts */
	NULL,			/* device */
	"tracefile.pcap",			/* filename */
	168,			/* sk_buff_size */
	-1,				/* dev_addon */
	nids_syslog,		/* syslog() */
	LOG_ALERT,			/* syslog_level */
	256,			/* scan_num_hosts */
	3000,			/* scan_delay */
	10,				/* scan_num_ports */
	nids_no_mem,		/* no_mem() */
	nids_ip_filter,		/* ip_filter() */
	NULL,			/* pcap_filter */
	1,				/* promisc */
	0,				/* one_loop_less */
	1024,			/* pcap_timeout */
	0,				/* multiproc */
	20000,			/* queue_limit */
	0,				/* tcp_workarounds */
	NULL,			/* pcap_desc */
	0,			        /* tcp_flow_timeout */
};





// Ž«ÈëÒ»žöipÊýŸÝœá¹¹£¬Ž«ÈëÒ»žöip·Ö×éµÄ³€¶È
// ÕâÒ»žöº¯ÊýÃ»ÓÐÊµÏÖÈÎºÎ¹ŠÄÜ
// ×ÜÊÇ·µ»Ø1
static int nids_ip_filter(struct ip *x, int len)
{
	(void)x;
	(void)len;
	return 1;
}

// ÕâÊÇÒ»žöÈÕÖŸ¹ÜÀíº¯Êý
static void nids_syslog(int type, int errnum, struct ip *iph, void *data)
{
	char saddr[20], daddr[20];
	char buf[1024];
	struct host *this_host;
	unsigned char flagsand = 255, flagsor = 0;
	int i;

	switch (type)
	{

	case NIDS_WARN_IP:
		if (errnum != NIDS_WARN_IP_HDR)
		{
			strcpy(saddr, int_ntoa(iph->ip_src.s_addr));
			strcpy(daddr, int_ntoa(iph->ip_dst.s_addr));
			syslog(nids_params.syslog_level,
			       "%s, packet (apparently) from %s to %s\n",
			       nids_warnings[errnum], saddr, daddr);
		}
		else
			syslog(nids_params.syslog_level, "%s\n",
			       nids_warnings[errnum]);
		break;

	case NIDS_WARN_TCP:
		strcpy(saddr, int_ntoa(iph->ip_src.s_addr));
		strcpy(daddr, int_ntoa(iph->ip_dst.s_addr));
		if (errnum != NIDS_WARN_TCP_HDR)
			syslog(nids_params.syslog_level,
			       "%s,from %s:%hu to  %s:%hu\n", nids_warnings[errnum],
			       saddr, ntohs(((struct tcphdr *) data)->th_sport), daddr,
			       ntohs(((struct tcphdr *) data)->th_dport));
		else
			syslog(nids_params.syslog_level, "%s,from %s to %s\n",
			       nids_warnings[errnum], saddr, daddr);
		break;

	case NIDS_WARN_SCAN:
		this_host = (struct host *) data;
		sprintf(buf, "Scan from %s. Scanned ports: ",
		        int_ntoa(this_host->addr));
		for (i = 0; i < this_host->n_packets; i++)
		{
			strcat(buf, int_ntoa(this_host->packets[i].addr));
			sprintf(buf + strlen(buf), ":%hu,",
			        this_host->packets[i].port);
			flagsand &= this_host->packets[i].flags;
			flagsor |= this_host->packets[i].flags;
		}
		if (flagsand == flagsor)
		{
			i = flagsand;
			switch (flagsand)
			{
			case 2:
				strcat(buf, "scan type: SYN");
				break;
			case 0:
				strcat(buf, "scan type: NULL");
				break;
			case 1:
				strcat(buf, "scan type: FIN");
				break;
			default:
				sprintf(buf + strlen(buf), "flags=0x%x", i);
			}
		}
		else
			strcat(buf, "various flags");
		syslog(nids_params.syslog_level, "%s", buf);
		break;

	default:
		syslog(nids_params.syslog_level, "Unknown warning number ?\n");
	}
}


/* called either directly from pcap_hand() or from cap_queue_process_thread()
 * depending on the value of nids_params.multiproc - mcree
 */

static void call_ip_frag_procs(void *data,bpf_u_int32 caplen)
{
	struct proc_node *i;
	for (i = ip_frag_procs; i; i = i->next)
		(i->item) (data, caplen);
}


/* wireless frame types, mostly from tcpdump (wam) */
#define FC_TYPE(fc)             (((fc) >> 2) & 0x3)
#define FC_SUBTYPE(fc)          (((fc) >> 4) & 0xF)
#define DATA_FRAME_IS_QOS(x)    ((x) & 0x08)
#define FC_WEP(fc)              ((fc) & 0x4000)
#define FC_TO_DS(fc)            ((fc) & 0x0100)
#define FC_FROM_DS(fc)          ((fc) & 0x0200)
#define T_MGMT 0x0		/* management */
#define T_CTRL 0x1		/* control */
#define T_DATA 0x2		/* data */
#define T_RESV 0x3		/* reserved */
#define EXTRACT_LE_16BITS(p) \
	((unsigned short)*((const unsigned char *)(p) + 1) << 8 | \
	(unsigned short)*((const unsigned char *)(p) + 0))
#define EXTRACT_16BITS(p)	((unsigned short)ntohs(*(const unsigned short *)(p)))
#define LLC_FRAME_SIZE 8
#define LLC_OFFSET_TO_TYPE_FIELD 6
#define ETHERTYPE_IP 0x0800


// Õâžöº¯ÊýÓŠžÃÊÇpcapœÓÊÕµœÒ»žö°üÖ®ºó£¬»Øµ÷µÄº¯Êý
// Ã»ÓÐŒÓstaticËùÒÔ£¬ÊÇÒ»žöÍâ²¿¿ÉŒûµÄº¯Êý
/*
	ÕâÒ»žöº¯Êý£¬ÓŠžÃÊÇpcapµÄ»Øµ÷º¯Êý£¬
	Ã¿µ±pcap×¥µœÒ»žö°üÖ®ºó£¬ŸÍ»á»Øµ÷Õâžöº¯Êý
*/
void nids_pcap_handler(u_char * par, struct pcap_pkthdr *hdr, u_char * data)
{


	u_char *data_aligned;
#ifdef HAVE_LIBGTHREAD_2_0
	struct cap_queue_item *qitem;
#endif
#ifdef DLT_IEEE802_11
	unsigned short fc;
	int linkoffset_tweaked_by_prism_code = 0;
	int linkoffset_tweaked_by_radio_code = 0;
#endif

	/*
	 * Check for savagely closed TCP connections. Might
	 * happen only when nids_params.tcp_workarounds is non-zero;
	 * otherwise nids_tcp_timeouts is always NULL.
	 */
	// Ê×ÏÈŒì²éÊÇ·ñÓÐtcp³¬Ê±
	if (NULL != nids_tcp_timeouts)
		tcp_check_timeouts(&hdr->ts);

	// œ«Ž«œøÀŽµÄÊýŸÝÁŽÂ·°üÍ·ž³ÖµžøÈ«ŸÖµÄ×îÐÂpcap°üÍ·œá¹¹ÌåÖžÕë
	// ip_fragment.cÖÐµÄipŽŠÀíº¯Êý
	nids_last_pcap_header = hdr;
	// ÕâÊÇpcap²¶»ñµÄdata£¬ž³ÖµžøÈ«ŸÖÖžÕë
	nids_last_pcap_data = data;

	// ÕâÒ»žö±äÁ¿Ã»ÓÐÊ¹ÓÃ£¬ÒÔºóÀ©Õ¹
	(void)par; /* warnings... */


	// žùŸÝÁŽœÓÀàÐÍœøÐÐŽŠÀí
	switch (linktype)
	{
		// 10MB
	case DLT_EN10MB:
		// Èç¹û²¶»ñµÄ°ü³€¶È<14 (14ÊÇÊýŸÝÁŽÂ·°üÍ·ŽóÐ¡)£¬ÄÇÃŽ²»ÊÇÒ»žöÍêÕûµÄÊýŸÝÁŽÂ·°ü
		// ²Î¿Œ: 2013ÄêÍõµÀÍøÂç95Ò³
		// ²Î¿Œ: http://blog.csdn.net/yaneng/article/details/4315516
		if (hdr->caplen < 14)
			return;

		/* Only handle IP packets and 802.1Q VLAN tagged packets below. */
		// ÕâÁœžö×ÖœÚÕýºÃÊÇtype×Ö¶Î
		// ²Î¿Œ: 2013ÄêÍõµÀÍøÂç95Ò³
		if (data[12] == 8 && data[13] == 0)
		{
			/* Regular ethernet */
			// ÐÞžÄÊýŸÝÁŽÂ·²ãµÄÊýŸÝÆ«ÒÆ£¬±ê×ŒµÄÒÔÌ«ÍøÍ·ŽóÐ¡ÊÇ14B
			nids_linkoffset = 14;
		}
		// ²Î¿Œ:http://baike.baidu.com/link?url=vxhfREoPvIFmDDMvrGnsxEbOXbYmVDuD_kgColXq_gny7opbqII1M1b7-3hR1Vi1ORar1TcRi3XG9RxW0-PvVa#2
		else if (data[12] == 0x81 && data[13] == 0)
		{
			/* Skip 802.1Q VLAN and priority information */
			// 802.1q°üÍ·ŽóÐ¡Îª18×ÖœÚ
			nids_linkoffset = 18;
		}
		else
			/* non-ip frame */
			return;
		break;

#ifdef DLT_PRISM_HEADER
#ifndef DLT_IEEE802_11
#error DLT_PRISM_HEADER is defined, but DLT_IEEE802_11 is not ???
#endif
	case DLT_PRISM_HEADER:
		//sizeof(prism2_hdr);
		nids_linkoffset = 144;
		linkoffset_tweaked_by_prism_code = 1;
		//now let DLT_IEEE802_11 do the rest
#endif
#ifdef DLT_IEEE802_11_RADIO
	case DLT_IEEE802_11_RADIO:
		// just get rid of the radio tap header
		if (!linkoffset_tweaked_by_prism_code)
		{
			nids_linkoffset = EXTRACT_LE_16BITS(data + 2); // skip radiotap header
			linkoffset_tweaked_by_radio_code = 1;
		}
		//now let DLT_IEEE802_11 do the rest
#endif
#ifdef DLT_IEEE802_11
	case DLT_IEEE802_11:
		/* I don't know why frame control is always little endian, but it
		 * works for tcpdump, so who am I to complain? (wam)
		 */
		if (!linkoffset_tweaked_by_prism_code && !linkoffset_tweaked_by_radio_code)
			nids_linkoffset = 0;
		fc = EXTRACT_LE_16BITS(data + nids_linkoffset);
		if (FC_TYPE(fc) != T_DATA || FC_WEP(fc))
		{
			return;
		}
		if (FC_TO_DS(fc) && FC_FROM_DS(fc))
		{
			/* a wireless distribution system packet will have another
			 * MAC addr in the frame
			 */
			nids_linkoffset += 30;
		}
		else
		{
			nids_linkoffset += 24;
		}
		if (DATA_FRAME_IS_QOS(FC_SUBTYPE(fc)))
			nids_linkoffset += 2;
		if (hdr->len < nids_linkoffset + LLC_FRAME_SIZE)
			return;
		if (ETHERTYPE_IP !=
		        EXTRACT_16BITS(data + nids_linkoffset + LLC_OFFSET_TO_TYPE_FIELD))
		{
			/* EAP, LEAP, and other 802.11 enhancements can be
			 * encapsulated within a data packet too.  Look only at
			 * encapsulated IP packets (Type field of the LLC frame).
			 */
			return;
		}
		nids_linkoffset += LLC_FRAME_SIZE;
		break;
#endif
	default:
		;
	}

	/*-------------------------------------------------------------
	ÖÁŽË£¬ÁŽœÓÀàÐÍÒÑŸ­ÅÐ¶ÏÍê±Ï£¬Ö÷ÒªÐÞžÄÁË likeoffsetÕâžöÈ«ŸÖ±äÁ¿
	-------------------------------------------------------------*/
	// Èç¹û²¶»ñµÄŽóÐ¡£¬±ÈÍ·»¹ÒªÐ¡£¬ÄÇÃŽÏÔÈ»ÊÇŽíÎóµÄ£¬Ö±œÓ·µ»Ø
	if (hdr->caplen < nids_linkoffset)
		return;
	// ·ñÔòŒÌÐøÍùÏÂÖŽÐÐ£¬¿ªÊŒŽŠÀíÕâžö°ü--Íš³£µÄÊÖ¶ÎŸÍÊÇ±£ŽæÏÂÀŽ



	/*
	* sure, memcpy costs. But many EXTRACT_{SHORT, LONG} macros cost, too.
	* Anyway, libpcap tries to ensure proper layer 3 alignment (look for
	* handle->offset in pcap sources), so memcpy should not be called.
	*/
#ifdef LBL_ALIGN
	// Èç¹ûÊÇ4µÄÆæÊý±¶£¬ŸÍÖŽÐÐÏÂÃæµÄif
	if ((unsigned long) (data + nids_linkoffset) & 0x3)
	{
		data_aligned = alloca(hdr->caplen - nids_linkoffset + 4);
		data_aligned -= (unsigned long) data_aligned % 4;
		memcpy(data_aligned, data + nids_linkoffset, hdr->caplen - nids_linkoffset);
	}
	else
#endif
		// Èç¹ûÃ»ÓÐ¶šÒåÉÏÃæµÄ Ô€±àÒë£¬ÄÇÃŽ
		// ÎÞÂÛÈçºÎ¶Œ»áÖŽÐÐÏÂÃæÕâÌõÓïŸä
		// Èç¹û¶šÒå¶øÀŽÉÏÃæµÄ Ô€±àÒë£¬ÄÇÃŽ
		// Ö»ÓÐÔÚlinkoffsetÎª4µÄÅŒÊý±¶µÄÊ±ºò£¬²Å»áÖŽÐÐÏÂÃæÕâÌõÓïŸä
		data_aligned = data + nids_linkoffset;

#ifdef HAVE_LIBGTHREAD_2_0
	// Èç¹ûÊÇ¶àÏß³ÌµÄ
	if(nids_params.multiproc)
	{
		/*
		 * Insert received fragment into the async capture queue.
		 * We hope that the overhead of memcpy
		 * will be saturated by the benefits of SMP - mcree
		 */
		// ÉêÇëÒ»¿é¿ÕŒä£¬œ«²¶»ñµÄÄÚÈÝ±£ŽæÆðÀŽ
		qitem=malloc(sizeof(struct cap_queue_item));
		// Èç¹ûÉêÇë³É¹Š£¬²¢ÇÒitemµÄdataÒ²ÉêÇë³É¹Š£¬ÔòÖŽÐÐif
		if (qitem && (qitem->data=malloc(hdr->caplen - nids_linkoffset)))
		{
			// ŒÇÂŒitemµÄ³€¶È(³öÈ¥ÊýŸÝÁŽÂ·°üÍ·)
			qitem->caplen=hdr->caplen - nids_linkoffset;
			// ×¢Òâ: data_aligned ÊÇŸ­¹ý¶ÔÆëÁËµÄÊýŸÝ
			// ¿œ±ŽÊýŸÝÁŽÂ·°üµÄÄÚÈÝ£¬µœitemµÄdataÖÐ
			memcpy(qitem->data,data_aligned,qitem->caplen);
			/*-------------------------------------------------------
			ŒÓËø×Œ±žŽŠÀíqueueÖÐµÄÄÚÈÝ
			---------------------------------------------------------*/
			g_async_queue_lock(cap_queue);
			/* ensure queue does not overflow */
			// Èç¹ûŽóÓÚ¶ÓÁÐµÄ×îŽóÏÞÖÆ
			if(g_async_queue_length_unlocked(cap_queue) > nids_params.queue_limit)
			{
				/* queue limit reached: drop packet - should we notify user via syslog? */
				// ¶ªÆúžÕžÕÉêÇëµÄÄÚÈÝ
				// ¿ÉÒÔÓÅ»¯µÄµØ·œ: ÏÈÅÐ¶Ï£¬ÔÙÉêÇë£¬²»ÒªŒ±×ÅÉêÇë£¬È»ºóÊÍ·Å
				// µ«ÊÇ¿ÉÄÜŒÓËøµÄµØ·œ»á±ÈœÏŽó£¬Ó°ÏìÐ§ÂÊ£¬ÕâÀïÏÈ·Å×Å
				free(qitem->data);
				free(qitem);
			}
			else
			{
				/* insert packet to queue */
				// ŒÓÈë¶ÓÁÐ
				g_async_queue_push_unlocked(cap_queue,qitem);
			}
			g_async_queue_unlock(cap_queue);
			/*-------------------------------------------------------
			ŽŠÀíÍêqueueÖÐµÄÄÚÈÝ£¬œâËø
			---------------------------------------------------------*/
		}
		// Èç¹ûÉêÇëÊ§°Ü£¬Ê²ÃŽ¶Œ²»×ö
		// ÎÒÈÏÎªÐèÒªÅÐ¶ÏÒ»ÏÂ£¬ÊÇ·ñÓŠžÃÊÍ·Åqitem !!!
	}
	// ·ñÔòÊÇÓÃ»§ÒªÇóµ¥œø³Ì
	else     /* user requested simple passthru - no threading */
	{
		// Ö±œÓŽŠÀíipËéÆ¬
		call_ip_frag_procs(data_aligned,hdr->caplen - nids_linkoffset);
	}
#else
	// ·ñÔòÖ±œÓŸÍÊÇµ¥œø³Ì(Ïß³Ì)
	call_ip_frag_procs(data_aligned,hdr->caplen - nids_linkoffset);
#endif
}

// Éú³ÉIP Æ¬¶Î
// Õâžöº¯Êý»á±»nids_pcap_handlerº¯Êýµ÷ÓÃ
// nids_pcap_handlerÓŠžÃÊÇÒ»žöpcapµÄ»Øµ÷º¯Êý£¬Ã¿µ±ÓÐÒ»žöÊýŸÝÁŽÂ·²ãµÄ°ü
// ±»pcap²¶»ñ£¬ŸÍ»á»Øµ÷nids_pcap_handler(Õâžöº¯ÊýµÄ¶šÒåŸÍÔÚÉÏÃæ)
static void gen_ip_frag_proc(u_char * data, int len)
{
	struct proc_node *i;
	struct ip *iph = (struct ip *) data;
	int need_free = 0;
	int skblen;
	// ¶šÒåÒ»žöÖžÏòº¯ÊýµÄÖžÕë
	void (*glibc_syslog_h_workaround)(int, int, struct ip *, void*)=
	    nids_params.syslog;

	if (!nids_params.ip_filter(iph, len))
		return;

	if (len < (int)sizeof(struct ip) || iph->ip_hl < 5 || iph->ip_v != 4 ||
	        ip_fast_csum((unsigned char *) iph, iph->ip_hl) != 0 ||
	        len < ntohs(iph->ip_len) || ntohs(iph->ip_len) < iph->ip_hl << 2)
	{
		glibc_syslog_h_workaround(NIDS_WARN_IP, NIDS_WARN_IP_HDR, iph, 0);
		return;
	}
	if (iph->ip_hl > 5 && ip_options_compile((unsigned char *)data))
	{
		glibc_syslog_h_workaround(NIDS_WARN_IP, NIDS_WARN_IP_SRR, iph, 0);
		return;
	}

	// ipÖØ×é
	// ÔÚip_defrag_stubÖÐ»¹»áµ÷ÓÃ
	// Ã¿µ±ÓÐÒ»žöÊýŸÝÁŽÂ·²ãµÄ°ü¹ýÀŽ£¬¶Œ»áŸ­¹ýÕâÀï£¬œ«ÕâžöÊýŸÝÁŽÂ·²ã
	// µÄ°ü£¬×é×°³Éip±šÎÄ
	switch (ip_defrag_stub((struct ip *) data, &iph))
	{
		// ³öŽí£¬·µ»Ø
	case IPF_ISF:
		return;
		// »¹Ã»ÓÐ×é³ÉÒ»žöÍêÕûµÄip±šÎÄ£¬ÐèÒªžü¶àµÄipËéÆ¬
	case IPF_NOTF:
		need_free = 0;
		iph = (struct ip *) data;
		break;
		// ÒÑŸ­×é³ÉÁËÒ»žöÍêÕûµÄip±šÎÄ£¬¿ÉÒÔÊÍ·Å¿ÕŒäÁË
	case IPF_NEW:
		need_free = 1;
		break;
	default:
		;
	}

	// ip°ü³€¶È+16
	skblen = ntohs(iph->ip_len) + 16;
	// Èç¹û²»ÐèÒªÊÍ·Å£¬ÄÇÃŽŒÌÐøÐÞžÄµ±Ç°skbµÄ³€¶È£¬°ÑžÕžÕ»ñµÃµÄ°üÌíŒÓœøÀŽ
	if (!need_free)
		skblen += nids_params.dev_addon;
	// ÕâÊÇÒ»žö+15È»ºóÇóÃþµÄ²Ù×÷£¬mod 16
	skblen = (skblen + 15) & ~15;
	skblen += nids_params.sk_buff_size;

	// Ñ­»·µ÷ÓÃËùÓÐÒÑŸ­±»×¢²á¹ýÁËµÄ£¬ŽŠÀí¹ØÓÚIPµÄº¯Êý
	for (i = ip_procs; i; i = i->next)
		(i->item) (iph, skblen);
	// Èç¹ûÐèÒªÊÍ·Å£¬ÄÇÃŽ»ØµœÓÃfreeº¯Êý
	///////////////////if (need_free)
	/////////////////////	free(iph);
}

#if HAVE_BSD_UDPHDR
#define UH_ULEN uh_ulen
#define UH_SPORT uh_sport
#define UH_DPORT uh_dport
#else
#define UH_ULEN len
#define UH_SPORT source
#define UH_DPORT dest
#endif


static void process_udp(char *data)
{
	struct proc_node *ipp = udp_procs;
	struct ip *iph = (struct ip *) data;
	struct udphdr *udph;
	struct tuple4 addr;
	int hlen = iph->ip_hl << 2;
	int len = ntohs(iph->ip_len);
	int ulen;
	if (len - hlen < (int)sizeof(struct udphdr))
		return;
	udph = (struct udphdr *) (data + hlen);
	ulen = ntohs(udph->UH_ULEN);
	if (len - hlen < ulen || ulen < (int)sizeof(struct udphdr))
		return;
	/* According to RFC768 a checksum of 0 is not an error (Sebastien Raveau) */

	// ÕâÀïœøÐÐÁËudpµÄchecksum
	if (udph->uh_sum && my_udp_check
	        ((void *) udph, ulen, iph->ip_src.s_addr,
	         iph->ip_dst.s_addr)) return;
	// Ÿ­¹ýÁËÉÏÃæµÄcheckŒì²é£¬Èç¹ûÃ»ÓÐÎÊÌâ£¬ŸÍ»áÖŽÐÐÏÂÃæÕâÐ©ÓïŸä
	addr.source = ntohs(udph->UH_SPORT);
	addr.dest = ntohs(udph->UH_DPORT);
	addr.saddr = iph->ip_src.s_addr;
	addr.daddr = iph->ip_dst.s_addr;

	// ÕâžöºÍÉÏÃæÒ»žöº¯ÊýµÄforÑ­»·ÊÇµÈŒÛµÄ
	// ±éÀúËùÓÐÒÑŸ­×¢²áµÄupdŽŠÀíº¯Êý£¬È»ºóœøÐÐŽŠÀí
	while (ipp)
	{
		ipp->item(&addr, ((char *) udph) + sizeof(struct udphdr),
		          ulen - sizeof(struct udphdr), data);
		ipp = ipp->next;
	}
}


// modified
// This is mostly like consumer.
static void nids_function()
{

	ELEMENT_TYPE current;

	while(1)
	{

		// The only thing we need to do is dequeue
		if (SUCCESS == dequeue(fifo_queue, &current))
		{
			process_tcp((u_char*)(current.data), current.skblen);
			// release this element
			// FIXME: I think it would be batter to release element
			// after process_tcp otherwise producer would risk reusing
			// this buffer before it is read for the next tcp datagram.


			/****
			ȫ�ֱ���
			****/
			outputcount ++;
			printf("\ntcp dequeue! output = %d\n", outputcount);
		}
		// buffer is empty
		else
		{
			// do nothing.
			while(SUCCESS != dequeue(fifo_queue, &current))
			{
				sleep(1);
			}
			//printf("\nqueue is empty! \n");
		}
	}
}
// end - 2014-01-25



// ×îÖÕip·Ö×éÉú³Éº¯Êý
// modified 2014-01-25
static void gen_ip_proc(u_char * data, int skblen)
{
	struct ip *iph;
	signed int temp;
	iph = (struct ip *) data;

	switch (iph->ip_p)
	{
		// Èç¹ûÉÏ²ãÊÇTCPÄÇÃŽŸÍµ÷ÓÃTCPŽŠÀíº¯Êý
	case IPPROTO_TCP:
		// Actually, this procedure will be called loopedly
		// so we don't need a while here.
		
		if (SUCCESS == enqueue(fifo_queue, (char*)iph, skblen))
		{
			// it means buffer is not totally full yet if success
			inputcount++;
			printf("\ntcp enqueue!, input = %d\n", inputcount);
		}
		else
		{
			// wait untill equeue successfully
			while(SUCCESS != enqueue(fifo_queue, (char*)iph, skblen))
			{
				sleep(1);
			}
			//printf("%d discarded!\n", discardcount);
			//discardcount ++;
			
		}
		
		break;
		// Èç¹ûÉÏ²ãÊÇUDPÄÇÃŽŸÍµ÷ÓÃUDPŽŠÀíº¯Êý
	case IPPROTO_UDP:
		process_udp((char *)data);
		break;
		// Èç¹ûÊÇICMP ...
	case IPPROTO_ICMP:
		if (nids_params.n_tcp_streams)
			process_icmp(data);
		break;
		// ·ñÔòÊ²ÃŽÒ²²»×ö
	default:
		break;
	}
}

// ³õÊŒ»¯ËùÓÐµÄ×¢²áŽŠÀíº¯Êý
static void init_procs()
{
	// ÉêÇëÒ»žö¿ÕŒä
	ip_frag_procs = mknew(struct proc_node);
	// ³õÊŒ»¯¿ÕŒäÖÐµÄitemÓò
	ip_frag_procs->item = gen_ip_frag_proc;
	// ³õÊŒ»¯¿ÕŒäÖÐµÄnextÓò
	ip_frag_procs->next = 0;

	// ÉêÇëÒ»žö¿ÕŒä
	ip_procs = mknew(struct proc_node);
	ip_procs->item = gen_ip_proc;
	ip_procs->next = 0;

	// ÕâÁœžöº¯Êý¶ŒÃ»ÓÐ×¢²á
	tcp_procs = 0;
	// Õâžöº¯ÊýÃ»ÓÐ×¢²á£¬ÔÚnids_register_udpÖÐ×¢²á(ŒûÏÂÃæ)
	udp_procs = 0;
}


void nids_register_udp(void (*x))
{
	register_callback(&udp_procs, x);
}

void nids_unregister_udp(void (*x))
{
	unregister_callback(&udp_procs, x);
}

void nids_register_ip(void (*x))
{
	register_callback(&ip_procs, x);
}

void nids_unregister_ip(void (*x))
{
	unregister_callback(&ip_procs, x);
}

void nids_register_ip_frag(void (*x))
{
	register_callback(&ip_frag_procs, x);
}

void nids_unregister_ip_frag(void (*x))
{
	unregister_callback(&ip_frag_procs, x);
}

static int open_live()
{
	char *device;
	int promisc = 0;

	if (nids_params.device == NULL)
		nids_params.device = pcap_lookupdev(nids_errbuf);
	if (nids_params.device == NULL)
		return 0;

	device = nids_params.device;
	if (!strcmp(device, "all"))
		device = "any";
	else
		promisc = (nids_params.promisc != 0);

	if ((desc = pcap_open_live(device, 16384, promisc,
	                           nids_params.pcap_timeout, nids_errbuf)) == NULL)
		return 0;
#ifdef __linux__
	if (!strcmp(device, "any") && nids_params.promisc
	        && !set_all_promisc())
	{
		nids_errbuf[0] = 0;
		strncat(nids_errbuf, strerror(errno), sizeof(nids_errbuf) - 1);
		return 0;
	}
#endif
	if (!raw_init())
	{
		nids_errbuf[0] = 0;
		strncat(nids_errbuf, strerror(errno), sizeof(nids_errbuf) - 1);
		return 0;
	}
	return 1;
}

#ifdef HAVE_LIBGTHREAD_2_0

#define START_CAP_QUEUE_PROCESS_THREAD() \
    if(nids_params.multiproc) { /* threading... */ \
	 if(!(g_thread_create_full((GThreadFunc)cap_queue_process_thread,NULL,0,FALSE,TRUE,G_THREAD_PRIORITY_LOW,&gerror))) { \
	    strcpy(nids_errbuf, "thread: "); \
	    strncat(nids_errbuf, gerror->message, sizeof(nids_errbuf) - 8); \
	    return 0; \
	 }; \
    }

#define STOP_CAP_QUEUE_PROCESS_THREAD() \
    if(nids_params.multiproc) { /* stop the capture process thread */ \
	 g_async_queue_push(cap_queue,&EOF_item); \
    }


/* thread entry point
 * pops capture queue items and feeds them to
 * the ip fragment processors - mcree
 */
// Õâžöº¯Êýœ«»áÊÇÄ³Ò»žöthreadµÄÈë¿Úµã£¬
// Õâžöº¯ÊýÍê³ÉµÄ¹ŠÄÜÊÇ£¬»ñÈ¡queueÖÐµÄitemsÈ»ºó°ÑÕâÐ©itemsËÍžøËéÆ¬ŽŠÀíÕß
static void cap_queue_process_thread()
{
	struct cap_queue_item *qitem;

	while(1)   /* loop "forever" */
	{
		// Ê¹ÓÃÁËÒ»žöËø»úÖÆ£¬±£Ö€ÁËŽÓcap_queueÖÐ»ñÈ¡ÕýÈ·µÄÊýŸÝ
		qitem=g_async_queue_pop(cap_queue);

		// Èç¹ûœáÊøÁË£¬ÄÇÃŽŸÃÍË³öÑ­»·
		if (qitem==&EOF_item) break; /* EOF item received: we should exit */

		// ·ñÔòÊ×ÏÈ±»µ÷ÓÃµÄÊÇ call_ip_frag_procs£¬
		// call_ip_frag_procsÊÇÑ­»·µÄµ÷ÓÃ ip_frag_procsÁŽ±íÖÐµÄËùÓÐº¯Êý£¬
		// ip_frag_procsÁŽ±íµÄ×îºóÒ»ÏîÊÇ gen_ip_frag_procº¯Êý
		// ÓÃ»§ÌíŒÓµÄ×Ô¶šÒåº¯Êý£¬¶Œ»áŽÓip_frag_procsÁŽ±íÍ·ŒÓÈë
		// gen_ip_frag_procº¯ÊýÊÇfragŽŠÀíµÄ×îºóÒ»»·£¬ËùÒÔÔÚgen_ip_frag_procº¯ÊýÖÐ»áÑ­»·µ÷ÓÃip_procsÁŽ±í
		// ip_procsÁŽ±íµÄ×îºóÒ»žöœÚµãÊÇgen_ip_procº¯Êý
		// ÓÃ»§×Ô¶šÒåµÄ¶ŒÊÇÌíŒÓÔÚip_procsÁŽ±íÍ·
		// gen_ip_procº¯Êý»ážùŸÝÇé¿öµ÷ÓÃÉÏ²ãµÄprocess_tcp process_udp process_icmpµÈº¯Êý
		// ÀýÈçµ÷ÓÃÁËprocess_udpº¯Êý¡£
		// process_udpº¯Êý»áÑ­»·±éÀúudp_procsÁŽ±íÖÐµÄËùÓÐŽŠÀíudpµÄ±»ÓÃ»§×¢²áÁËµÄº¯Êý
		call_ip_frag_procs(qitem->data,qitem->caplen);

		// ÉÏÃæµÄº¯ÊýÖŽÐÐÍêÁËÖ®ºó£¬ŸÍ¿ÉÒÔÊÍ·Å¿ÕŒäÁË£¬È»ºóÖŽÐÐÏÂÒ»žöwhile
		free(qitem->data);
		free(qitem);
	}

	// ÍË³öºóÉ±ËÀÏß³Ì
	g_thread_exit(NULL);
}

#else

#define START_CAP_QUEUE_PROCESS_THREAD()
#define STOP_CAP_QUEUE_PROCESS_THREAD()

#endif


// ÕâÀïŸÍÊÇnidsµÄÈ«ŸÖ³õÊŒ»¯º¯Êý
int nids_init()
{

	ELEMENT_TYPE bq_node;
	ELEMENT_TYPE_P bq_current, bq_end;
	char * ptr;

	///////////////////////////
	printf("\n nids_init 001 \n");


	/* free resources that previous usages might have allocated */
	nids_exit();

	if (nids_params.pcap_desc)
		desc = nids_params.pcap_desc;
	else if (nids_params.filename)
	{
		if ((desc = pcap_open_offline(nids_params.filename,
		                              nids_errbuf)) == NULL)
			return 0;
	}
	else if (!open_live())
		return 0;

	if (nids_params.pcap_filter != NULL)
	{
		u_int mask = 0;
		struct bpf_program fcode;

		if (pcap_compile(desc, &fcode, nids_params.pcap_filter, 1, mask) <
		        0) return 0;
		if (pcap_setfilter(desc, &fcode) == -1)
			return 0;
	}
	switch ((linktype = pcap_datalink(desc)))
	{
#ifdef DLT_IEEE802_11
#ifdef DLT_PRISM_HEADER
	case DLT_PRISM_HEADER:
#endif
#ifdef DLT_IEEE802_11_RADIO
	case DLT_IEEE802_11_RADIO:
#endif
	case DLT_IEEE802_11:
		/* wireless, need to calculate offset per frame */
		break;
#endif

#ifdef DLT_NULL
	case DLT_NULL:
		nids_linkoffset = 4;
		break;
#endif
	case DLT_EN10MB:
		nids_linkoffset = 14;
		break;
	case DLT_PPP:
		nids_linkoffset = 4;
		break;
		/* Token Ring Support by vacuum@technotronic.com, thanks dugsong! */
	case DLT_IEEE802:
		nids_linkoffset = 22;
		break;

	case DLT_RAW:
	case DLT_SLIP:
		nids_linkoffset = 0;
		break;
#define DLT_LINUX_SLL   113
	case DLT_LINUX_SLL:
		nids_linkoffset = 16;
		break;
#ifdef DLT_FDDI
	case DLT_FDDI:
		nids_linkoffset = 21;
		break;
#endif
#ifdef DLT_PPP_SERIAL
	case DLT_PPP_SERIAL:
		nids_linkoffset = 4;
		break;
#endif
	default:
		strcpy(nids_errbuf, "link type unknown");
		return 0;
	}
	if (nids_params.dev_addon == -1)
	{
		if (linktype == DLT_EN10MB)
			nids_params.dev_addon = 16;
		else
			nids_params.dev_addon = 0;
	}
	if (nids_params.syslog == nids_syslog)
		openlog("libnids", 0, LOG_LOCAL0);

	// ×¢²áËùÓÐº¯Êý
	init_procs();
	tcp_init(nids_params.n_tcp_streams);
	ip_frag_init(nids_params.n_hosts);
	scan_init();

	if(nids_params.multiproc)
	{
#ifdef HAVE_LIBGTHREAD_2_0
		g_thread_init(NULL);
		cap_queue=g_async_queue_new();
#else
		strcpy(nids_errbuf, "libnids was compiled without threads support");
		return 0;
#endif
	}



	///////////////////////////
	printf("\n nids_init 002 \n");

	// init
	fifo_queue = mknew(struct queue_t);
	if (!fifo_queue)
	{
		return 0;	
	}
	// set fifo_queue with '0'
	queue_init(fifo_queue);
	inputcount = 0;
	outputcount = 0;
	discardcount = 0;

	///////////////////////////
	printf("\n nids_init 003 \n");

#if 0
	// init element for fifo_queue->data
	fifo_node_p = mknew_n(struct fifo_node, QUEUE_SIZE);
	if (!fifo_node_p)
	{
		free(fifo_queue);
		return 0;
	}
	buf_end = fifo_queue->data + QUEUE_SIZE;
	for (buf_current = fifo_queue->data; buf_current < buf_end; buf_current++, fifo_node_p ++)
	{
		(*buf_current) = fifo_node_p;
	}
#endif


	// allocate a buffer for tcp data.
	// 65535B for each tcp datagram.
	ptr = mknew_n(char, 65535*QUEUE_SIZE);
	if (!ptr)
	{
		free(fifo_queue);
		return 0;
	}

	///////////////////////////
	printf("\n nids_init 004 \n");

	// Initialize fifo_node
	// Eache node has a point, 'data', pointing to a buffer.
	// There are 65535 buffers but they are allocated at a time
	// referenced by 'ptr'.
	bq_end = fifo_queue->data + QUEUE_SIZE;
	for (bq_current = fifo_queue->data; bq_current < bq_end;
			bq_current++, ptr += 65535)
	{
		////////////////////////////////////
		//printf("bq_end=0x%p, data=0x%p, bq_current=0x%p \n", bq_end, fifo_queue->data, bq_current);
		bq_current->data = ptr;
		bq_current->skblen = -1;
	}


	///////////////////////////
	printf("\n nids_init 005 \n");

	return 1;
}

int nids_run()
{


	// Èç¹ûpcat_t µÄÒ»žöÖžÕëÎª¿Õ£¬ÔòÊä³öŽíÎó
	if (!desc)
	{
		strcpy(nids_errbuf, "Libnids not initialized");
		return 0;
	}


	//add: thread 2014 1 25   3
	FifoProces();
	//end add


	//START_CAP_QUEUE_PROCESS_THREAD(); /* threading... */

	//pcap_loop(desc, -1, (pcap_handler) nids_pcap_handler, 0);
	/* FIXME: will this code ever be called? Don't think so - mcree */
	// I don't think this code will ever be called, either.
	//STOP_CAP_QUEUE_PROCESS_THREAD();


	nids_exit();
	return 0;
}


//newadd 2014 2 18
void FifoProces()
{
	coreNum=sysconf(_SC_NPROCESSORS_CONF);//»ñÈ¡ºËÊý
	//printf("core num=%d\n",coreNum);
	//tid ÓÃÀŽ±êÊŸ²»Í¬µÄÏß³ÌidºÅ£¬ÓÃÒÔ°ó¶š¶ÔÓÃµÄcpu
	int i,tid[2]= {0,1};
	//thread_error=pthread_create(&th1,NULL,thread_pros1,(void*)&tid[0]);
	thread_error=pthread_create(&th1,NULL,thread_pros1,NULL);
	if(thread_error!=0)
	{
		sprintf("error:%s\n",strerror(thread_error));
		return 0;
	}
	//thread_error=pthread_create(&th2,NULL,thread_pros2,(void*)&tid[1]);
	thread_error=pthread_create(&th2,NULL,thread_pros2,NULL);
	if(thread_error!=0)
	{
		sprintf("error:%s\n",strerror(thread_error));
		return 0;
	}
	pthread_join(th1,NULL);
	pthread_join(th2,NULL);

}

//end newadd

//add: 2014 1 25 4
// running pcap_loop to capture packages from ethernet.
void * thread_pros1(void *arg)
{
	cpu_set_t mask;//cpuºËµÄŒ¯ºÏ
	cpu_set_t get;//»ñÈ¡ÔÚŒ¯ºÏÖÐµÄcpu
	printf("This is the first phrase!\n");
	//int *ar=(int *)arg;
	//int *ar=NULL;//debug
	//*ar=0;///debug
	//printf("this is the %d thread\n",*ar);

	CPU_ZERO(&mask);
	CPU_SET(0,&mask);
	if(-1==sched_setaffinity(0,sizeof(mask),&mask))
		printf("Faild to band %d thread on cpu\n",0);
	//else printf("%d thread band to %d cpu successfully\n",*ar,sched_getcpu());
	CPU_ZERO(&get);
	if(sched_getaffinity(0,sizeof(get),&get)<0)
		printf("faild get cpu source\n");


	//////////////////////////////////
	coreNum=sysconf(_SC_NPROCESSORS_CONF);//获取核数
	printf("core num=%d\n",coreNum);
	printf("This is the first phrase!\n");
	printf("\"pcap_get\" thread is run on %d cpu\n",sched_getcpu());
	sleep(6);
	//////////////////////////////////

	pcap_loop(desc, -1, (pcap_handler) nids_pcap_handler, 0);
	STOP_CAP_QUEUE_PROCESS_THREAD();

	//todo :Ïß³ÌÎªº¯ÊýµÄÈë¿Úº¯Êý
	//gen_ip_frag_proc;
}

// running nids_functions to trip into a dead loop
// in the loop we tackle tcp datagrams.
void *thread_pros2(void * arg)
{
	cpu_set_t mask;//cpuºËµÄŒ¯ºÏ
	cpu_set_t get;//»ñÈ¡ÔÚŒ¯ºÏÖÐµÄcpu

	//newadd 2014 2 18
	//int *ar=(int *)arg;
	//int *ar=NULL;
	//*ar=1;//debug
	//printf("this is the %d thread\n",*ar);

	CPU_ZERO(&mask);
	CPU_SET(1,&mask);
	if(-1==sched_setaffinity(0,sizeof(mask),&mask))
		printf("Faild to band %d thread on cpu\n",1);
	CPU_ZERO(&get);
	if(sched_getaffinity(0,sizeof(get),&get)<0)
		printf("faild get cpu source\n");


	//////////////////////////////////
	coreNum=sysconf(_SC_NPROCESSORS_CONF);//获取核数
	printf("core num=%d\n",coreNum);
	printf("This is the second phrase!\n");
	sleep(6);
	//////////////////////////////////
	//else printf("%d thread band to %d cpu successfully\n",*ar,sched_getcpu());
	//end newadd
	nids_function();
	//todo :Ïß³ÌÎªµÚ¶þœ×¶ÎµÄÈë¿Úº¯Êý
	//tcp_procs;
}
//end add

void nids_exit()
{
	if (!desc)
	{
		strcpy(nids_errbuf, "Libnids not initialized");
		return;
	}
#ifdef HAVE_LIBGTHREAD_2_0
	if (nids_params.multiproc)
	{
		/* I have no portable sys_sched_yield,
		   and I don't want to add more synchronization...
		*/
		while (g_async_queue_length(cap_queue)>0)
			usleep(100000);
	}
#endif
	tcp_exit();
	ip_frag_exit();
	scan_exit();
	strcpy(nids_errbuf, "loop: ");
	strncat(nids_errbuf, pcap_geterr(desc), sizeof nids_errbuf - 7);
	if (!nids_params.pcap_desc)
		pcap_close(desc);
	desc = NULL;

	free(ip_procs);
	free(ip_frag_procs);
}

int nids_getfd()
{
	if (!desc)
	{
		strcpy(nids_errbuf, "Libnids not initialized");
		return -1;
	}
	return pcap_get_selectable_fd(desc);
}

int nids_next()
{
	struct pcap_pkthdr h;
	char *data;

	if (!desc)
	{
		strcpy(nids_errbuf, "Libnids not initialized");
		return 0;
	}
	if (!(data = (char *) pcap_next(desc, &h)))
	{
		strcpy(nids_errbuf, "next: ");
		strncat(nids_errbuf, pcap_geterr(desc), sizeof(nids_errbuf) - 7);
		return 0;
	}
	/* threading is quite useless (harmful) in this case - should we do an API change?  */
	START_CAP_QUEUE_PROCESS_THREAD();
	nids_pcap_handler(0, &h, (u_char *)data);
	STOP_CAP_QUEUE_PROCESS_THREAD();
	return 1;
}

int nids_dispatch(int cnt)
{
	int r;

	if (!desc)
	{
		strcpy(nids_errbuf, "Libnids not initialized");
		return -1;
	}
	START_CAP_QUEUE_PROCESS_THREAD(); /* threading... */
	if ((r = pcap_dispatch(desc, cnt, (pcap_handler) nids_pcap_handler,
	                       NULL)) == -1)
	{
		strcpy(nids_errbuf, "dispatch: ");
		strncat(nids_errbuf, pcap_geterr(desc), sizeof(nids_errbuf) - 11);
	}
	STOP_CAP_QUEUE_PROCESS_THREAD();
	return r;
}





