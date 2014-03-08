/*
Copyright (c) 1999 Rafal Wojtczuk <nergal@7bulls.com>. All rights reserved.
See the file COPYING for license details.
*/


#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <string.h>

#include "nids.h"
#include "fifo.h"



#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))

#define __USE_GNU
#include <unistd.h>
#include <sched.h>
#include <stdio.h>




// struct tuple4 contains addresses and port numbers of the TCP connections
// the following auxiliary function produces a string looking like
// 10.0.0.1,1024,10.0.0.2,23
char *
adres (struct tuple4 addr)
{
	static char buf[256];
	strcpy (buf, int_ntoa (addr.saddr));
	sprintf (buf + strlen (buf), ",%i,", addr.source);
	strcat (buf, int_ntoa (addr.daddr));
	sprintf (buf + strlen (buf), ",%i", addr.dest);
	return buf;
}

void
tcp_callback (struct tcp_stream *a_tcp, void ** this_time_not_needed)
{
	char buf[1024];
	// 把地址放入buffer
	strcpy (buf, adres (a_tcp->addr)); // we put conn params into buf
	// 如果是刚刚建立的tcp
	if (a_tcp->nids_state == NIDS_JUST_EST)
	{
		// connection described by a_tcp is established
		// here we decide, if we wish to follow this stream
		// sample condition: if (a_tcp->addr.dest!=23) return;
		// in this simple app we follow each stream, so..
		// 修改tcp的数据、紧急数据的接收喜好
		a_tcp->client.collect++; // we want data received by a client
		a_tcp->server.collect++; // and by a server, too
		a_tcp->server.collect_urg++; // we want urgent data received by a
		// server
#ifdef WE_WANT_URGENT_DATA_RECEIVED_BY_A_CLIENT
		a_tcp->client.collect_urg++; // if we don't increase this value,
		// we won't be notified of urgent data
		// arrival
#endif
		// 如果是刚刚建立的一个tcp，仅仅打印地址
		fprintf (stderr, "%s established\n", buf);
		return;
	}

	// 如果是即将关闭的tcp
	if (a_tcp->nids_state == NIDS_CLOSE)
	{
		// connection has been closed normally
		// 打印关闭提示
		fprintf (stderr, "%s closing\n", buf);
		return;
	}

	// 如果是重置，打印重置
	if (a_tcp->nids_state == NIDS_RESET)
	{
		// connection has been closed by RST
		fprintf (stderr, "%s reset\n", buf);
		return;
	}

	// 如果是接收到一个数据
	if (a_tcp->nids_state == NIDS_DATA)
	{
		// new data has arrived; gotta determine in what direction
		// and if it's urgent or not
		struct half_stream *hlf;
		// 如果是服务器端的紧急数据
		if (a_tcp->server.count_new_urg)
		{
			// new byte of urgent data has arrived
			// 打印紧急数据标志
			strcat(buf,"(urgent->)");
			buf[strlen(buf)+1]=0;
			// 保存紧急数据
			// buf[strlen(buf)]=a_tcp->server.urgdata;
			// 在标准输出上显示
			write(1,buf,strlen(buf));
			return;
		}
		
		// We don't have to check if urgent data to client has arrived,
		// because we haven't increased a_tcp->client.collect_urg variable.
		// So, we have some normal data to take care of.
		// 如果是普通的用户端数据
		if (a_tcp->client.count_new)
		{
			// new data for client
			hlf = &a_tcp->client; // from now on, we will deal with hlf var,
			// which will point to client side of conn
			strcat (buf, "(<-)"); // symbolic direction of data
		}
		// 否则是普通的客户端数据
		else
		{
			hlf = &a_tcp->server; // analogical
			strcat (buf, "(->)");
		}
		// 在2号输出端口输出提示符
		fprintf(stderr,"%s",buf); // we print the connection parameters
		// (saddr, daddr, sport, dport) accompanied
		// by data flow direction (-> or <-)
		// 在stderr端口输出数据
		write(2,hlf->data,hlf->count_new); // we print the newly arrived data

	}
	return ;
}

int
main ()
{
	// here we can alter libnids params, for instance:
	// nids_params.n_hosts=256;
	if (!nids_init ())
	{
		fprintf(stderr,"%s\n",nids_errbuf);
		exit(1);
	}

	nids_register_tcp (tcp_callback);

	nids_run ();
	return 0;
}

