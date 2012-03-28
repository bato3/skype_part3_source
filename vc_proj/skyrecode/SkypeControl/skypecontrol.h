/*\
|*|
|*| SkypeControl v0.104 by Sean O'Neil.
|*| Copyright (c) 2008-2009 by VEST Corporation.
|*| All rights reserved. Strictly Confidential!
|*|
\*/

#ifndef _SKYPECONTROL_H_
#define _SKYPECONTROL_H_

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "skype_basics.h"
#include "skype_rc4.h"

static void die (char *msg) {
		printf("%s\n",msg);
		exit(-1);
};



#ifndef __GNUC__
	#define tcp_seq			u32
	#pragma pack(1)
	typedef struct ip
	{
		u8					ip_hl:4,	/* header length */
							ip_v:4;		/* version */
		u8					ip_tos;		/* type of service */
		u16					ip_len;		/* total length */
		u16					ip_id;		/* identification */
		u16					ip_off;		/* fragment offset field */
	#define	IP_RF			0x8000		/* reserved fragment flag */
	#define	IP_DF			0x4000		/* dont fragment flag */
	#define	IP_MF			0x2000		/* more fragments flag */
	#define	IP_OFFMASK		0x1FFF		/* mask for fragmenting bits */
		u8					ip_ttl;		/* time to live */
		u8					ip_p;		/* protocol */
		u16					ip_sum;		/* checksum */
	struct in_addr			ip_src,ip_dst;	/* source and dest address */
	};
	typedef struct tcphdr
	{
		u16					th_sport;	/* source port */
		u16					th_dport;	/* destination port */
		tcp_seq				th_seq;		/* sequence number */
		tcp_seq				th_ack;		/* acknowledgement number */
		u8					th_x2:4,	/* (unused) */
							th_off:4;	/* data offset */
		u8					th_flags;
	#define	TH_FIN			0x01
	#define	TH_SYN			0x02
	#define	TH_RST			0x04
	#define	TH_PUSH			0x08
	#define	TH_ACK			0x10
	#define	TH_URG			0x20
	#define	TH_ECE			0x40
	#define	TH_CWR			0x80
	#define	TH_FLAGS		(TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
		u16					th_win;		/* window */
		u16					th_sum;		/* checksum */
		u16					th_urp;		/* urgent pointer */
	};
	struct udphdr
	{
		u16					uh_sport;	/* source port */
		u16					uh_dport;	/* destination port */
		u16					uh_ulen;	/* udp length */
		u16					uh_sum;		/* udp checksum */
	};
#endif

#ifndef IPPROTO_DIVERT
	#define	IPPROTO_DIVERT	254		/* divert pseudo-protocol */
#endif

#define BUFF_SIZE			0x100000	// who knows what other protocols are out there besides TCP/IP
#define SC_ALLOW			0
#define SC_DROP				1
#define SC_TERMINATE		2
#define SC_BLOCK			1

static SOCKET				din, dout;	// in/out divert sockets
static fd_set				fds;	// duh!
static u32					my_external_address[2], my_addresses = 0;	// so far only one external interface is supported, two will still work, but not more
static u8					buff[BUFF_SIZE];	// buffer for all incoming packets
static u8					data[65536];	// data for RC4. can't possibly have bigger TCP/UDP packets
typedef struct _connection
{
	u32					id;		// last valid rand
	time_t				seen;	// time of the last packet
	u32					n;		// been caught this many times
	u32					ip;		// source IP
	u16					port, state;	// source port, connection state
	struct _connection	*next, *prev;	// collision chain
} connection;

static connection		*connection_list[262144];	// 2^18 connection lists

static u32 hash16 (u32 a, u32 b) {return hash32(a,b)>>14;}	// 18-bit [IP:port] hash for the above connection table

static connection * get_connection (const u32 ip, const u32 port)
{
	u32					i = hash16 (ip, port);
	connection			*p = connection_list[i], *q;
	time_t				t = time (NULL);

#pragma warning(disable:4018)
	
	if (p) for (;;)
	{
		if ((p->ip == ip) && (p->port == port))
		{
			if (t > p->seen + p->n*900 + 30)	// 15-min to 32-hour timeouts for skypes, 30 seconds for all other connections
			{
				p->id = 0;
				p->n = 0;
				p->state = 0;
			}
			p->seen = t;
			return p;
		}
		q = p->next;
		if (t > p->seen + p->n*900 + 30)	// 15-min to 32-hour timeouts for skypes, 30 seconds for all other connections
		{
			if (q) q->prev = p->prev;
			if (p->prev) p->prev->next = q; else connection_list[i] = q;
			free (p);
			p = q ? q->prev : NULL;
		}
		if (q == NULL) break;
		p = q;
	}

#pragma warning(default:4018)

	q = malloc (sizeof(connection));
	q->ip = ip;
	q->port = (u16) port;
	q->seen = t;
	q->state = 0;
	q->n = 0;
	if (p) p->next = q; else connection_list[i] = q;
	return q;
}


static size_t ip_size (const u8 * const b, const size_t dlen)
{
	size_t				ret;
	
	if (dlen < sizeof (struct ip)) return 0;
	ret = ((struct ip *) b)->ip_hl * 4;
	if (ret < sizeof (struct ip) || ret > dlen) return 0;
	return ret;
}

static u16 ip_sum (u32 sum, const void * const hdr, u16 len)
{
	const u8 * const	b = hdr;
	u32					i;
	
	for (i = 0; i+1 < len; i += 2) sum += (b[i]<<8)+b[i+1];
	if (len&1) sum += b[i]<<8;
	while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
	sum ^= 0xFFFF;
	return bswap16(sum);
}

static u16 tcp_sum (struct ip * const ip_hdr, struct tcphdr * const tcp_hdr, u16 len)
{
	u16					sum = ip_sum (ip_hdr->ip_p + len, &ip_hdr->ip_src, 8) ^ 0xFFFF;
	
	sum = bswap16(sum);
	return ip_sum (sum, tcp_hdr, len);
}


static void divert_open (void)
{
	struct sockaddr_in	sa;
	
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = 0;
	sa.sin_port = htons (1111);
	if ((dout = socket(PF_INET, SOCK_RAW, IPPROTO_DIVERT)) == -1) die ("socket");
	if (bind (dout, (struct sockaddr *) &sa, sizeof (struct sockaddr_in)) == -1) die ("bind");
	//error ("Input divert socket = %d\n", dout);
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = 0;
	sa.sin_port = htons (1112);
	if ((din = socket(PF_INET, SOCK_RAW, IPPROTO_DIVERT)) == -1) die ("socket");
	if (bind (din, (struct sockaddr *) &sa, sizeof (struct sockaddr_in)) == -1) die ("bind");
	//error ("Output divert socket = %d\n", din);
}

#endif
