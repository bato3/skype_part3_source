//
//tcp communication
//

#include<stdio.h>

#include <winsock.h>  
#include "rc4/Expand_IV.h"


extern int main_unpack (u8 *indata, u32 inlen);

extern unsigned int Calculate_CRC32(char *crc32, int bytes);
extern int udp_talk(char *remoteip, unsigned short remoteport, char *buf, int len, char *result);
extern int tcp_talk(char *remoteip, unsigned short remoteport, char *buf, int len, char *result,int need_close);
extern int tcp_send(char *remoteip, unsigned short remoteport, char *buf, int len);

extern int show_memory(char *mem, int len, char *text);
extern int process_pkt(char *pkt, int pkt_len, int use_replyto);


typedef struct _skype_thing {
	u32				type, id, m, n;
} skype_thing;

extern int main_pack (skype_thing *mythings, int mythings_len, u8 *outdata, u32 maxlen);
extern int last_recv_pkt_num;

//rc4 send
RC4_context rc4;

//rc4 recv
RC4_context rc4_save;

//////////////////////
// tcp first packet //
//////////////////////
int make_tcp_pkt1(u32 rnd, u32 *remote_tcp_newrnd, char *pkt, int *pkt_len) {
	int len;
	u32	iv;
	u8 send_probe_pkt[]="\x00\x01\x00\x00\x00\x01\x00\x00\x00\x03";
	len=sizeof(send_probe_pkt)-1;


	iv = rnd;

	Skype_RC4_Expand_IV (&rc4, iv, 1);

	RC4_crypt (send_probe_pkt, len, &rc4, 0);

	//make send pkt
	rnd=bswap32(rnd);
	memcpy(pkt,(char*)&rnd,4);
	rnd=bswap32(rnd);
	//rc4
	memcpy(pkt+4,(char *)&send_probe_pkt,len);

	len=14;

	*pkt_len=len;

	return 0;
};


int process_tcp_pkt1(char *pkt, int pkt_len, u32 *remote_tcp_rnd) {
	u32	newrnd;
	u32 iv;
	
	if (pkt_len<0x0E) {
		//printf("too short packet\n");
		//printf("not skype\n");
		return -1;
	};

	memcpy(&newrnd,pkt,4);
	
	iv = bswap32(newrnd);
	
	Skype_RC4_Expand_IV (&rc4_save, iv, 1);
	
	RC4_crypt (pkt+4, 10, &rc4_save, 1);
	
	if (pkt_len > 0x0E) {
		RC4_crypt (pkt+14, pkt_len-14, &rc4_save, 0);
	};

	if (strncmp(pkt+4+2,"\x00\x00\x00\x01\x00\x00\x00\x03",8)!=0) {
		//printf("first answer wrong\n");
		//printf("not skype\n");
		return -1;
	};

	*remote_tcp_rnd=newrnd;


	return 0;
};




///////////////////////////////
//tcp second packet
////////////////////////////////
int make_tcp_pkt2(u16 seqnum, u32 rnd, char *pkt, int *pkt_len) {
	int len;
	u32	iv;

	u8 result[0x1000];
	int result_len;

	//42394 - 0xA59A my iport
	skype_thing	mythings[] = {
		{0, 0x01, 0x00000003, 0},
		{1, 0x0D, 0xD6BA8CD9, 0x9205E2CD},
		{0, 0x10, 0xA59A, 0},
	};
	int mythings_len=3;

	u8 send_probe_pkt[]="\x30\xFF\xFF\x13\xF2\x01\xFF\xFF\x42\x44\x40\xFA\x3B\x4C\xE4\xAF\x94\xD9\x8C\xBA\xD6\xCD\xE2\x05\x92";
	len=sizeof(send_probe_pkt)-1;


	//main_unpack(send_probe_pkt,len);
	result_len=main_pack(mythings, mythings_len, result, sizeof(result)-1 );
	//show_memory(result,nlen,"packed42:");
	//main_unpack(result,nlen);

	memcpy(send_probe_pkt+8,result,result_len);

	show_memory(send_probe_pkt,len,"send pkt2:");


	seqnum=bswap16(seqnum);
	memcpy(send_probe_pkt+1,(char *)&seqnum,2);
	seqnum=bswap16(seqnum);

	seqnum=bswap16(seqnum-1);
	memcpy(send_probe_pkt+6,(char *)&seqnum,2);
	seqnum=bswap16(seqnum-1);

	iv = rnd;

	Skype_RC4_Expand_IV (&rc4, iv, 1);
	
	RC4_crypt (send_probe_pkt, len, &rc4, 0);


	memcpy(pkt,send_probe_pkt,len);
	
	*pkt_len=len;


	return 0;
};


int process_tcp_pkt2(char *pkt, int pkt_len) {

	RC4_crypt (pkt, pkt_len, &rc4_save, 0);

	show_memory(pkt,pkt_len,"result:");

	//process_pkt(pkt,pkt_len,1);
	main_unpack(pkt,pkt_len);


	return 0;
};

//if supernode, we recv clients online.
//if not supernode
//client:
//09:41:29 CommLayer: Packet #0199 received from 192.168.1.10 using TCP
//09:41:29 I:0x00000007 D:7
//09:41:29 I:0x0000A59A D:42394
//09:41:29 CommLayer: Query cmd $30 #0198
//09:41:29 Localnode: CommandReceived(cmd=$30) from 192.168.1.10:4340
//09:41:29 Localnode: rejecting client connect from 192.168.1.10:4340. sending alernative host addrs
//and return to us: 0x153 bytes with alternative host address
//


///////////////////////////////
//tcp confirm packet
////////////////////////////////
int make_tcp_confirm(char *pkt, int *pkt_len) {
	int len;

	// pkt confirm
	u8 confirm_pkt[]="\x07\x01\xFF\xFF";


	// confirm
	memcpy(confirm_pkt+2,(char *)&last_recv_pkt_num,2);

	len=0;
	memcpy(pkt+len,confirm_pkt,sizeof(confirm_pkt)-1);
	len+=sizeof(confirm_pkt)-1;

	//show_memory(pkt,len,"send confirm:");

	RC4_crypt (pkt, len, &rc4, 0);

	*pkt_len=len;


	return 0;
};


///////////////////////////////
//tcp third packet
////////////////////////////////
int make_tcp_pkt3(u16 seqnum, u32 rnd, char *pkt, int *pkt_len) {
	int len;
	u8 result[0x1000];
	int result_len;

	skype_thing	mythings[] = {
		{0, 0x04, 0x10, 0},
		{0, 0x05, 0x06, 0},
	};
	int mythings_len=2;

	//u8 send_probe_pkt[]="\x16\xFF\xFF\x06\x82\x03\xFF\xFF\x42\x33\x48\x93";
	u8 send_probe_pkt[]="\x14\xFF\xFF\x06\x32\xFF\xFF\x42\x85\x14\xC9";
	len=sizeof(send_probe_pkt)-1;


	//main_unpack(send_probe_pkt,len);
	result_len=main_pack(mythings, mythings_len, result, sizeof(result)-1 );
	//show_memory(result,result_len,"packed42:");
	//main_unpack(result,result_len);

	memcpy(send_probe_pkt+7,result,result_len);
	show_memory(send_probe_pkt,len,"send pkt3:");


	//seq
	seqnum=bswap16(seqnum);
	memcpy(send_probe_pkt+1,(char *)&seqnum,2);
	seqnum=bswap16(seqnum);

	seqnum--;
	seqnum=bswap16(seqnum);
	memcpy(send_probe_pkt+5,(char *)&seqnum,2);
	seqnum=bswap16(seqnum);


	len=0;
	memcpy(pkt+len,send_probe_pkt,sizeof(send_probe_pkt)-1);
	len+=sizeof(send_probe_pkt)-1;

	
	RC4_crypt (pkt, len, &rc4, 0);

	*pkt_len=len;


	return 0;
};



///////////////////////////////
//tcp 4 packet
////////////////////////////////
int make_tcp_pkt4(u16 seqnum, u32 rnd, char *pkt, int *pkt_len) {
	int len;
	//u8 result[0x1000];
	//int result_len;

	skype_thing	mythings[] = {
		{0, 0x04, 0x10, 0},
		{0, 0x05, 0x06, 0},
	};
	int mythings_len=2;

	// cmd 37$ send our info to node
	u8 send_probe_pkt[]="\x78\xFF\xFF"
"\x32\xA9\x02\x42\x31\x9A\x5F\x5D\xF8\x90\xC4\x1F\x86\xE5\x4E\x43"
"\x48\xCE\x13\x3B\x9F\xA0\xD0\x36\xC2\x86\x4F\xF1\xDE\x49\x7F\x02"
"\xAF\xC9\x6A\x56\x23\xC4\xFD\x42\x66\x51\xBF\x3E\x7A\x9C\xE9\x76"
"\x6B\x7D\x17\x9A\x7C\x02\xB1\x02\x42\x15"
;
	len=sizeof(send_probe_pkt)-1;

// anounce to node my info


//my addr cmd $36 using udp
//02-11: 78.37.50.251:42394
/*
78 - 4E
37 - 25
50 - 32
251 - FB

4e 25 32 fb

192 - c0  
168 - a8
1 - 1
10 - 0a
*/

//42394 - 0xA59A my iport
/*
FBBEA04A
4a- 74
a0 - 160
be - 190
fb - 251
*/
/*
00-00: 1C 00 00 00
00-01: 7F 07 00 00
00-02: 00 00 00 00
00-03: 00 00 00 00
00-04: 00 00 00 00
00-05: E8 03 00 00
00-06: 00 00 00 00
00-07: 00 00 00 00
00-08: 01 00 00 00
00-0B: 01 00 00 00
00-0D: 02 00 00 00
03-0E: "0/1.4.0.84/259"
00-0F: FB BE A0 4A
03-5D: "0/1.4.0.84/259"
03-5E: "en"
00-76: 00 00 00 00
00-77: 00 00 00 00
*/

	//process_pkt(send_probe_pkt,len,0);
	//main_unpack(send_probe_pkt,len);

	//result_len=main_pack(mythings, mythings_len, result, sizeof(result)-1 );
	//show_memory(result,result_len,"packed42:");
	//main_unpack(result,result_len);

	//memcpy(send_probe_pkt+7,result,result_len);
	//show_memory(send_probe_pkt,len,"send pkt3:");


	//seq
	seqnum=bswap16(seqnum);
	memcpy(send_probe_pkt+1,(char *)&seqnum,2);
	seqnum=bswap16(seqnum);


	len=0;
	memcpy(pkt+len,send_probe_pkt,sizeof(send_probe_pkt)-1);
	len+=sizeof(send_probe_pkt)-1;

	
	RC4_crypt (pkt, len, &rc4, 0);

	*pkt_len=len;


	return 0;
};




///////////////////////////////
//tcp five packet
////////////////////////////////
int make_tcp_pkt5(u16 seqnum, u32 rnd, char *pkt, int *pkt_len) {
	int len;

	//u8 result[0x1000];
	//int result_len;

	skype_thing	mythings[] = {
		{0, 0x04, 0x10, 0},
		{0, 0x05, 0x06, 0},
	};
	int mythings_len=2;

	u8 send_probe_pkt[]="\xC4\x02\x05\xD8"
"\x08\x32\x05\xD7\x42\x32\x40\xF6\x4F\xF7\x08\x32\x05\xD9\x42\x34"
"\xCD\x96\x68\xEE\x08\x32\x05\xDA\x42\x34\xC4\xA0\xA6\xEE\x08\x32"
"\x05\xDB\x42\x32\x71\xB3\xCF\xF7\x08\x32\x05\xDC\x42\x34\xAA\x09"
"\xF8\xEE\x08\x32\x05\xDD\x42\x33\xE4\x54\xD6\x22\x08\x32\x05\xDE"
"\x42\x34\xA4\x5B\x64\xEE\x08\x32\x05\xDF\x42\x34\x70\xB1\x77\x9E"
"\x08\x32\x05\xE0\x42\x34\xD8\xF3\x90\xEE\x08\x32\x05\xE1\x42\x33"
"\xD1\xD3\x49\x22\x08\x32\x05\xE2\x42\x34\x58\x06\x6D\x9E\x08\x32"
"\x05\xE3\x42\x34\x56\x8B\x86\x9E\x08\x32\x05\xE4\x42\x32\x62\x78"
"\x97\xF7\x08\x32\x05\xE5\x42\x33\x1C\x63\x25\xFA\x08\x32\x05\xE6"
"\x42\x34\xDC\xE2\x94\xEE\x08\x32\x05\xE7\x42\x34\xDE\xB4\xCA\xEE"
;

	len=sizeof(send_probe_pkt)-1;


	//process_pkt(send_probe_pkt,len,1);
	main_unpack(send_probe_pkt,len);

	//result_len=main_pack(mythings, mythings_len, result, sizeof(result)-1 );
	//show_memory(result,result_len,"packed42:");
	//main_unpack(result,result_len);

	//memcpy(send_probe_pkt+7,result,result_len);
	//show_memory(send_probe_pkt,len,"send pkt3:");


	//seq
	seqnum=bswap16(seqnum);
	memcpy(send_probe_pkt+2,(char *)&seqnum,2);
	seqnum=bswap16(seqnum);

	seqnum--;
	seqnum=bswap16(seqnum);
	memcpy(send_probe_pkt+6,(char *)&seqnum,2);
	seqnum=bswap16(seqnum);
	seqnum++;

	seqnum++;
	seqnum=bswap16(seqnum);
	memcpy(send_probe_pkt+16,(char *)&seqnum,2);
	seqnum=bswap16(seqnum);

	seqnum++;
	seqnum=bswap16(seqnum);
	memcpy(send_probe_pkt+16,(char *)&seqnum,2);
	seqnum=bswap16(seqnum);

	len=0;
	memcpy(pkt+len,send_probe_pkt,sizeof(send_probe_pkt)-1);
	len+=sizeof(send_probe_pkt)-1;

	RC4_crypt (pkt, len, &rc4, 0);

	*pkt_len=len;

	return 0;
};


int process_tcp_pkt5(char *pkt, int pkt_len) {
	
	RC4_crypt (pkt, pkt_len, &rc4_save, 0);

	show_memory(pkt,pkt_len,"result:");

	//process_pkt(pkt,pkt_len,1);
	main_unpack(pkt,pkt_len);


	return 0;
};


