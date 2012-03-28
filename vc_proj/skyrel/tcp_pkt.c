//
//tcp communication
//

#include<stdio.h>

#include <winsock.h>  
#include "rc4/Expand_IV.h"
#include "short_types.h"

typedef struct _skype_thing {
	u32				type, id, m, n;
} skype_thing;


extern int encode_to_7bit(char *buf, uint word, int limit);
extern int first_bytes_header(u16 seqnum, char *header, int header_len, char *buf, int buf_len);
extern int first_bytes_header2(u16 seqnum, char *header, int header_len, char *buf, int buf_len);
extern int first_bytes_size(u16 seqnum, char *header, int header_len, char *buf, int buf_len);

extern int main_unpack_test (u8 *indata, u32 inlen, u32 test_type, u32 test_id);
extern int main_unpack_saveip (u8 *indata, u32 inlen);
extern int main_unpack (u8 *indata, u32 inlen);
extern int main_pack (skype_thing *mythings, int mythings_len, u8 *outdata, u32 maxlen);

extern unsigned int Calculate_CRC32(char *crc32, int bytes);
extern int tcp_talk(char *remoteip, unsigned short remoteport, char *buf, int len, char *result,int need_close);
extern int show_memory(char *mem, int len, char *text);


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

	rnd=bswap32(rnd);
	memcpy(pkt,(char*)&rnd,4);
	rnd=bswap32(rnd);

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

	show_memory(pkt,pkt_len,"result1:");

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

	/*
	// our session id
	skype_thing	mythings[] = {
		{0, 3, 0x63E0, 0},
	};
	int mythings_len = 1;
	*/

	u8 send_probe_pkt[]="\x1A\xFF\xFF\x08\xCA\x04\xFF\xFF\x42\x6A\xC6\x22\xA5\x7B";
	len=sizeof(send_probe_pkt)-1;


	//seqnum=0x2ADD;

	seqnum=bswap16(seqnum);
	memcpy(send_probe_pkt+1,(char *)&seqnum,2);
	seqnum=bswap16(seqnum);

	seqnum--;
	seqnum=bswap16(seqnum);
	memcpy(send_probe_pkt+6,(char *)&seqnum,2);
	seqnum=bswap16(seqnum);
	seqnum++;

	memcpy(pkt,send_probe_pkt,len);


	iv = rnd;

	Skype_RC4_Expand_IV (&rc4, iv, 1);

	show_memory(pkt,len,"send pkt2:");
	RC4_crypt (pkt, len, &rc4, 0);
	

	*pkt_len=len;


	return 0;
};


int process_tcp_pkt2(char *pkt, int pkt_len, int *last_recv_pkt_num) {
	int ret;

	RC4_crypt(pkt, pkt_len, &rc4_save, 0);

	/*
	memcpy(last_recv_pkt_num,pkt+1,2);
	*last_recv_pkt_num=bswap16(*last_recv_pkt_num);
	(*last_recv_pkt_num)++;
	*last_recv_pkt_num=bswap16(*last_recv_pkt_num);
	*/

	show_memory(pkt,pkt_len,"result2:");
	
	// supernode check
	// if yet 06 0x21 blob, this is supernode reply
	ret=main_unpack(pkt, pkt_len);


	
	return 0;
};


int process_tcp_pkt3(char *pkt, int pkt_len, int *last_recv_pkt_num) {
	int ret;

	RC4_crypt(pkt, pkt_len, &rc4_save, 0);

	/*
	memcpy(last_recv_pkt_num,pkt+1,2);
	*last_recv_pkt_num=bswap16(*last_recv_pkt_num);
	(*last_recv_pkt_num)++;
	*last_recv_pkt_num=bswap16(*last_recv_pkt_num);
	*/

	show_memory(pkt,pkt_len,"result3:");
	
	// supernode check
	// if yet 06 0x21 blob, this is supernode reply
	ret=main_unpack(pkt, pkt_len);


	
	return 0;
};
