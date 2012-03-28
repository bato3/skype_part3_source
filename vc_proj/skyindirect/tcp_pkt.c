//
//tcp communication
//

#include <stdio.h>

#include <winsock.h>  
#include "rc4/Expand_IV.h"

#include "short_types.h"

#include "global_vars.h"


typedef struct _skype_thing {
	u32				type, id, m, n;
} skype_thing;


extern int encode_to_7bit(char *buf, uint word, int limit);
extern int first_bytes_header(u16 seqnum, char *header, int header_len, char *buf, int buf_len);
extern int first_bytes_header2(u16 seqnum, char *header, int header_len, char *buf, int buf_len);
extern int first_bytes_size(u16 seqnum, char *header, int header_len, char *buf, int buf_len);

extern int main_unpack_connid (u8 *indata, u32 inlen, u32 *connid);
extern int main_unpack_test (u8 *indata, u32 inlen, u32 test_type, u32 test_id);
extern int main_unpack_saveip (u8 *indata, u32 inlen);
extern int main_unpack (u8 *indata, u32 inlen);
extern int main_pack (skype_thing *mythings, int mythings_len, u8 *outdata, u32 maxlen);

extern unsigned int Calculate_CRC32(char *crc32, int bytes);
extern int show_memory(char *mem, int len, char *text);


extern uint DEBUG_LEVEL;


//////////////////////
// tcp first packet //
//////////////////////
int make_tcp_pkt1(char *globalptr, u32 rnd, u32 *remote_tcp_newrnd, char *pkt, int *pkt_len) {
	int len;
	u32	iv;
	u8 send_probe_pkt[]="\x00\x01\x00\x00\x00\x01\x00\x00\x00\x03";

	struct global_s *global;
	global=(struct global_s *)globalptr;

	len=sizeof(send_probe_pkt)-1;

	iv = rnd;

	Skype_RC4_Expand_IV (&global->rc4_send, iv, 1);

	RC4_crypt (send_probe_pkt, len, &global->rc4_send, 0);

	rnd=bswap32(rnd);
	memcpy(pkt,(char*)&rnd,4);
	rnd=bswap32(rnd);

	memcpy(pkt+4,(char *)&send_probe_pkt,len);

	len=14;

	*pkt_len=len;

	return 0;
};


int process_tcp_pkt1(char *globalptr, char *pkt, int pkt_len, u32 *remote_tcp_rnd) {
	u32	newrnd;
	u32 iv;
	
	struct global_s *global;
	global=(struct global_s *)globalptr;


	if (pkt_len<0x0E) {
		//printf("too short packet\n");
		//printf("not skype\n");
		return -1;
	};

	memcpy(&newrnd,pkt,4);
	
	iv = bswap32(newrnd);
	
	Skype_RC4_Expand_IV (&global->rc4_recv, iv, 1);
	
	RC4_crypt (pkt+4, 10, &global->rc4_recv, 1);
	
	if (pkt_len > 0x0E) {
		RC4_crypt (pkt+14, pkt_len-14, &global->rc4_recv, 0);
	};

	if (DEBUG_LEVEL>=100) show_memory(pkt,pkt_len,"result1:");

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
int make_tcp_pkt2(char *globalptr, u16 seqnum, u32 rnd, char *pkt, int *pkt_len) {
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

	struct global_s *global;
	global=(struct global_s *)globalptr;

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

	Skype_RC4_Expand_IV (&global->rc4_send, iv, 1);

	if (DEBUG_LEVEL>=100) show_memory(pkt,len,"send pkt2:");
	RC4_crypt (pkt, len, &global->rc4_send, 0);
	

	*pkt_len=len;


	return 0;
};


int process_tcp_pkt2(char *globalptr, char *pkt, int pkt_len, int *last_recv_pkt_num, u32 *connid) {
	struct global_s *global;
	global=(struct global_s *)globalptr;


	RC4_crypt(pkt, pkt_len, &global->rc4_recv, 0);

	/*
	memcpy(last_recv_pkt_num,pkt+1,2);
	*last_recv_pkt_num=bswap16(*last_recv_pkt_num);
	(*last_recv_pkt_num)++;
	*last_recv_pkt_num=bswap16(*last_recv_pkt_num);
	*/

	if (DEBUG_LEVEL>=100) show_memory(pkt,pkt_len,"result2:");
	
	if (DEBUG_LEVEL>=100) main_unpack(pkt+3, pkt_len-3);

	// header with pkt id may contain 42
	main_unpack_connid (pkt+3, pkt_len-3, connid);

	
	return 0;
};


int process_tcp_pkt3(char *globalptr, char *pkt, int pkt_len, int *last_recv_pkt_num) {
	struct global_s *global;
	global=(struct global_s *)globalptr;

	
	RC4_crypt(pkt, pkt_len, &global->rc4_recv, 0);

	
	memcpy(last_recv_pkt_num,pkt+1,2);
	//*last_recv_pkt_num=bswap16(*last_recv_pkt_num);
	//(*last_recv_pkt_num)++;
	//*last_recv_pkt_num=bswap16(*last_recv_pkt_num);
	

	if (DEBUG_LEVEL>=100) show_memory(pkt,pkt_len,"result3:");
	
	// supernode check
	// if yet 06 0x21 blob, this is supernode reply
	if (DEBUG_LEVEL>=100) main_unpack(pkt, pkt_len);

	// return data from 42

	
	return 0;
};



///////////////////////////////
//tcp confirm packet
////////////////////////////////
int make_tcp_pkt_confirm(char *globalptr, int last_recv_num, char *pkt, int *pkt_len) {
	int len;

	u8 confirm[]="\x07\x01\xFF\xFF";

	struct global_s *global;
	global=(struct global_s *)globalptr;

	len=sizeof(confirm)-1;

	
	memcpy(confirm+2,&last_recv_num,2);

	if (DEBUG_LEVEL>=100) show_memory(confirm,4,"confirm bef:");

	memcpy(pkt,confirm,len);




	RC4_crypt(pkt, len, &global->rc4_send, 0);
	
	if (DEBUG_LEVEL>=100) show_memory(pkt,len,"send pkt confirm:");

	*pkt_len=len;


	return 0;
};
