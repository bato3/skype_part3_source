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

	u8 result[0x1000];
	int result_len;

	// 1 - 0x0D localnode hash
	// 0 - 0x10 local port
	skype_thing	mythings[] = {
		{0, 0x01, 0x00000003, 0},
		{1, 0x0D, 0xD1ADBEEF, 0xBEEFD1AD},
		{0, 0x10, 0xAABB, 0},
	};
	int mythings_len = 3;

	u8 send_probe_pkt[]="\x30\xFF\xFF\x13\xF2\x01\xFF\xFF";
	len=sizeof(send_probe_pkt)-1;

	seqnum=bswap16(seqnum);
	memcpy(send_probe_pkt+1,(char *)&seqnum,2);
	seqnum=bswap16(seqnum);

	seqnum=bswap16(seqnum-1);
	memcpy(send_probe_pkt+6,(char *)&seqnum,2);
	seqnum=bswap16(seqnum-1);

	memcpy(pkt,send_probe_pkt,len);


	result_len=main_pack(mythings, mythings_len, result, sizeof(result)-1 );
	memcpy(pkt+len,result,result_len);
	len=len+result_len;

	iv = rnd;

	Skype_RC4_Expand_IV (&rc4, iv, 1);
	
	RC4_crypt (pkt, len, &rc4, 0);
	
	*pkt_len=len;


	return 0;
};


int process_tcp_pkt2(char *pkt, int pkt_len, int *last_recv_pkt_num) {
	int ret;

	RC4_crypt(pkt, pkt_len, &rc4_save, 0);

	memcpy(last_recv_pkt_num,pkt+1,2);
	*last_recv_pkt_num=bswap16(*last_recv_pkt_num);
	(*last_recv_pkt_num)++;
	*last_recv_pkt_num=bswap16(*last_recv_pkt_num);

	show_memory(pkt,pkt_len,"result2:");
	
	// supernode check
	// if yet 06 0x21 blob, this is supernode reply
	ret=main_unpack_test(pkt, pkt_len, 0x06, 0x21) ;

	if (ret==0){
		//printf("skype client, dumping nodes\n");
		//main_unpack_saveip(pkt,pkt_len);
		return -1;
	};

	
	return 0;
};

//
//if supernode, we recv nr of clients online.
//if not supernode, 0x153 bytes with alternative host address
//



/*
ask for any 0x4D slots ( 25(0x19) -- max )
po 6 v kajdom
{0, 4, 0x4D, 0x00},
{0, 5, 0x06, 0x00},
==
ask for any 0x03 slots
po 5 nod
{0, 4, 0x03, 0x00},
{0, 5, 0x05, 0x00},

0x10(0x0A - max) nod iz slota 2d
{0, 0, 0x2D, 0x00},
{0, 5, 0x10, 0x00},
*/

/*
"\x14\x05\xD6\x06\x32\x05\xD5\x42\x85\x14\xC9
*/
/*
"\xC4\x02\x05\xD8"
"\x08\x32\x05\xD7\x42\x32\x40\xF6\x4F\xF7"
"\x08\x32\x05\xD9\x42\x34\xCD\x96\x68\xEE"
"\x08\x32\x05\xDA\x42\x34\xC4\xA0\xA6\xEE"
"\x08\x32\x05\xDB\x42\x32\x71\xB3\xCF\xF7"
"\x08\x32\x05\xDC\x42\x34\xAA\x09\xF8\xEE"
"\x08\x32\x05\xDD\x42\x33\xE4\x54\xD6\x22"
"\x08\x32\x05\xDE\x42\x34\xA4\x5B\x64\xEE"
"\x08\x32\x05\xDF\x42\x34\x70\xB1\x77\x9E"
"\x08\x32\x05\xE0\x42\x34\xD8\xF3\x90\xEE"
"\x08\x32\x05\xE1\x42\x33\xD1\xD3\x49\x22"
"\x08\x32\x05\xE2\x42\x34\x58\x06\x6D\x9E"
"\x08\x32\x05\xE3\x42\x34\x56\x8B\x86\x9E"
"\x08\x32\x05\xE4\x42\x32\x62\x78\x97\xF7"
"\x08\x32\x05\xE5\x42\x33\x1C\x63\x25\xFA"
"\x08\x32\x05\xE6\x42\x34\xDC\xE2\x94\xEE"
"\x08\x32\x05\xE7\x42\x34\xDE\xB4\xCA\xEE"
;
*/



///////////////////////////////
//tcp third packet
////////////////////////////////
int make_tcp_pkt3(u16 seqnum, u32 rnd, int last_recv_pkt_num, int start_slot, char *pkt, int *pkt_len) {
	int len;
	int i;
	u16 seqnum42;
	
	u8 result[0x2000];
	int result_len;
	u8 bufheader[0x10];
	int bufheader_len;
	u8 pkt_tmp[0x2000];
	int pkt_tmp_len;

	u32 num_nodes_from_slot=0x0A;
	skype_thing	mythings[] = {
		{0, 0, 0xFF, 0x00},
		{0, 5, 0xFF, 0x00},
	};
	int mythings_len=2;
	/*
	u32 slots_num[] = { 0x002D, 0x055A, 0x006E, 0x003D,
						0x0523, 0x01C1, 0x04D5, 0x036D,
						0x07A7, 0x01AA, 0x0309, 0x0303,
						0x0038, 0x00AB, 0x07DD, 0x07F6 };
	*/
	int slots_num_size=16;
	u8 send_pkt1[] = "\x07\x01\xFF\xFF";



	len=0;
	seqnum42=seqnum;

	// pkt1 confirm 
	memcpy(send_pkt1+2,&last_recv_pkt_num,2);
	memcpy(pkt+len,send_pkt1,sizeof(send_pkt1)-1);
	len+=sizeof(send_pkt1)-1;


	seqnum42+=3;
	pkt_tmp_len=0;
	for(i=0;i<slots_num_size;i++){

		if (i>1) {
			seqnum42++;
		};

		//mythings[0].m=slots_num[i];
		mythings[0].m=start_slot;
		mythings[0].n=0;
		
		start_slot++;

		mythings[1].m=num_nodes_from_slot;
		mythings[1].n=0;

		result_len=main_pack(mythings, mythings_len, result, sizeof(result)-1 );

		if (i==0){ seqnum42-=2; };
		bufheader_len=first_bytes_header2(seqnum42, bufheader, sizeof(bufheader)-1, result, result_len);
		if (i==0){ seqnum42+=2; };

		memcpy(pkt_tmp+pkt_tmp_len,bufheader,bufheader_len);
		pkt_tmp_len+=bufheader_len;
		memcpy(pkt_tmp+pkt_tmp_len,result,result_len);
		pkt_tmp_len+=result_len;

	};


	seqnum42=seqnum+2;
	bufheader_len=first_bytes_size(seqnum42, bufheader, sizeof(bufheader)-1, pkt_tmp, pkt_tmp_len);

	memcpy(pkt+len,bufheader,bufheader_len);
	len+=bufheader_len;
	memcpy(pkt+len,pkt_tmp,pkt_tmp_len);
	len+=pkt_tmp_len;


	show_memory(pkt,len,"send pkt3:");
	
	RC4_crypt (pkt, len, &rc4, 0);

	*pkt_len=len;

	return 0;
};


int process_tcp_pkt3(char *pkt, int pkt_len, int *last_recv_pkt_num) {
	
	RC4_crypt (pkt, pkt_len, &rc4_save, 0);

	memcpy(last_recv_pkt_num,pkt+2,2);

	/*
	*last_recv_pkt_num=bswap16(*last_recv_pkt_num);
	(*last_recv_pkt_num)++;
	*last_recv_pkt_num=bswap16(*last_recv_pkt_num);
	*/

	show_memory(pkt,pkt_len,"result3:");

	main_unpack(pkt,pkt_len);
	main_unpack_saveip(pkt,pkt_len);


	return 0;
};


