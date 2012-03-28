//
//udp communication
//

#include<stdio.h>

#include <winsock.h>  
#include "rc4/Expand_IV.h"

extern unsigned int Calculate_CRC32(char *crc32, int bytes);

extern int show_memory(char *mem, int len, char *text);
extern int main_unpack (u8 *indata, u32 inlen);
extern int main_unpack_once (u8 *indata, u32 inlen);

typedef struct _skype_thing {
	u32				type, id, m, n;
} skype_thing;

typedef struct _skype_list
{
	struct _skype_list	*next;
	skype_thing			*thing;
	u32					allocated_things;
	u32					things;
} skype_list;



extern int main_pack(skype_thing *mythings, int mythings_len, u8 *outdata, u32 maxlen);
extern int main_pack_into(skype_list *list, u8 *outdata, u32 maxlen);
extern int encode_to_7bit(char *buf, unsigned int word, int limit);




////////////////////////
// udp search prepare //
////////////////////////
int make_udp_profile_prepare(char *req_user, u16 seqnum, char *send_pkt, int *s_len, int num1, int num2) {
	u8 result[0x1000];
	int result_len;
	u8 header[0x100];
	int header_len=5;
	int send_len;


	skype_thing	mythings2[] = {
		{03, 00, (u32 )req_user, 0x00},
		{00, 01, 0x00, 0x00},
		{00, 02, 0x00, 0x00},
	};
	int mythings2_len=3;
	skype_list		list2 = {&list2, mythings2, mythings2_len, mythings2_len};

	u32 dw[2]  = { 0x10,0x0B };

	skype_thing	mythings[] = {
		{05, 00, (u32 )&list2, 0x00},
		{06, 01, (u32 )&dw, 2<<2},
	};
	int mythings_len=2;

	/*
	//u32 dw2[8] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
	skype_thing	mythings[] = {
		{05, 00, (u32 )&list2, 0x00},
		{06, 01, (u32 )&dw, 2<<2},
		{06, 02, (u32 )&dw2, 8<<2},
	};
	int mythings_len=3;
	*/

	skype_list		list = {&list, mythings, mythings_len, mythings_len};



	mythings2[1].m=num1;
	mythings2[2].m=num2;

	result_len=main_pack_into(&list, result, sizeof(result)-1 );

	//show_memory(result,result_len,"packed42:");
	//main_unpack(result,result_len);

	header_len=encode_to_7bit(header, result_len+2, header_len);


	// pkt size
	send_len=0;
	memcpy(send_pkt+send_len,header,header_len);
	send_len+=header_len;

	// cmd 
	send_pkt[send_len]=0x72;
	send_len++;

	// seqnum
	seqnum=bswap16(seqnum);
	memcpy(send_pkt+send_len,(char *)&seqnum,2);
	seqnum=bswap16(seqnum);
	send_len+=2;

	// 42 data
	memcpy(send_pkt+send_len,result,result_len);
	send_len+=result_len;

	*s_len=send_len;


	return 0;

};



////////////////////////
// udp request Profile //
////////////////////////
int make_udp_profile_pkt1(char *ourip,char *destip, u16 seqnum, u32 rnd, char *req_user, char *pkt, int *pkt_len) {
	RC4_context rc4;

	u8 send_pkt[0x1000];
	int send_len;
	int slen;

	u16 seqnum42;

	u32	newrnd, iv, iv3[3];
	u32 targetip;
	u32 publicip;
	u32 pkt_crc32;

	
	
	send_len=0;

	seqnum42=seqnum;
	make_udp_profile_prepare(req_user, seqnum42, (char *)&send_pkt+send_len, &slen, 0x00, 0x10);
	send_len+=slen;


	// make rc4 init
	targetip=inet_addr(destip);
	publicip=inet_addr(ourip);
	//prepare
	newrnd = rnd;
	iv3[0] = ntohl(publicip);
	iv3[1] = ntohl(targetip);
	iv3[2] = seqnum+1;
	//init seed for rc4
	iv = crc32(iv3,3) ^ newrnd;
	//crc32
	pkt_crc32=Calculate_CRC32( (char *)send_pkt,send_len);
	//init rc4 structure by iv
	Skype_RC4_Expand_IV (&rc4, iv, 1);

	
	// encode rc4
	//show_memory(send_pkt,send_len,"bef rc4:");
	RC4_crypt  (send_pkt,send_len, &rc4, 0);
	//show_memory(send_pkt,send_len,"aft rc4:");


	//make send pkt

	//pktnum+1,
	seqnum++;
	seqnum=bswap16(seqnum);
	memcpy(pkt,(char*)&seqnum,2);
	seqnum=bswap16(seqnum);

	//02 - tip dannih ?
	memcpy(pkt+2,"\x02",1);
	
	//init data//our rnd seed?
	newrnd=bswap32(newrnd);
	memcpy(pkt+3,(char*)&newrnd,4);
	newrnd=bswap32(newrnd);
	
	//crc32
	pkt_crc32=bswap32(pkt_crc32);
	memcpy(pkt+7,(char *)&pkt_crc32,4);
	pkt_crc32=bswap32(pkt_crc32);

	//rc4 data
	memcpy(pkt+11,(char *)&send_pkt,send_len);

	//display pkt bef send
	//show_memory(pkt,send_len+11,"send pkt:");

	*pkt_len=send_len+11;


	return 0;
};



////////////////////////////////////////////////////////


/*
05-00: {
03-00: "alex"
00-01: 09 00 00 00
00-02: 14 00 00 00
05-00: }
05-00: {
03-00: "us"
00-01: 00 00 00 00
00-02: 28 00 00 00
05-00: }
06-01: 10 00 00 00, 0B 00 00 00
*/

///////////////////////////////////
// udp search prepare by country //
///////////////////////////////////
int make_udp_search_by_country_prepare(char *req_user, char *req_country, u16 seqnum, char *send_pkt, int *s_len) {
	u8 result[0x1000];
	int result_len;
	u8 header[0x100];
	int header_len=5;
	int send_len;


	skype_thing	mythings3[] = {
		{03, 00, (u32 )req_country, 0x00},
		{00, 01, 0x00, 0x00},
		{00, 02, 0x28, 0x00},
	};
	int mythings3_len=3;
	skype_list		list3 = {&list3, mythings3, mythings3_len, mythings3_len};

	skype_thing	mythings2[] = {
		{03, 00, (u32 )req_user, 0x00},
		{00, 01, 0x09, 0x00},
		{00, 02, 0x14, 0x00},
	};
	int mythings2_len=3;
	skype_list		list2 = {&list2, mythings2, mythings2_len, mythings2_len};

	u32 dw[2]  = { 0x10,0x0B };
	skype_thing	mythings[] = {
		{05, 00, (u32 )&list2, 0x00},
		{05, 00, (u32 )&list3, 0x00},
		{06, 01, (u32 )&dw, 2<<2},
	};
	int mythings_len=3;

	skype_list		list = {&list, mythings, mythings_len, mythings_len};



	result_len=main_pack_into(&list, result, sizeof(result)-1 );

	//show_memory(result,result_len,"packed42:");
	//main_unpack(result,result_len);

	header_len=encode_to_7bit(header, result_len+2, header_len);
	if (header_len==-1){
		return -1;
	};

	// pkt size
	send_len=0;
	memcpy(send_pkt+send_len,header,header_len);
	send_len+=header_len;

	// cmd 
	send_pkt[send_len]=0x72;
	send_len++;

	// seqnum
	seqnum=bswap16(seqnum);
	memcpy(send_pkt+send_len,(char *)&seqnum,2);
	seqnum=bswap16(seqnum);
	send_len+=2;

	// 42 data
	memcpy(send_pkt+send_len,result,result_len);
	send_len+=result_len;

	*s_len=send_len;


	return 0;

};



////////////////////////
// udp request Search //
////////////////////////
int make_udp_search_by_county_pkt1(char *ourip,char *destip, u16 seqnum, u32 rnd, char *req_user, char *req_country,
																					char *pkt, int *pkt_len) {
	RC4_context rc4;

	u8 send_pkt[0x1000];
	int send_len;
	int slen;

	u16 seqnum42;

	u32	newrnd, iv, iv3[3];
	u32 targetip;
	u32 publicip;
	u32 pkt_crc32;
	int ret;
	
	
	send_len=0;

	seqnum42=seqnum;
	ret=make_udp_search_by_country_prepare(req_user, req_country, seqnum42, (char *)&send_pkt+send_len, &slen);
	if (ret==-1){
		//printf("prepare failed\n");
		return -1;
	};
	send_len+=slen;


	// make rc4 init
	targetip=inet_addr(destip);
	publicip=inet_addr(ourip);
	//prepare
	newrnd = rnd;
	iv3[0] = ntohl(publicip);
	iv3[1] = ntohl(targetip);
	iv3[2] = seqnum+1;
	//init seed for rc4
	iv = crc32(iv3,3) ^ newrnd;
	//crc32
	pkt_crc32=Calculate_CRC32( (char *)send_pkt,send_len);
	//init rc4 structure by iv
	Skype_RC4_Expand_IV (&rc4, iv, 1);

	
	// encode rc4
	//show_memory(send_pkt,send_len,"bef rc4:");
	RC4_crypt  (send_pkt,send_len, &rc4, 0);
	//show_memory(send_pkt,send_len,"aft rc4:");


	//make send pkt

	//pktnum+1,
	seqnum++;
	seqnum=bswap16(seqnum);
	memcpy(pkt,(char*)&seqnum,2);
	seqnum=bswap16(seqnum);

	//02 - tip dannih ?
	memcpy(pkt+2,"\x02",1);
	
	//init data//our rnd seed?
	newrnd=bswap32(newrnd);
	memcpy(pkt+3,(char*)&newrnd,4);
	newrnd=bswap32(newrnd);
	
	//crc32
	pkt_crc32=bswap32(pkt_crc32);
	memcpy(pkt+7,(char *)&pkt_crc32,4);
	pkt_crc32=bswap32(pkt_crc32);

	//rc4 data
	memcpy(pkt+11,(char *)&send_pkt,send_len);

	//display pkt bef send
	//show_memory(pkt,send_len+11,"send pkt:");

	*pkt_len=send_len+11;


	return 0;
};


/////////////////////////////////////////////////////

//
// Process all search reply
//
int process_udp_search_pkt1(char *pkt,int pkt_len,char *ourip,char *destip,char *mainbuf, u32 *mainbuf_len) {
	RC4_context rc4;
	u32 newrnd;
	u32 targetip;
	u32 publicip;
	u32	iv3[3];
	u32 iv;
	int flagbig;
	int header_len;
	u32 count;

	flagbig=0;
	if (pkt_len > 0x520) {
		flagbig=1;
	};

	//show_memory(pkt,pkt_len,"result len:");

	targetip=inet_addr(destip);
	publicip=inet_addr(ourip);

	if (flagbig){
		newrnd = bswap32(dword(pkt+7));
	}else{
		newrnd = bswap32(dword(pkt+3));
	};

	iv3[2] = bswap16(word(pkt)); 
	iv3[1] = bswap32(publicip);
	iv3[0] = bswap32(targetip);

	iv = crc32(iv3,3) ^ newrnd;

	Skype_RC4_Expand_IV (&rc4, iv, 1);

	if (flagbig){
		header_len=15;
	}else{
		header_len=11;
	};

	//show_memory(pkt+header_len,pkt_len-header_len,"bef rc4:");	
	RC4_crypt (pkt+header_len, pkt_len-header_len, &rc4, 0);
	show_memory(pkt+header_len,pkt_len-header_len,"aft rc4:");	


	count=*mainbuf_len;
	memcpy(mainbuf+count,pkt+header_len,pkt_len-header_len);
	*mainbuf_len=count+(pkt_len-header_len);


	//main_unpack(pkt+header_len,pkt_len-header_len);


	return 0;
};


