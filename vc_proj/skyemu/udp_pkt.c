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


extern u8 bigbuf[0x100000];
extern u32 bigbuf_count;

extern int main_pack(skype_thing *mythings, int mythings_len, u8 *outdata, u32 maxlen);
extern int main_pack_into(skype_list *list, u8 *outdata, u32 maxlen);

extern int encode_to_7bit(char *buf, unsigned int word, int limit);

/////////////////////
// udp first packet//
/////////////////////
int make_udp_probe_pkt1(char *ourip,char *destip,unsigned short seqnum,u32 rnd, char *pkt, int *pkt_len) {
	RC4_context rc4;
	int len;
	u32 tmp;

	u32	iv, iv3[3];
	u32 targetip;
	u32 publicip;
	u32 pkt_crc32;

	u8 send_probe_pkt[]="\x04\xda\x01\xFF\xFF\x42\x15";
	len=sizeof(send_probe_pkt)-1;


	seqnum=bswap16(seqnum);
	memcpy(send_probe_pkt+3,(char *)&seqnum,2);
	seqnum=bswap16(seqnum);

	targetip=inet_addr(destip);
	publicip=inet_addr(ourip);

	iv3[0] = ntohl(publicip);
	iv3[1] = ntohl(targetip);
	iv3[2] = seqnum+1;

	iv = crc32(iv3,3) ^ rnd;

	pkt_crc32=Calculate_CRC32( (char *)send_probe_pkt,len);

	Skype_RC4_Expand_IV (&rc4, iv, 1);
	

	RC4_crypt (send_probe_pkt, len, &rc4, 0);

	//make send pkt
	seqnum++;
	seqnum=bswap16(seqnum);
	memcpy(pkt,(char*)&seqnum,2);
	seqnum=bswap16(seqnum);
	//02 - tip dannih
	memcpy(pkt+2,"\x02",1);
	//init data//our rnd seed?
	tmp=bswap32(rnd);
	memcpy(pkt+3,(char*)&tmp,4);
	//crc32
	pkt_crc32=bswap32(pkt_crc32);
	memcpy(pkt+7,(char *)&pkt_crc32,4);
	pkt_crc32=bswap32(pkt_crc32);
	//rc4 data
	memcpy(pkt+11,(char *)&send_probe_pkt,len);
	len=18;

	*pkt_len=len;

	return 0;
};


int process_udp_probe_pkt1(char *pkt, int pkt_len, u32 *remote_udp_rnd, u32 *public_ip) {

	if (pkt_len != 0x0B) {
		//printf("Not Nack packet recv!\n");
		return -1;
	};

	memcpy(remote_udp_rnd,pkt+7,4);
	*remote_udp_rnd=bswap32(*remote_udp_rnd);

	memcpy(public_ip,pkt+3,4);

	return 1;
};




///////////////////////
// udp second packet //
///////////////////////
int make_udp_probe_pkt2(char *ourip,char *ip,unsigned short seqnum,u32 rnd,u32 remote_udp_rnd,char *pkt,int *pkt_len) {
	RC4_context rc4;
	u32	iv;
	u32 targetip;
	u32 publicip;
	u32 pkt_crc32;
	int len;

	u8 send_probe_pkt[]="\x04\xda\x01\xFF\xFF\x42\x15";
	len=sizeof(send_probe_pkt)-1;


	seqnum=bswap16(seqnum);
	memcpy(send_probe_pkt+3,(char *)&seqnum,2);
	seqnum=bswap16(seqnum);

	targetip=inet_addr(ip);
	publicip=inet_addr(ourip);

	
	seqnum++;
	seqnum=bswap16(seqnum);
	iv = bswap16(seqnum) ^ remote_udp_rnd;
	seqnum=bswap16(seqnum);
	seqnum--;

	pkt_crc32=Calculate_CRC32( (char *)send_probe_pkt,len);

	Skype_RC4_Expand_IV (&rc4, iv, 1);
		
	RC4_crypt (send_probe_pkt, len, &rc4, 0);

	//make send pkt
	seqnum++;
	seqnum=bswap16(seqnum);
	memcpy(pkt,(char*)&seqnum,2);
	seqnum=bswap16(seqnum);
	len=2;
	//03 01 tip dannih?
	memcpy(pkt+2,"\x03\x01",2);
	len=4;	
	//remote newrnd
	remote_udp_rnd=bswap32(remote_udp_rnd);
	memcpy(pkt+4,(char*)&remote_udp_rnd,4);
	remote_udp_rnd=bswap32(remote_udp_rnd);
	len=8;
	//dst ip
	targetip=bswap32(targetip);
	memcpy(pkt+8,(char*)&targetip,4);
	targetip=bswap32(targetip);
	len=12;
	//crc32
	pkt_crc32=bswap32(pkt_crc32);
	memcpy(pkt+12,(char *)&pkt_crc32,4);
	pkt_crc32=bswap32(pkt_crc32);
	len=16;
	//rc4
	memcpy(pkt+16,(char *)&send_probe_pkt,len);
	len=23;

	*pkt_len=len;


	return 0;

};


int process_udp_probe_pkt2(char *pkt,int pkt_len,char *ourip,char *destip) {
	RC4_context rc4;
	u32 newrnd;
	u32 targetip;
	u32 publicip;
	u32	iv3[3];
	u32 iv;

	targetip=inet_addr(destip);
	publicip=inet_addr(ourip);


	if (pkt_len!=0x12) {
		//printf("probe accepted len mismatch\n");
		//printf("not supernode\n");
		return -1;
	};

	pkt_len=pkt_len-0x0B;

	newrnd = bswap32(dword(pkt+3)); //last byte in Nack, first in reply

	iv3[2] = bswap16(word(pkt)); //pkt seq num
	iv3[1] = bswap32(publicip);	// target_IP
	iv3[0] = bswap32(targetip);	// source_IP

	iv = crc32(iv3,3) ^ newrnd;

	Skype_RC4_Expand_IV (&rc4, iv, 1);
	
	RC4_crypt (pkt+0x0B, pkt_len, &rc4, 0);

	if (strncmp(pkt+0x0B,"\x04\xE3\x01",3)!=0) {
		//printf("probe not accepted\n);
		//printf("its skype client\n");
		return -1;
	};



	return 1;
};


////////////////////////////////
// end udp section
////////////////////////////////



////////////////////////
// udp reqNodes packet//
////////////////////////
int make_udp_reqnodes_pkt1(char *ourip, char *destip, u16 seqnum, u32 rnd, char *pkt, int *pkt_len) {
	RC4_context rc4;
	int len;

	u32	newrnd, iv, iv3[3];
	u32 targetip;
	u32 publicip;
	u32 pkt_crc32;

	u8 send_probe_pkt[]="\x08\xE2\x02\xFF\xFF\x42\xB3\x79\x93\x96\xA0";

	len=sizeof(send_probe_pkt)-1;




	seqnum=bswap16(seqnum);
	memcpy(send_probe_pkt+3,(char *)&seqnum,2);
	seqnum=bswap16(seqnum);

	
	targetip=inet_addr(destip);
	publicip=inet_addr(ourip);

	//prepare

	//bswap32(dword(b+i+p));
	newrnd = rnd;
	printf("newrnd=%08X\n",newrnd);

	//init data for rc4
	iv3[0] = ntohl(publicip);   // our public ip
	iv3[1] = ntohl(targetip);	// target_IP
	iv3[2] = seqnum+1;   // pkt seq num


	//init seed for rc4
	iv = crc32(iv3,3) ^ newrnd;

	//crc32
	pkt_crc32=Calculate_CRC32( (char *)send_probe_pkt,len);

	//init rc4 structure by iv
	Skype_RC4_Expand_IV (&rc4, iv, 1);

	
	show_memory(send_probe_pkt,len,"bef rc4:");
	RC4_crypt (send_probe_pkt, len, &rc4, 0);
	show_memory(send_probe_pkt,len,"aft rc4:");



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
	memcpy(pkt+11,(char *)&send_probe_pkt,len);

	len=len+11;

	//display pkt bef send

	show_memory(pkt,len,"send pkt:");

	*pkt_len=len;


	return 0;

};


int process_udp_reqnodes_pkt1(char *pkt,int pkt_len, char *ourip, char *destip) {
	RC4_context rc4;
	u32 newrnd;
	u32 targetip;
	u32 publicip;
	u32	iv3[3];
	u32 iv;
	//int len;


	show_memory(pkt,pkt_len,"result len:");

	//len=len-15;

	targetip=inet_addr(destip);
	publicip=inet_addr(ourip);

	newrnd = bswap32(dword(pkt+7)); //last byte in Nack, first in reply

	iv3[2] = bswap16(word(pkt));   //pkt seq num
	iv3[1] = bswap32(publicip);	// target_IP
	iv3[0] = bswap32(targetip);	// source_IP

	iv = crc32(iv3,3) ^ newrnd;

	Skype_RC4_Expand_IV (&rc4, iv, 1);


	show_memory(pkt+15,pkt_len-15,"bef rc4:");	
	RC4_crypt (pkt+15, pkt_len-15, &rc4, 0);
	show_memory(pkt+15,pkt_len-15,"aft rc4:");	


	main_unpack(pkt+15,pkt_len-15);


	return 0;
};



////////////////////////
// udp reqUsers packet//
////////////////////////
int make_udp_requser_pkt1(char *ourip,char *destip, u16 seqnum, u32 rnd, char *pkt, int *pkt_len) {
	RC4_context rc4;
	int len;

	u32	newrnd, iv, iv3[3];
	u32 targetip;
	u32 publicip;
	u32 pkt_crc32;
	

	/*
	skype_thing	mythings[] = {
		{0, 0x04, 0x10, 0},
		{0, 0x05, 0x06, 0},
	};
	int mythings_len=2;
	*/


	//xot_iam
	//u8 send_probe_pkt[]="\x12\x72\x05\xF6\x42\xF6\x23\x1F\xA2\xA1\x1B\x8D\xC2\xB2\x69\xDE\x55\x5B\xC8\x92";
	
	//cyberozz
	//u8 send_probe_pkt[]="\x12\x72\xFF\xFF\x42\xF6\x22\xF8\xBF\xE4\x57\xA9\xE4\x54\xC3\xE7\xD1\x6A\xA2\xE0";
	
	//sean_oneil
	//u8 send_probe_pkt[]="\x13\x72\xFF\xFF\x42\xF6\x23\x1E\x65\x56\xA2\x5D\x7E\xAD\x00\xD2\xDC\xD0\x85\xEC\xFB";

	//alexsword25
	//u8 send_probe_pkt[]="\x14\x72\xFF\xFF\x42\xF6\x23\x0D\x95\xFC\x63\xF1\xF4\x16\xC4\xBB\x22\x02\x2B\xA8\x73\x6B";

	//partnersingrants
	//u8 send_probe_pkt[]="\x15\x72\xFC\xC2\x42\xF6\x22\xF4\x75\x67\x38\x10\x38\xEF\x9F\xB4\x15\x23\xFB\x07\x4B\x15\xD9";

	// search substring in skypename


/*
    // bigbones
	u8 send_probe_pkt[]=
"\x11\x72\xE7\x06\x42\xF6\x22\xFF\xE4\xC1\x02\x1C\xC2\x80\x27\x17"
"\x82\x12\xB9\x12\x72\xE7\x12\x42\xF6\x22\xFF\xE4\xC1\x02\x1C\xC3"
"\xB3\x39\x62\x0C\x1A\xEE\x25\x11\x72\xE7\x18\x42\xF6\x22\xFF\xE4"
"\xC1\x02\x1C\xC3\xE7\x5D\x6A\x86\xBD\x6F"
;
*/

/*
//alexdwar - no one exist
	u8 send_probe_pkt[]=
"\x11\x72\xE9\x1A\x42\xF6\x23\x0D\x95\xF5\x87\xBA\x64\x17\x9F\xE4"
"\xE6\x7A\xDD\x12\x72\xE9\x1C\x42\xF6\x23\x0D\x95\xF5\x87\xBA\x64"
"\x73\xA5\xD7\x30\xD7\x1C\x53\x12\x72\xE9\x1D\x42\xF6\x23\x0D\x95"
"\xF5\x87\xBA\x64\x83\x45\xF5\x69\x95\x01\x29"
;
*/


	// goodok
	u8 send_probe_pkt[]=
"\x10\x72\xFE\xAF\x42\xF6\x22\xFB\x4A\x92\xA4\xAA\x29\x32\x89\x31"
"\xDB\x1D\x11\x72\xFE\xBB\x42\xF6\x22\xFB\x4A\x92\xA4\xAA\x75\xE3"
"\x77\xEB\x00\x06\x8F\x11\x72\xFE\xC1\x42\xF6\x22\xFB\x4A\x92\xA4"
"\xAA\x82\xE9\x1D\x16\x41\x01\x81"
;



/*
	//goodon
	u8 send_probe_pkt[]=
"\x10\x72\xEC\xF0\x42\xF6\x22\xFB\x4A\x92\xD5\x91\xEE\xC0\x71\x26"
"\x40\xAA\x10\x72\xEC\xFC\x42\xF6\x22\xFB\x4A\x92\xD5\x94\xCF\xE3"
"\xB9\x3D\x5E\x1A\x10\x72\xED\x02\x42\xF6\x22\xFB\x4A\x92\xD5\x95"
"\x4D\x0E\x1E\x3F\x1C\x76"
;
*/

	/*
	//goddy
	u8 send_probe_pkt[]=
"\x10\x72\xEE\xAB\x42\xF6\x22\xFB\x39\xAD\xD5\xB7\xC5\x95\xCB\x26"
"\xBE\x39\x10\x72\xEE\xB7\x42\xF6\x22\xFB\x39\xAD\xD5\xBA\xC1\x54"
"\xC8\xFD\x78\xA7\x10\x72\xEE\xBD\x42\xF6\x22\xFB\x39\xAD\xD5\xBB"
"\x43\x03\xDB\x07\x61\x88"
;
*/

	/*
	//goodby
	u8 send_probe_pkt[]=
"\x11\x72\xF0\x14\x42\xF6\x22\xFB\x4A\x8F\x6C\xAF\xDF\xAC\x33\xB1"
"\x2E\xB2\xFE\x11\x72\xF0\x1F\x42\xF6\x22\xFB\x4A\x8F\x6C\xAF\xE7"
"\x8A\x3D\x57\x2F\xFF\x03\x11\x72\xF0\x25\x42\xF6\x22\xFB\x4A\x8F"
"\x6C\xAF\xE8\xE0\x37\x62\xF5\x66\x1B"
;
*/




	len=sizeof(send_probe_pkt)-1;


	//seqnum=bswap16(seqnum);
	//memcpy(send_probe_pkt+2,(char *)&seqnum,2);
	//seqnum=bswap16(seqnum);

	

	targetip=inet_addr(destip);
	publicip=inet_addr(ourip);

	//prepare

	newrnd = rnd;


	iv3[0] = ntohl(publicip);   // our public ip
	iv3[1] = ntohl(targetip);	// target_IP
	iv3[2] = seqnum+1;   // pkt seq num


	//init seed for rc4
	iv = crc32(iv3,3) ^ newrnd;
	//crc32
	pkt_crc32=Calculate_CRC32( (char *)send_probe_pkt,len);

	//init rc4 structure by iv
	Skype_RC4_Expand_IV (&rc4, iv, 1);

	
	show_memory(send_probe_pkt,len,"bef rc4:");
	RC4_crypt (send_probe_pkt, len, &rc4, 0);
	show_memory(send_probe_pkt,len,"aft rc4:");



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
	memcpy(pkt+11,(char *)&send_probe_pkt,len);

	len=len+11;

//display pkt bef send

	show_memory(pkt,len,"send pkt:");

	*pkt_len=len;

	return 0;
};




int process_udp_requser_pkt1(char *pkt,int pkt_len,char *ourip,char *destip) {
	RC4_context rc4;
	u32 newrnd;
	u32 targetip;
	u32 publicip;
	u32	iv3[3];
	u32 iv;


	show_memory(pkt,pkt_len,"result len:");

	targetip=inet_addr(destip);
	publicip=inet_addr(ourip);

	newrnd = bswap32(dword(pkt+3));

	iv3[2] = bswap16(word(pkt)); 
	iv3[1] = bswap32(publicip);
	iv3[0] = bswap32(targetip);

	iv = crc32(iv3,3) ^ newrnd;

	Skype_RC4_Expand_IV (&rc4, iv, 1);


	show_memory(pkt+11,pkt_len-11,"bef rc4:");	
	RC4_crypt (pkt+11, pkt_len-11, &rc4, 0);
	show_memory(pkt+11,pkt_len-11,"aft rc4:");	


	main_unpack(pkt+11,pkt_len-11);


	return 0;
};




////////////////////////////////////////////////////////////////////




/*
05-00: {
03-00: "goodok"
00-01: 00 00 00 00
00-02: 10 00 00 00
05-00: }
06-01: 10 00 00 00, 0B 00 00 00
05-00: {
03-00: "goodok"
00-01: 05 00 00 00
00-02: 10 00 00 00
05-00: }
06-01: 10 00 00 00, 0B 00 00 00
05-00: {
03-00: "goodok"
00-01: 09 00 00 00
00-02: 14 00 00 00
05-00: }
06-01: 10 00 00 00, 0B 00 00 00
*/

//partnersingrants
//u8 send_probe_pkt[]="\x15\x72\xFC\xC2\x42\xF6\x22\xF4\x75\x67\x38\x10\x38\xEF\x9F\xB4\x15\x23\xFB\x07\x4B\x15\xD9";


////////////////////////
// udp search prepare //
////////////////////////
int make_udp_search_prepare(char *req_user, u16 seqnum, char *send_pkt, int *s_len, int num1, int num2) {
	u8 result[0x1000];
	int result_len;

	u8 header[0x100];
	int header_len=5;

	int send_len;


	// into
	skype_thing	mythings2[] = {
		{03, 00, (u32 )req_user, 0x00},
		{00, 01, 0x00, 0x00},
		{00, 02, 0x00, 0x00},
	};
	int mythings2_len=3;
	skype_list		list2 = {&list2, mythings2, mythings2_len, mythings2_len};

	// main
	u32 dw[2] = { 0x10,0x0B };
	skype_thing	mythings[] = {
		{05, 00, (u32 )&list2, 0x00},
		{06, 01, (u32 )&dw, 2<<2},
	};
	int mythings_len=2;
	skype_list		list = {&list, mythings, mythings_len, mythings_len};


	mythings2[1].m=num1;
	mythings2[2].m=num2;

	// pack
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
// udp req Search packet//
////////////////////////
int make_udp_reqsearch_pkt1(char *ourip,char *destip, u16 seqnum, u32 rnd, char *pkt, int *pkt_len) {
	RC4_context rc4;

	u8 send_pkt[0x1000];
	int send_len;
	int slen;

	u16 seqnum42;

	u32	newrnd, iv, iv3[3];
	u32 targetip;
	u32 publicip;
	u32 pkt_crc32;

	//u8 req_user[]="putin";

	//u8 req_user[]="alex.gordon";
	//u8 req_user[]="alex.gordon8";
	//u8 req_user[]="alex.";
	u8 req_user[]="shamanyst";


	//seqnum=0xFEAF;

	// prepare
	send_len=0;

	seqnum42=seqnum;
	make_udp_search_prepare(req_user, seqnum42, (char *)&send_pkt+send_len, &slen, 0x00, 0x10);
	send_len+=slen;

	seqnum42+=12;
	make_udp_search_prepare(req_user, seqnum42, (char *)&send_pkt+send_len, &slen, 0x05, 0x10);
	send_len+=slen;

	seqnum42+=6;
	make_udp_search_prepare(req_user, seqnum42, (char *)&send_pkt+send_len, &slen, 0x09, 0x14);
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
	show_memory(send_pkt,send_len,"bef rc4:");
	RC4_crypt  (send_pkt,send_len, &rc4, 0);
	show_memory(send_pkt,send_len,"aft rc4:");



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
	show_memory(pkt,send_len+11,"send pkt:");

	*pkt_len=send_len+11;


	return 0;
};




int process_udp_reqsearch_pkt1(char *pkt,int pkt_len,char *ourip,char *destip) {
	RC4_context rc4;
	u32 newrnd;
	u32 targetip;
	u32 publicip;
	u32	iv3[3];
	u32 iv;
	int flagbig;
	int header_len;

	flagbig=0;
	if (pkt_len > 0x500) {
		flagbig=1;
	};

	show_memory(pkt,pkt_len,"result len:");

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

	show_memory(pkt+header_len,pkt_len-header_len,"bef rc4:");	
	RC4_crypt (pkt+header_len, pkt_len-header_len, &rc4, 0);
	show_memory(pkt+header_len,pkt_len-header_len,"aft rc4:");	


	memcpy(bigbuf+bigbuf_count,pkt+header_len,pkt_len-header_len);
	bigbuf_count+=pkt_len-header_len;

	//main_unpack(pkt+header_len,pkt_len-header_len);



	return 0;
};


