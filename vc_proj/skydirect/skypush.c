// skypush.c : Defines the entry point for the console application.
//


#include <stdio.h>
#include <stdlib.h>

#include <string.h>  
#include <winsock.h>  
#include <windows.h>  
#include <sys/types.h>  
#include <time.h>
#include <errno.h>  

#include "short_types.h"

#include "global_vars.h"

extern int main_unpack(u8 *indata, u32 inlen);
extern int main_unpack_get (u8 *indata, u32 inlen, u8 *ipinfo, u32 *ipinfo_len);
extern int slot_find(u8 *str);

extern int make_udp_push_pkt1(char *globalptr, char *ourip,char *destip, u16 seqnum, u32 rnd, char *pkt, int *pkt_len);
extern int process_udp_push_pkt1(char *globalptr, char *pkt,int pkt_len,char *ourip,char *destip);

extern int udp3_talk(char *remoteip, u16 remoteport, char *buf, int len, char *result, int result_maxlen);

extern int show_memory(char *mem, int len, char *text);


extern int DEBUG;





//
// Supernode udp user request
//
int snode_udp_push(char *globalptr, char *destip, u16 destport, char *our_public_ip) {
	u16 seqnum;
	u32 rnd;
	char resp[0x1000];
	int resp_len;
	char pkt[0x1000];
	int pkt_len;
	int retcode;

	struct global_s *global;
	global=(struct global_s *)globalptr;



	seqnum=rand() % 0x10000;

	rnd=rand() % 0x10000;
	rnd+=(rand() % 0x10000)*0x10000;
	

	// pkt1
	retcode=make_udp_push_pkt1(globalptr,our_public_ip,destip,seqnum,rnd,(char *)pkt,&pkt_len);
	if (retcode==-1) {
		printf("prepare error\n");
		return -1;
	};
	resp_len=udp3_talk(destip,destport,pkt,pkt_len,resp,sizeof(resp));
	if (resp_len<0) {
		printf("socket comm error\n");
		return -1;
	};
	if (resp_len==0) {
		printf("timeout\n");
		return -2;
	};
	
	if (DEBUG) printf("part len:0x%08X\n",resp_len);

	retcode=process_udp_push_pkt1(globalptr,resp,resp_len,our_public_ip,destip);
	if (retcode==-1) {
		printf("Push pkt reply fail\n");
		return -3;
	};
	

	//printf("our public ip: %s\n",our_public_ip);
	//printf("this is supernode\n");

	return 1;
	
}








//
// Skype push Main
//
int skypush_main(char *globalptr, char *destip,u16 destport,char *our_public_ip) {
	int ret;
	
	struct global_s *global;
	global=(struct global_s *)globalptr;


	printf("Push request to target node ip: %s\n",destip);

	ret=snode_udp_push(globalptr,destip,destport,our_public_ip);
	if (ret!=1){
		printf("udp push failed\n");
		return -1;
	};


	return 1;
	
}

