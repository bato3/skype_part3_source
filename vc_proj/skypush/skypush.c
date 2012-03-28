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


extern int main_unpack(u8 *indata, u32 inlen);
extern int main_unpack_get (u8 *indata, u32 inlen, u8 *ipinfo, u32 *ipinfo_len);
extern int slot_find(u8 *str);

extern int make_udp_push_pkt1(char *ourip,char *destip, u16 seqnum, u32 rnd, char *pkt, int *pkt_len);
extern int process_udp_push_pkt1(char *pkt,int pkt_len,char *ourip,char *destip);

extern int udp_talk(char *remoteip, u16 remoteport, char *buf, int len, char *result, int result_maxlen, int *retsock);
extern int udp_recv(char *remoteip, unsigned short remoteport, char *result, int result_maxlen, int *retsock);

extern int show_memory(char *mem, int len, char *text);


int DEBUG = 1;



// 
// status of udp remote node
//
int status_udp_print(int retcode, char *our_public_ip){
	
	switch (retcode) {
		case 1:
			printf("this is supernode! our public ip: %s\n",our_public_ip);
			break;
		case -1:
			printf("socket comm error\n");
			break;
		case -2:
			printf("timeout\n");
			break;
		case -3:
			printf("not skype\n");
			break;
		case -4:
			printf("skype client\n");
			break;
		default:
			printf("unknown case, %d\n",retcode);
	};

	return 0;
};


//
// Supernode udp user request
//
int snode_udp_push(char *destip, u16 destport, char *our_public_ip) {
	u16 seqnum;
	u32 rnd;
	char resp[0x1000];
	int resp_len;
	char pkt[0x1000];
	int pkt_len;
	int retcode;
	int retsock;


	seqnum=rand() % 0x10000;

	rnd=rand() % 0x10000;
	rnd+=(rand() % 0x10000)*0x10000;
	

	// pkt1
	retcode=make_udp_push_pkt1(our_public_ip,destip,seqnum,rnd,(char *)pkt,&pkt_len);
	if (retcode==-1) {
		//printf("prepare error\n");
		return -1;
	};
	resp_len=udp_talk(destip,destport,pkt,pkt_len,resp,sizeof(resp), &retsock);
	if (resp_len<0) {
		//printf("socket comm error\n");
		return -1;
	};
	if (resp_len==0) {
		//printf("timeout\n");
		return -2;
	};
	
	if (DEBUG) printf("part len:0x%08X\n",resp_len);

	retcode=process_udp_push_pkt1(resp,resp_len,our_public_ip,destip);
	if (retcode==-1) {
		//printf("not skype\n");
		return -3;
	};
	

	//printf("our public ip: %s\n",our_public_ip);
	//printf("this is supernode\n");

	return 1;
	
}








//
// Main
//
int main(int argc, char* argv[]) {
	char *destip;
	u16 destport;
	char our_public_ip[128];
	int ret;
	char *MY_ADDR;

	

	srand( time(NULL) );


	if (argc!=2){
		//printf("usage: <you public ip>\n");
		//exit(1);
	};

	//MY_ADDR=strdup(argv[1]);
	//destip=strdup(argv[1]);
	//destport=atoi(argv[2]);

	MY_ADDR=strdup("95.52.158.53");
	
	strcpy(our_public_ip,MY_ADDR);

	destip=strdup("165.230.143.72");
	destport=65330;

	printf("Push request to target node ip: %s\n",destip);

	ret=snode_udp_push(destip,destport,our_public_ip);


	return 0;
	
}

