// skysearch.c : Defines the entry point for the console application.
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

extern int make_udp_probe_pkt1(char *ourip,char *destip,unsigned short seqnum, u32 rnd, char *pkt, int *pkt_len);
extern int process_udp_probe_pkt1(char *pkt, int pkt_len, u32 *remote_udp_rnd, u32 *public_ip);

extern int make_udp_probe_pkt2(char *ourip,char *destip,unsigned short seqnum,u32 rnd,u32 remote_udp_rnd,char *pkt,int *pkt_len);
extern int process_udp_probe_pkt2(char *pkt,int pkt_len,char *ourip,char *destip);


extern int udp_talk(char *remoteip, unsigned short remoteport, char *buf, int len, char *result);


int main(int argc, char* argv[]) {
	char *destip;
	unsigned short destport;
	unsigned short seqnum;
	u32 rnd;

	char result[1024];
	u32 result_len;
	u32 remote_udp_rnd;
	u32 public_ip;

	struct in_addr addr;
	char our_public_ip[1024];


	char pkt[1024];
	int pkt_len;

	int retcode;



	//ip of supernode, from skype.log "probe accept"
	if (argc!=3){
		printf("usage ip port\n");
		exit(1);
	};
	destip=strdup(argv[1]);
	destport=atoi(strdup(argv[2]));

	//destip=strdup("192.168.1.17");
	//destport=1234;
	//destip=strdup("192.168.1.17");
	//destport=33864;
	//destip=strdup("192.168.1.10");
	//destport=42394;
	//destip=strdup("67.172.54.187");
	//destport=29753;
	//destip=strdup("118.165.3.141");
	//destport=52862;

	
	// init rnd
	srand( time(NULL) );

	//init our public ip as unknown
	strncpy(our_public_ip,"0.0.0.0",8);

	// init seq
	seqnum=rand() % 0x10000;

	// init rnd
	rnd=rand() % 0x10000;
	rnd+=(rand() % 0x10000)*0x10000;
	
	make_udp_probe_pkt1(our_public_ip,destip,seqnum,rnd,(char *)pkt,&pkt_len);
	result_len=udp_talk(destip,destport,pkt,pkt_len,result);
	retcode=process_udp_probe_pkt1(result,result_len,&remote_udp_rnd,&public_ip);

	if (!retcode) {
		printf("not supernode\n");
		exit(1);
	};

	addr.s_addr=public_ip;
    strncpy(our_public_ip,inet_ntoa( addr ),1024);

	make_udp_probe_pkt2(our_public_ip,destip,seqnum,rnd,remote_udp_rnd,(char *)pkt,&pkt_len);
	result_len=udp_talk(destip,destport,pkt,pkt_len,result);
	retcode=process_udp_probe_pkt2(result,result_len,our_public_ip,destip);

	if (!retcode) {
		printf("not supernode, may be skype client\n");
		exit(1);
	};

	printf("supernode check ok\n");
	printf("our public ip: %s\n",our_public_ip);



	return 0;
	
}

