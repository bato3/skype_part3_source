// skyrel.c : Defines the entry point for the console application.
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


// tcp
extern int make_tcp_pkt1(u32 rnd, u32 *remote_tcp_rnd, char *pkt, int *pkt_len);
extern int make_tcp_pkt2(u16 seqnum, u32 rnd, char *pkt, int *pkt_len);
// tcp process
extern int process_tcp_pkt1(char *pkt, int pkt_len, u32 *remote_tcp_rnd);
extern int process_tcp_pkt2(char *pkt, int pkt_len, int *last_recv_pkt_num);
extern int process_tcp_pkt3(char *pkt, int pkt_len, int *last_recv_pkt_num);
// comm udp/tcp
extern int tcp_talk_init();
extern int tcp_talk_deinit();
// comm func
extern int tcp_talk(char *remoteip, unsigned short remoteport, char *buf, int len, char *result, int maxlen, int need_close);
extern int tcp_talk_recv(char *remoteip, unsigned short remoteport, char *result, int maxlen, int need_close);
// debug
extern int show_memory(char *mem, int len, char *text);


#define BUF_SIZE 8192


// 
// status of tcp remote node
//
int status_tcp_print(int retcode){
	
	switch (retcode) {
		case 1:
			printf("this is supernode!\n");
			break;
		case -1:
			printf("socket comm error\n");
			break;
		case -2:
			printf("connection failed\n");
			break;
		case -3:
			printf("timeout\n");
			break;
		case -4:
			printf("not skype\n");
			break;
		case -5:
			printf("old skype client\n");
			break;
		case -6:
			printf("skype client, clients node dumped\n");
			break;
		default:
			printf("unknown case, %d\n",retcode);
	};

	return 0;
};


//
// Supernode tcp test
//
int snode_tcp_test(char *destip, u16 destport) {
	u16 seqnum;
	u32 rnd;
	u32 remote_tcp_rnd;
	int last_recv_pkt_num;
	char resp[BUF_SIZE];
	int resp_len;
	char pkt[BUF_SIZE];
	int pkt_len;
	int retcode;
	int maxlen;

	
	maxlen=sizeof(resp)-1;

	last_recv_pkt_num=0;

	seqnum=rand() % 0x10000;

	rnd=rand() % 0x10000;
	rnd+=(rand() % 0x10000)*0x10000;


	tcp_talk_init();
	
	// pkt1
	retcode=make_tcp_pkt1(rnd,  &remote_tcp_rnd, (char *)pkt, &pkt_len);
	if (retcode==-1) {
		//printf("build pkt fail\n");
		return -1;
	};
	resp_len=tcp_talk(destip,destport,pkt,pkt_len,resp,maxlen,0);
	if (resp_len==-1) {
		//printf("socket comm error\n");
		tcp_talk_deinit();
		return -1;
	};
	if (resp_len==0) {
		//printf("connection failed\n");
		tcp_talk_deinit();
		return -2;
	};
	if (resp_len==-2) {
		//printf("timeout\n");
		tcp_talk_deinit();
		return -3;
	};
	retcode=process_tcp_pkt1(resp,resp_len,&remote_tcp_rnd);
	if (retcode==-1) {
		//printf("not skype\n");
		tcp_talk_deinit();
		return -4;
	};


	// pkt2
	retcode=make_tcp_pkt2(seqnum, rnd, (char *)pkt, &pkt_len);
	if (retcode==-1) {
		//printf("build pkt fail\n");
		return -1;
	};
	resp_len=tcp_talk(destip,destport,pkt,pkt_len,resp,maxlen,0);
	if (resp_len==-1) {
		//printf("socket comm error\n");
		tcp_talk_deinit();
		return -1;
	};
	if (resp_len==0) {
		//printf("connection failed\n");
		tcp_talk_deinit();
		return -2;
	};
	if (resp_len==-2) {
		//printf("timeout\n");
		tcp_talk_deinit();
		return -3;
	};
	retcode=process_tcp_pkt2(resp,resp_len, &last_recv_pkt_num);
	if (retcode==-1) {
		printf("parse pkt2 error\n");
		tcp_talk_deinit();
		return -1;
	};


	printf("waiting for connection\n");

	// recv additional data
	do{

		resp_len=tcp_talk_recv(destip,destport,resp,maxlen,0);
		if (resp_len<0) {
			printf("pkt3, socket error\n");
			break;
		};

		if (resp_len>0){
			retcode=process_tcp_pkt3(resp,resp_len, &last_recv_pkt_num);
			if (retcode==-1) {
				printf("pkt3, parse error\n");
				break;
			};
		};

		printf("resp_len: %d\n",resp_len);
		Sleep(1000);

	}while(1);



	//printf("this is supernode\n");

	return 1;
};




//
// Main
//
int main(int argc, char* argv[]) {
	char *destip;
	u16 destport;
	int ret;
	int i=0;
	
	srand( time(NULL) );


	
	if (argc!=3){
		printf("usage: <ip> <port>\n");
		exit(1);
	};
	

	destip=strdup(argv[1]);
	destport=atoi(strdup(argv[2]));

	//destip=strdup("94.109.93.2");
	//destport=3352;

	printf("Target node: %s\n",destip);

	ret=snode_tcp_test(destip,destport);
	status_tcp_print(ret);

	


	return 0;
	
}
