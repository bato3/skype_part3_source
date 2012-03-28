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

#include "global_vars.h"

// tcp
extern int make_tcp_pkt1(char *globalptr, u32 rnd, u32 *remote_tcp_rnd, char *pkt, int *pkt_len);
extern int make_tcp_pkt2(char *globalptr, u16 seqnum, u32 rnd, char *pkt, int *pkt_len);

int make_tcp_pkt_confirm(char *globalptr, int last_recv_num, char *pkt, int *pkt_len);

// tcp process
extern int process_tcp_pkt1(char *globalptr, char *pkt, int pkt_len, u32 *remote_tcp_rnd);
extern int process_tcp_pkt2(char *globalptr, char *pkt, int pkt_len, int *last_recv_pkt_num, u32 *connid);
extern int process_tcp_pkt3(char *globalptr, char *pkt, int pkt_len, int *last_recv_pkt_num);


extern int tcpn_talk_init(int *getsock, char *remoteip, unsigned short remoteport);
extern int tcpn_talk_deinit(int *getsock);
extern int tcpn_talk(int *getsock,char *remoteip,u16 remoteport,char *buf,int buf_len,char *result,int result_len);

extern int tcpn_talk_recv(int *getsock, char *result, int result_len);
extern int tcpn_talk_recv2(int *getsock, char *result, int result_len);
extern int tcpn_talk_send(int *getsock, char *confirm, unsigned int confirm_len);

// debug
extern int show_memory(char *mem, int len, char *text);




extern unsigned int DEBUG_LEVEL;


#define SNODES_MAX 0x1000


// structure of addr
struct _snodes_straddr {
	char *ip;
	char *port;
};


struct _snodes_straddr snodes_file[SNODES_MAX];
int snodes_file_len=0;


//
// Load nodes from file
//
int load_snodes_file(){
	FILE *fp;
	char line[8192];
	int file_ret;
	char *ptr;


	fp=fopen("./_relay_addr.txt","r");
	if (fp==NULL){
		return -1;
	};

	snodes_file_len=0;


	do {
		line[0]=0;
		file_ret=fscanf(fp,"%s\n",line);
		if (strlen(line)!=0){
			//printf("line: %s\n",line);
			
			ptr=strchr(line,':');
			
			if (ptr!=NULL) {
				
				ptr[0]=0;
				
				snodes_file[snodes_file_len].ip=malloc(256);
				snodes_file[snodes_file_len].port=malloc(256);
				strncpy(snodes_file[snodes_file_len].ip,line,256);
				strncpy(snodes_file[snodes_file_len].port,ptr+1,256);
				
				//printf("ip: %s port: %s\n",snodes_file->ip,snodes_file->port);
				
				snodes_file_len++;
			
				if (snodes_file_len > SNODES_MAX){
					if (DEBUG_LEVEL>=100) printf("buf limit exceed\n");
					return -1;
				};
			};

		};

	}while(file_ret!=EOF);


	fclose(fp);


	return 0;

};


//
// Supernode tcp relay test
//
int snode_tcp_relay(char *destip, u16 destport, u32 *connid, int *retsock, char *globalptr) {
	u16 seqnum;
	u32 rnd;
	u32 remote_tcp_rnd;
	int last_recv_pkt_num;
	char resp[0x2005];
	int resp_len;
	char pkt[0x2005];
	int pkt_len;
	int retcode;
	int resp_maxlen;

	
	struct global_s *global;
	global=(struct global_s *)globalptr;


	resp_maxlen=sizeof(resp)-1;

	last_recv_pkt_num=0;

	seqnum=rand() % 0x10000;

	rnd=global->rnd;


	resp_len=tcpn_talk_init(retsock, destip, destport);
	if (resp_len==-1) {
		if (DEBUG_LEVEL>=100) printf("socket comm error\n");
		return -1;
	};
	if (resp_len==0) {
		if (DEBUG_LEVEL>=100) printf("connection failed\n");
		return -2;
	};
	
	// pkt1
	retcode=make_tcp_pkt1(globalptr, rnd,  &remote_tcp_rnd, (char *)pkt, &pkt_len);
	if (retcode==-1) {
		if (DEBUG_LEVEL>=100) printf("build pkt fail\n");
		return -1;
	};
	resp_len=tcpn_talk(retsock,destip,destport,pkt,pkt_len,resp,resp_maxlen);
	if (resp_len==-1) {
		if (DEBUG_LEVEL>=100) printf("socket comm error\n");
		tcpn_talk_deinit(retsock);
		return -1;
	};
	if (resp_len==0) {
		if (DEBUG_LEVEL>=100) printf("connection failed\n");
		tcpn_talk_deinit(retsock);
		return -2;
	};
	if (resp_len==-2) {
		if (DEBUG_LEVEL>=100) printf("timeout\n");
		tcpn_talk_deinit(retsock);
		return -3;
	};
	retcode=process_tcp_pkt1(globalptr, resp,resp_len,&remote_tcp_rnd);
	if (retcode==-1) {
		if (DEBUG_LEVEL>=100) printf("not skype\n");
		tcpn_talk_deinit(retsock);
		return -4;
	};


	// pkt2
	retcode=make_tcp_pkt2(globalptr, seqnum, rnd, (char *)pkt, &pkt_len);
	if (retcode==-1) {
		if (DEBUG_LEVEL>=100) printf("build pkt fail\n");
		return -1;
	};
	resp_len=tcpn_talk(retsock,destip,destport,pkt,pkt_len,resp,resp_maxlen);
	if (resp_len==-1) {
		if (DEBUG_LEVEL>=100) printf("socket comm error\n");
		tcpn_talk_deinit(retsock);
		return -1;
	};
	if (resp_len==0) {
		if (DEBUG_LEVEL>=100) printf("connection failed\n");
		tcpn_talk_deinit(retsock);
		return -2;
	};
	if (resp_len==-2) {
		if (DEBUG_LEVEL>=100) printf("timeout\n");
		tcpn_talk_deinit(retsock);
		return -3;
	};
	retcode=process_tcp_pkt2(globalptr, resp,resp_len, &last_recv_pkt_num, connid);
	if (retcode==-1) {
		if (DEBUG_LEVEL>=100) printf("parse pkt2 error\n");
		tcpn_talk_deinit(retsock);
		return -1;
	};



	//printf("this is supernode\n");
	return 1;
};


//
// SkyRel Main
//
unsigned int skyrel_main(char *globalptr, int *retsock) {
	int ret;
	int i=0;
	u32 connid=0;
	char *destip;
	u16 destport;
	
	struct global_s *global;
	global=(struct global_s *)globalptr;



	ret=load_snodes_file();
	if (ret==-1){
		if (DEBUG_LEVEL>=100) printf("file not found\n");
		return -1;
	};

	for(i=0;i<snodes_file_len;i++){

		destip=snodes_file[i].ip;
		destport=atoi(snodes_file[i].port);

		if (DEBUG_LEVEL>=100) printf("Target node: %s\n",destip);
		ret=snode_tcp_relay(destip,destport,&connid,retsock,globalptr);

		if((ret==1)&&(connid>0)){

			strcpy(global->relayip,destip);
			global->relayport=destport;
			global->connid=connid;

			return 1;
		};
		if ((ret==1)&&(connid==0)){
			if (DEBUG_LEVEL>=100) printf("Fail to get connid, next\n");
		}

	};

	


	return -1;
	
}


//
// Supernode tcp relay answer
//
int snode_tcp_answer(char *globalptr, int *retsock) {
	int last_recv_num;
	char resp[0x2005];
	int resp_len;
	int retcode;
	int resp_maxlen;

	u8 confirm[0x100];
	u32 confirm_len=0;

	struct global_s *global;
	global=(struct global_s *)globalptr;


	resp_maxlen=sizeof(resp)-1;

	// pkt 3 recv
	resp_len=tcpn_talk_recv2(retsock,resp,resp_maxlen);
	if (resp_len<0) {
		if (DEBUG_LEVEL>=100) printf("pkt3, socket error\n");
		tcpn_talk_deinit(retsock);
		return -1;
	};
	if (resp_len==0){
		if (DEBUG_LEVEL>=100) printf("pkt3, connection closed unexpected\n");
		tcpn_talk_deinit(retsock);
		return -1;
	};
	retcode=process_tcp_pkt3(globalptr, resp,resp_len, &last_recv_num);
	if (retcode==-1) {
		if (DEBUG_LEVEL>=100) printf("pkt3, parse error\n");
		tcpn_talk_deinit(retsock);
		return -1;
	};

	global->last_recv_num=last_recv_num;


	retcode=make_tcp_pkt_confirm(globalptr, last_recv_num, (char *)confirm, &confirm_len);
	if (retcode==-1) {
		if (DEBUG_LEVEL>=100) printf("build pkt fail confirm\n");
		return -1;
	};


	// pkt send confirm
	resp_len=tcpn_talk_send(retsock,confirm,confirm_len);
	if (resp_len<0) {
		if (DEBUG_LEVEL>=100) printf("pkt3, socket error\n");
		tcpn_talk_deinit(retsock);
		return -1;
	};



	//printf("this is supernode\n");

	return 1;

};


//
// SkyRel answer check
//
unsigned int skyrel_answer(char *globalptr, int *retsock) {
	int ret;
	int i=0;

	struct global_s *global;
	global=(struct global_s *)globalptr;


	if (DEBUG_LEVEL>=100) printf("skyrel answer retsock: 0x%08X\n",*retsock);

	ret=snode_tcp_answer(globalptr,retsock);
	if(ret!=1){
		return -1;
	};



	return 1;
	
}
