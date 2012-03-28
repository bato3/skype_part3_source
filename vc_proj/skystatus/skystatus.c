// skystatus.c : Defines the entry point for the console application.
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
// comm udp/tcp
extern int tcp_talk_init();
extern int tcp_talk_deinit();
// comm func
extern int tcp_talk(char *remoteip, unsigned short remoteport, char *buf, int len, char *result,int maxlen,int need_close);
// debug
extern int show_memory(char *mem, int len, char *text);




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


	fp=fopen("./_check_addr.txt","r");
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
					printf("buf limit exceed\n");
					exit(-1);
				};
			};

		};

	}while(file_ret!=EOF);


	fclose(fp);


	return 0;

};



// 
// status of tcp remote node
//
int status_tcp_print(int retcode){
	
	switch (retcode) {
		case 1:
			printf("this is supernode!\n");
			break;
		case -99:
			printf("build pkt fail\n");
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
			printf("not skype proto\n");
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
	char resp[8192];
	int resp_len;
	char pkt[8192];
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
		return -99;
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
		//printf("not skype proto\n");
		tcp_talk_deinit();
		return -4;
	};


	// pkt2
	retcode=make_tcp_pkt2(seqnum, rnd, (char *)pkt, &pkt_len);
	if (retcode==-1) {
		//printf("build pkt fail\n");
		return -99;
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
		//printf("not skype proto\n");
		tcp_talk_deinit();
		return -4;
	};




	//printf("this is supernode\n");

	return 1;
};




// Main
//
int main(int argc, char* argv[]){
	char *destip;
	u16 destport;
	int ret;


	srand( time(NULL) );
	

	ret=load_snodes_file();
	if (ret==-1){
		printf("file not found\n");
		return -1;
	};
	

	destip=snodes_file[0].ip;
	destport=atoi(snodes_file[0].port);

	printf("Target node: %s\n",destip);

	ret=snode_tcp_test(destip,destport);
	status_tcp_print(ret);
	


	return 0;
};

