// skyslot.c : Defines the entry point for the console application.
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


//tcp
extern int make_tcp_pkt1(u32 rnd, u32 *remote_tcp_rnd, char *pkt, int *pkt_len);
extern int make_tcp_pkt2(u16 seqnum, u32 rnd, char *pkt, int *pkt_len);
extern int make_tcp_pkt3(u16 seqnum, u32 rnd, int last_recv_pkt_num, int start_slot, char *pkt, int *pkt_len);

// tcp process
extern int process_tcp_pkt1(char *pkt, int pkt_len, u32 *remote_tcp_rnd);
extern int process_tcp_pkt2(char *pkt, int pkt_len, int *last_recv_pkt_num);
extern int process_tcp_pkt3(char *pkt, int pkt_len, int *last_recv_pkt_num);


//comm udp/tcp
extern int tcp_talk_init();
extern int tcp_talk_deinit();

extern int tcp_talk(char *remoteip, unsigned short remoteport, char *buf, int len, char *result,int need_close);
extern int show_memory(char *mem, int len, char *text);

int last_slot=0;

// dont change !!!
// or change also in comm_sock.c
#define BUF_SIZE 8192



// structure of addr
struct _snodes_straddr {
	char *ip;
	char *port;
};

struct _snodes_straddr snodes_straddr[]=
	{ 		
		{"213.114.11.237","51068"}, 
		{"88.113.134.138","13139"}, 
		{"70.76.146.96","42250"}, 
		{"80.90.195.207","49608"}, 
		{"81.84.147.69","53589"}, 
		{"140.115.126.128","13660"}, 
		{"140.180.189.222","20104"}, 
		{"78.49.188.73","29625"}, 
		{"95.160.147.153","31551"}, 
		{"99.226.235.146","14385"}, 
		{"87.56.177.240","41527"}, 
		{"219.118.123.106","38239"},
		{"98.217.5.20","48982"},
		{"207.244.165.106","2400"},
		{"119.235.72.36","45269"},
		{"85.141.72.52","53162"},
		{"129.94.191.249","35545"},
		{"98.169.245.251","8942"},
		{"71.86.210.49","64713"},
		{"72.193.150.96","35164"},
		{"190.206.238.152","59364"},
		{"189.6.167.18","22468"},
		{"89.45.152.44","8541"},
		{"76.22.187.70","50981"},
		{"80.70.228.248","10915"},
		{"192.168.1.10","42394"}
	};

int snodes_len=16;

#define SNODES_MAX 0x1000

struct _snodes_straddr snodes_file[SNODES_MAX];

int snodes_file_len=0;

int load_snodes_file(){
	FILE *fp;
	char line[8192];
	int file_ret;
	char *ptr;


	fp=fopen("./_boot_addr.txt","r");
	if (fp==NULL){
		printf("file not found\n");
		exit(-1);
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

	//exit(-1);


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
int snode_tcp_test(char *destip, u16 destport, int start_slot) {
	u16 seqnum;
	u32 rnd;
	u32 remote_tcp_rnd;
	int last_recv_pkt_num;
	char resp[BUF_SIZE];
	int resp_len;
	char pkt[BUF_SIZE];
	int pkt_len;
	int retcode;



	last_recv_pkt_num=0;

	seqnum=rand() % 0x10000;

	rnd=rand() % 0x10000;
	rnd+=(rand() % 0x10000)*0x10000;


	tcp_talk_init();
	
	// pkt1
	make_tcp_pkt1(rnd,  &remote_tcp_rnd, (char *)pkt, &pkt_len);
	resp_len=tcp_talk(destip,destport,pkt,pkt_len,resp,0);
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
	make_tcp_pkt2(seqnum, rnd, (char *)pkt, &pkt_len);
	resp_len=tcp_talk(destip,destport,pkt,pkt_len,resp,0);
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
		//printf("old skype client\n");
		tcp_talk_deinit();
		return -5;
	};
	retcode=process_tcp_pkt2(resp,resp_len, &last_recv_pkt_num);
	if (retcode==-1) {
		//printf("skype client, nodes dumped\n");
		tcp_talk_deinit();
		return -6;
	};

	// pkt3
	seqnum=+2;
	make_tcp_pkt3(seqnum, rnd, last_recv_pkt_num, start_slot, (char *)pkt, &pkt_len);
	resp_len=tcp_talk(destip,destport,pkt,pkt_len,resp,0);
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
	process_tcp_pkt3(resp,resp_len, &last_recv_pkt_num);


	// pkt4 .. 
	do{
		start_slot+=16;
		seqnum=+2;
		make_tcp_pkt3(seqnum, rnd, last_recv_pkt_num, start_slot, (char *)pkt, &pkt_len);
		resp_len=tcp_talk(destip,destport,pkt,pkt_len,resp,0);
		if (resp_len==-1) {
			//printf("socket comm error\n");
			tcp_talk_deinit();
			return 1;
		};
		if (resp_len==0) {
			//printf("connection failed\n");
			tcp_talk_deinit();
			return 1;
		};
		if (resp_len==-2) {
			//printf("timeout\n");
			tcp_talk_deinit();
			return 1;
		};
		process_tcp_pkt3(resp,resp_len, &last_recv_pkt_num);


	}while( (start_slot+16) < 2048 );

	//printf("this is supernode\n");

	return 1;
};




//
// Main
//
int main(int argc, char* argv[]) {
	char *destip;
	u16 destport;
	int start_slot;
	int ret;
	int i=0;
	
	srand( time(NULL) );


	/*
	if (argc!=3){
		printf("usage ip port\n");
		exit(1);
	};
	destip=strdup(argv[1]);
	destport=atoi(strdup(argv[2]));
	
	ret=snode_tcp_test(destip,destport);
	status_tcp_print(ret);
	*/

	//destip=strdup("192.168.1.1");
	//destport=807;
	//destip=strdup("192.168.1.18");
	//destport=33864;
	//destip=strdup("192.168.1.10");
	//destport=42394;


	start_slot=0;

	load_snodes_file();
	for(i=0;i<snodes_file_len;i++){

		destip=snodes_file[i].ip;
		destport=atoi(snodes_file[i].port);

		printf("%s\n",destip);
		ret=snode_tcp_test(destip,destport,start_slot);
		status_tcp_print(ret);

		if(ret==1){
			start_slot=last_slot;
		};

		if((ret==1) && (start_slot>=2047)){
			exit(-1);
		};

	};
	


	return 0;
	
}
