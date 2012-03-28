// skydump.c : Defines the entry point for the console application.
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
extern int make_tcp_pkt3(u16 seqnum, u32 rnd, int last_recv_pkt_num, char *pkt, int *pkt_len);

// tcp process
extern int process_tcp_pkt1(char *pkt, int pkt_len, u32 *remote_tcp_rnd);
extern int process_tcp_pkt2(char *pkt, int pkt_len, int *last_recv_pkt_num);
extern int process_tcp_pkt3(char *pkt, int pkt_len);


//comm udp/tcp
extern int tcp_talk_init();
extern int tcp_talk_deinit();

extern int tcp_talk(char *remoteip, unsigned short remoteport, char *buf, int len, char *result,int need_close);
extern int show_memory(char *mem, int len, char *text);


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
{"192.168.1.100","3692"},
{"192.168.1.10","40736"},
{"87.255.5.23","55453"},

//
//timeouts for all, they are just very old
//
/*
{"97.87.164.152","25561"},
{"80.148.26.97","46801"},
{"99.249.101.244","65114"},
{"70.15.203.155","59252"},
{"80.192.52.164","43990"},
{"69.203.92.202","32158"},
{"79.199.64.207","44355"},
{"88.184.40.72","55337"},
{"76.104.149.156","30499"},
{"71.60.218.16","46020"},
{"68.34.94.41","56706"},
{"78.61.78.183","33034"},
{"76.110.240.86","27904"},
{"77.77.19.16","37907"},
{"84.252.42.12","3899"},
{"86.71.91.234","41076"},
{"75.111.63.117","51367"},
{"75.191.162.21","55995"},
{"98.185.23.252","58945"},
{"24.165.53.25","44916"},
{"24.8.122.106","17815"},
{"98.208.112.110","23383"},
{"69.207.173.53","12538"},
{"69.120.183.222","14515"},
{"64.194.33.124","51781"},
{"24.236.208.237","5723"},
{"85.64.49.136","51641"},
{"74.206.166.246","42317"},
{"74.206.190.236","9054"},
{"74.206.190.200","59880"},
{"74.206.190.170","32628"},
{"74.61.74.252","20959"},
{"76.18.61.129","54905"},
{"75.186.57.84","5385"},
{"89.113.230.150","60952"},
{"24.94.141.220","63849"},
{"118.128.5.221","24739"},
{"96.228.187.201","56560"},
{"74.206.190.200","20959"},
{"76.164.182.252","55713"},
{"64.194.17.65","4239"},
{"97.74.113.31","49470"},
{"98.247.143.179","52886"},
{"76.17.243.169","31378"},
{"74.206.190.122","38140"},
{"71.227.220.29","26252"},
{"173.48.204.45","21918"},
{"74.206.190.208","50359"},
{"68.47.15.208","52164"},
{"74.104.162.225","26589"},
{"24.94.93.226","56876"},
{"58.65.192.247","33550"},
{"91.211.244.210","12611"},
{"76.169.230.114","27665"},
{"137.22.228.224","15442"},
{"74.103.27.112","35304"},
{"70.44.14.82","32499"},
*/

	};

//int snodes_len=47;

int snodes_len=3;


/*
struct _snodes_straddr snodes_straddr[]=
	{ 		
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
*/


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


	last_recv_pkt_num=0;

	seqnum=rand() % 0x10000;

	rnd=rand() % 0x10000;
	rnd+=(rand() % 0x10000)*0x10000;


	tcp_talk_init();
	
	// pkt1
	retcode=make_tcp_pkt1(rnd,  &remote_tcp_rnd, (char *)pkt, &pkt_len);
	if (retcode==-1) {
		//printf("prepare pkt error\n");
		tcp_talk_deinit();
		return -1;
	};
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
	retcode=make_tcp_pkt2(seqnum, rnd, (char *)pkt, &pkt_len);
	if (retcode==-1) {
		//printf("prepare pkt error\n");
		tcp_talk_deinit();
		return -1;
	};
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
	retcode=make_tcp_pkt3(seqnum, rnd, last_recv_pkt_num, (char *)pkt, &pkt_len);
	if (retcode==-1) {
		//printf("prepare pkt error\n");
		tcp_talk_deinit();
		return -1;
	};
	resp_len=tcp_talk(destip,destport,pkt,pkt_len,resp,1);
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
	process_tcp_pkt3(resp,resp_len);


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


	
	for(i=0;i<snodes_len;i++){

		destip=snodes_straddr[i].ip;
		destport=atoi(snodes_straddr[i].port);

		printf("%s\n",destip);

		ret=snode_tcp_test(destip,destport);
		status_tcp_print(ret);

		if (ret==1){
			//exit(-1);
		};

	};
	


	return 0;
	
}

