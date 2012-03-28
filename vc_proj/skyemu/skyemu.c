// skyemu.c : Defines the entry point for the console application.
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

extern int main_unpack (u8 *indata, u32 inlen);

//udp
extern int make_udp_probe_pkt1(char *ourip, char *destip, u16 seqnum, u32 rnd, char *pkt, int *pkt_len);
extern int process_udp_probe_pkt1(char *pkt, int pkt_len, u32 *remote_udp_rnd, u32 *public_ip);
extern int make_udp_probe_pkt2(char *ourip, char *destip, u16 seqnum, u32 rnd, u32 remote_udp_rnd, char *pkt, int *pkt_len);
extern int process_udp_probe_pkt2(char *pkt, int pkt_len, char *ourip, char *destip);

// udp reqnodes
extern int make_udp_reqnodes_pkt1(char *ourip, char *destip, u16 seqnum, u32 rnd, char *pkt, int *pkt_len);
extern int process_udp_reqnodes_pkt1(char *pkt,int pkt_len,char *ourip,char *destip);

//udp requser
extern int make_udp_requser_pkt1(char *ourip,char *destip, u16 seqnum, u32 rnd, char *pkt, int *pkt_len);
extern int process_udp_requser_pkt1(char *pkt,int pkt_len,char *ourip,char *destip);

//udp reqsearch
extern int make_udp_reqsearch_pkt1(char *ourip,char *destip, u16 seqnum, u32 rnd, char *pkt, int *pkt_len);
extern int process_udp_reqsearch_pkt1(char *pkt,int pkt_len,char *ourip,char *destip);

//tcp
extern int make_tcp_pkt1(u32 rnd, u32 *remote_tcp_rnd, char *pkt, int *pkt_len);
extern int make_tcp_pkt2(u16 seqnum, u32 rnd, char *pkt, int *pkt_len);

extern int make_tcp_confirm(char *pkt, int *pkt_len);

extern int make_tcp_pkt3(u16 seqnum, u32 rnd, char *pkt, int *pkt_len);
extern int make_tcp_pkt4(u16 seqnum, u32 rnd, char *pkt, int *pkt_len);
extern int make_tcp_pkt5(u16 seqnum, u32 rnd, char *pkt, int *pkt_len);

// tcp process
extern int process_tcp_pkt1(char *pkt, int pkt_len, u32 *remote_tcp_rnd);
extern int process_tcp_pkt2(char *pkt, int pkt_len);
extern int process_tcp_pkt5(char *pkt, int pkt_len);


//comm udp/tcp
extern int udp_talk(char *remoteip, u16 remoteport, char *buf, int len, char *result);
extern int udp_recv(char *remoteip, unsigned short remoteport, char *result);
extern int tcp_talk(char *remoteip, unsigned short remoteport, char *buf, int len, char *result,int need_close);
extern int tcp_talk2(char *remoteip, unsigned short remoteport, char *buf, int len, char *result,int need_close);
extern int tcp_send(char *remoteip, unsigned short remoteport, char *buf, int len);

extern int show_memory(char *mem, int len, char *text);

// dont change !!!
// or change also in comm_sock.c
#define BUF_SIZE 0x20000

int last_recv_pkt_num;
u32 node_req_addr1;
u16 node_req_port1;
u32 node_req_addr2;
u16 node_req_port2;

u8 bigbuf[0x100000];
u32 bigbuf_count=0;


#define MY_ADDR   "78.37.61.73"

// structure of addr
struct _snodes_straddr {
	char *ip;
	char *port;
};

struct _snodes_straddr snodes_straddr[]=
	{ 		
		{"89.76.20.105","11700"}, 
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


int load_snodes_file(){
	FILE *fp;
	char line[8192];
	int file_ret;
	char *ptr;


	fp=fopen("./ip_addr.txt","r");
	

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
// Supernode udp node request
//
int snode_udp_nodereq(char *destip, u16 destport, char *our_public_ip) {
	u16 seqnum;
	u32 rnd;

	char resp[BUF_SIZE];
	int resp_len;

	char pkt[BUF_SIZE];
	int pkt_len;

	int retcode;

	seqnum=rand() % 0x10000;

	rnd=rand() % 0x10000;
	rnd+=(rand() % 0x10000)*0x10000;
	

	/*
	// pkt1
	make_udp_reqnodes_pkt1(our_public_ip,destip,seqnum,rnd,(char *)pkt,&pkt_len);
	resp_len=udp_talk(destip,destport,pkt,pkt_len,resp);
	if (resp_len<0) {
		printf("socket comm error\n");
		return -1;
	};
	if (resp_len==0) {
		printf("timeout\n");
		return -2;
	};
	retcode=process_udp_reqnodes_pkt1(resp,resp_len,our_public_ip,destip);
	if (retcode==-1) {
		printf("not skype\n");
		return -3;
	};
	*/


	// pkt2
	make_udp_requser_pkt1(our_public_ip,destip,seqnum,rnd,(char *)pkt,&pkt_len);
	resp_len=udp_talk(destip,destport,pkt,pkt_len,resp);
	if (resp_len<0) {
		printf("socket comm error\n");
		return -1;
	};
	if (resp_len==0) {
		printf("timeout\n");
		return -2;
	};
	retcode=process_udp_requser_pkt1(resp,resp_len,our_public_ip,destip);
	if (retcode==-1) {
		printf("not skype\n");
		return -3;
	};


	printf("our public ip: %s\n",our_public_ip);
	printf("this is supernode\n");

	return 1;
	
}



//
// Supernode udp user request
//
int snode_udp_userreq(char *destip, u16 destport, char *our_public_ip) {
	u16 seqnum;
	u32 rnd;

	char resp[BUF_SIZE];
	int resp_len;

	char pkt[BUF_SIZE];
	int pkt_len;

	int retcode;

	seqnum=rand() % 0x10000;

	rnd=rand() % 0x10000;
	rnd+=(rand() % 0x10000)*0x10000;
	

	// pkt1
	make_udp_requser_pkt1(our_public_ip,destip,seqnum,rnd,(char *)pkt,&pkt_len);
	resp_len=udp_talk(destip,destport,pkt,pkt_len,resp);
	if (resp_len<0) {
		printf("socket comm error\n");
		return -1;
	};
	if (resp_len==0) {
		printf("timeout\n");
		return -2;
	};
	retcode=process_udp_requser_pkt1(resp,resp_len,our_public_ip,destip);
	if (retcode==-1) {
		printf("not skype\n");
		return -3;
	};


	printf("our public ip: %s\n",our_public_ip);
	printf("this is supernode\n");

	return 1;
	
}


//
// Supernode udp user request
//
int snode_udp_reqsearch(char *destip, u16 destport, char *our_public_ip) {
	u16 seqnum;
	u32 rnd;

	char resp[BUF_SIZE];
	int resp_len;

	char pkt[BUF_SIZE];
	int pkt_len;

	int retcode;

	seqnum=rand() % 0x10000;

	rnd=rand() % 0x10000;
	rnd+=(rand() % 0x10000)*0x10000;
	

	// pkt1
	make_udp_reqsearch_pkt1(our_public_ip,destip,seqnum,rnd,(char *)pkt,&pkt_len);
	resp_len=udp_talk(destip,destport,pkt,pkt_len,resp);
	if (resp_len<0) {
		printf("socket comm error\n");
		return -1;
	};
	if (resp_len==0) {
		printf("timeout\n");
		return -2;
	};
	retcode=process_udp_reqsearch_pkt1(resp,resp_len,our_public_ip,destip);
	if (retcode==-1) {
		printf("not skype\n");
		return -3;
	};
	
	do {

		resp_len=udp_recv(destip,destport,resp);
		if (resp_len<0) {
			printf("socket comm error\n");
			//return -1;
			break;
		};
		if (resp_len==0) {
			printf("timeout\n");
			//return -2;
			break;
		};
		retcode=process_udp_reqsearch_pkt1(resp,resp_len,our_public_ip,destip);
		if (retcode==-1) {
			printf("not skype\n");
			//return -3;
			break;
		};

	} while(resp_len>0);


	main_unpack (bigbuf, bigbuf_count);


	printf("our public ip: %s\n",our_public_ip);
	printf("this is supernode\n");

	return 1;
	
}





//
// Supernode udp test
//
int snode_udp_test(char *destip, u16 destport, char *our_public_ip) {
	u16 seqnum;
	u32 rnd;

	char resp[BUF_SIZE];
	int resp_len;

	u32 remote_udp_rnd;
	u32 public_ip;

	struct in_addr addr;

	char pkt[BUF_SIZE];
	int pkt_len;

	int retcode;


	strncpy(our_public_ip,"0.0.0.0",8);

	seqnum=rand() % 0x10000;

	rnd=rand() % 0x10000;
	rnd+=(rand() % 0x10000)*0x10000;
	
	// pkt1
	make_udp_probe_pkt1(our_public_ip,destip,seqnum,rnd,(char *)pkt,&pkt_len);
	resp_len=udp_talk(destip,destport,pkt,pkt_len,resp);
	if (resp_len<0) {
		//printf("socket comm error\n");
		return -1;
	};
	if (resp_len==0) {
		//printf("timeout\n");
		return -2;
	};
	retcode=process_udp_probe_pkt1(resp,resp_len,&remote_udp_rnd,&public_ip);
	if (retcode==-1) {
		//printf("not skype\n");
		return -3;
	};
	addr.s_addr=public_ip;
    strncpy(our_public_ip,inet_ntoa( addr ),128);

	// pkt2
	make_udp_probe_pkt2(our_public_ip,destip,seqnum,rnd,remote_udp_rnd,(char *)pkt,&pkt_len);
	resp_len=udp_talk(destip,destport,pkt,pkt_len,resp);
	if (resp_len<0) {
		//printf("socket comm error\n");
		return -1;
	};
	if (resp_len==0) {
		//printf("timeout\n");
		return -2;
	};
	retcode=process_udp_probe_pkt2(resp,resp_len,our_public_ip,destip);
	if (retcode==-1) {
		//printf("skype client\n");
		return -4;
	};


	//printf("our public ip: %s\n",our_public_ip);
	//printf("this is supernode\n");
	return 1;
	
}



//
// Supernode tcp test
//
int snode_tcp_test(char *destip, u16 destport) {
	u16 seqnum;
	u32 rnd;
	u32 remote_tcp_rnd;

	char resp[BUF_SIZE];
	int resp_len;
	char pkt[BUF_SIZE];
	int pkt_len;

	int retcode;



	seqnum=rand() % 0x10000;
	printf("seqnum=0x%08X\n",seqnum);

	rnd=rand() % 0x10000;
	rnd+=(rand() % 0x10000)*0x10000;


	
	// pkt1
	make_tcp_pkt1(rnd,  &remote_tcp_rnd, (char *)pkt, &pkt_len);
	resp_len=tcp_talk(destip,destport,pkt,pkt_len,resp,0);
	if (resp_len<0) {
		//printf("socket comm error\n");
		return -1;
	};
	if (resp_len==0) {
		//printf("connection failed\n");
		return -2;
	};
	retcode=process_tcp_pkt1(resp,resp_len,&remote_tcp_rnd);
	if (retcode==-1) {
		//printf("not skype\n");
		return -3;
	};


	// pkt2
	make_tcp_pkt2(seqnum, rnd, (char *)pkt, &pkt_len);
	resp_len=tcp_talk(destip,destport,pkt,pkt_len,resp,0);
	if (resp_len<0) {
		//printf("socket comm error\n");
		return -1;
	};
	if (resp_len==0) {
		//printf("connection failed\n");
		return -2;
	};
	retcode=process_tcp_pkt2(resp,resp_len);
	if (retcode==-1) {
		//printf("skype client\n");
		return -4;
	};

	// pkt confirm
	make_tcp_confirm((char *)pkt, &pkt_len);
	resp_len=tcp_send(destip,destport,pkt,pkt_len);
	if (resp_len<0) {
		//printf("socket comm error\n");
		return -1;
	};
	if (resp_len==0) {
		//printf("connection failed\n");
		return -2;
	};


	seqnum+=3;
	// pkt3 sent $6
	make_tcp_pkt3(seqnum, rnd, (char *)pkt, &pkt_len);
	resp_len=tcp_send(destip,destport,pkt,pkt_len);
	if (resp_len<0) {
		//printf("socket comm error\n");
		return -1;
	};
	if (resp_len==0) {
		//printf("connection failed\n");
		return -2;
	};

	seqnum+=2;
	// pkt4 sent , my info
	make_tcp_pkt4(seqnum, rnd, (char *)pkt, &pkt_len);
	resp_len=tcp_send(destip,destport,pkt,pkt_len);
	if (resp_len<0) {
		//printf("socket comm error\n");
		return -1;
	};
	if (resp_len==0) {
		//printf("connection failed\n");
		return -2;
	};
	
	seqnum+=2;
	// pkt5 sent routing ask  many sent $6
	make_tcp_pkt5(seqnum, rnd, (char *)pkt, &pkt_len);
	resp_len=tcp_talk2(destip,destport,pkt,pkt_len,resp,0);
	if (resp_len<0) {
		//printf("socket comm error\n");
		return -1;
	};
	if (resp_len==0) {
		//printf("connection failed\n");
		return -2;
	};
	retcode=process_tcp_pkt5(resp,resp_len);
	

	// ask for nodes in slot

	//printf("this is supernode\n");
	return 1;
};




//
// Main
//
//ip of supernode, from skype.log "probe accept"
int main(int argc, char* argv[]) {
	
	char *destip;
	u16 destport;

	int ret;
	int i=0;

//	struct in_addr addr;
	char our_public_ip[128];
	char reqnodes_ip[128];
	
	srand( time(NULL) );


	
	/*
	if (argc!=3){
		printf("usage ip port\n");
		exit(1);
	};
	destip=strdup(argv[1]);
	destport=atoi(strdup(argv[2]));
	*/
	


	//destip=strdup("192.168.1.10");
	//destport=123;
	//destip=strdup("192.168.1.18");
	//destport=33864;
	//destip=strdup("192.168.1.10");
	//destport=42394;
	//destport=52862;



	// tcp session check
	if (0){
		ret=snode_tcp_test(destip,destport);
		status_tcp_print(ret);

	};

	// udp session check
	if (0){
		ret=snode_udp_test(destip,destport,(char *)&our_public_ip);
		status_udp_print(ret,our_public_ip);
	};

	/*
	for(i=0;i<snodes_len;i++){
		destip=snodes_straddr[i].ip;
		destport=atoi(snodes_straddr[i].port);
		ret=snode_udp_test(destip,destport,(char *)&our_public_ip);
		status_udp_print(ret,our_public_ip);
	};
	*/

	/*
	for(i=0;i<snodes_len;i++){
		destip=snodes_straddr[i].ip;
		destport=atoi(snodes_straddr[i].port);
		ret=snode_tcp_test(destip,destport);
		status_tcp_print(ret);
	};
	*/


	// udp send nodes request
	// not tested
	if (0) {

		printf("send nodes request\n");

		//destip=snodes_straddr[0].ip;
		//destport=atoi(snodes_straddr[0].port);
		//addr.s_addr=htonl(node_req_addr1);
		//strncpy(reqnodes_ip,inet_ntoa( addr ),128);
		
		printf("nodes ip: %s\n",reqnodes_ip);

		//destip=reqnodes_ip;
		//destport=node_req_port1;
		ret=snode_udp_nodereq(destip,destport,our_public_ip);

		//destip=snodes_straddr[15].ip;
		//destport=atoi(snodes_straddr[15].port);
		//ret=snode_udp_nodereq(destip,destport,snodes_straddr[15].ip);

	};


	// udp send user profile request
	if (0) {

		printf("send user request\n");

		strcpy(our_public_ip,"78.37.50.255");
	
		printf("node ip: %s\n",destip);

		ret=snode_udp_userreq(destip,destport,our_public_ip);

	};

	if (0){

		printf("send mass user profile requests\n");

		strcpy(our_public_ip,MY_ADDR);

		load_snodes_file();

		for(i=0;i<snodes_file_len;i++){

			destip=snodes_file[i].ip;
			destport=atoi(snodes_file[i].port);

			printf("target node ip: %s\n",destip);
			ret=snode_udp_userreq(destip,destport,our_public_ip);
		};

	};


	// search
	if (1){

		printf("send mass user search requests\n");

		strcpy(our_public_ip,MY_ADDR);

		load_snodes_file();

		for(i=0;i<snodes_file_len;i++){

			destip=snodes_file[i].ip;
			destport=atoi(snodes_file[i].port);

			printf("target node ip: %s\n",destip);
			ret=snode_udp_reqsearch(destip,destport,our_public_ip);

			
			exit(1);
		};

	};


	//Sleep(1000*180);

	return 0;
	
}

