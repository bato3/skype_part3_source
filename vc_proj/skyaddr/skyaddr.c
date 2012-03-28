// skyaddr.c : Defines the entry point for the console application.
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

int slot_find(u8 *str);

extern int make_udp_reqsearch_pkt1(char *ourip,char *destip, u16 seqnum, u32 rnd, char *skypeuser, char *pkt, int *pkt_len);
extern int process_udp_reqsearch_pkt1(char *pkt,int pkt_len,char *ourip,char *destip);

extern int udp_talk(char *remoteip, u16 remoteport, char *buf, int len, char *result);
extern int udp_recv(char *remoteip, unsigned short remoteport, char *result);

extern int show_memory(char *mem, int len, char *text);

extern int decode_profile(u8 *remote_profile, u8 *pubkey, u8 *data, u8 *skypename);


// dont change !!!
// or change also in comm_sock.c
#define BUF_SIZE 0x20000
#define SNODES_MAX 0x100

//#define MY_ADDR   "78.37.51.152"

char *MY_ADDR;


u8 bigbuf[0x100000];
u32 bigbuf_count=0;


struct _snodes_straddr {
	char *ip;
	char *port;
};

struct _slots {
	struct _snodes_straddr snodes[SNODES_MAX];
	u32 snodes_len;
};
struct _slots slots[2048];




int load_slots_file(){
	FILE *fp;
	char line[8192];
	int file_ret;
	char *ptr;
	u32 slotid=0;

	fp=fopen("./_getnodes.txt","r");
	if (fp==NULL){
		printf("file not found\n");
		exit(-1);
	};
	

	do {
		line[0]=0;
		file_ret=fscanf(fp,"%s\n",&line);
		if (strlen(line)!=0){
			//printf("line: %s\n",line);
			if (strstr(line,"::")!=NULL){
				continue;
			};
			if (strstr(line,"Slot:")!=NULL){
				continue;
			};
			if (strstr(line,"0x")!=NULL){
				sscanf(line,"%x",&slotid);
				//printf("slotid: 0x%08X\n",slotid);
				slots[slotid].snodes_len=0;
				continue;
			};
			ptr=strchr(line,':');
			if (ptr!=NULL) {		
				ptr[0]=0;		
				slots[slotid].snodes[slots[slotid].snodes_len].ip=malloc(256);
				slots[slotid].snodes[slots[slotid].snodes_len].port=malloc(256);
				strncpy(slots[slotid].snodes[slots[slotid].snodes_len].ip,line,256);
				strncpy(slots[slotid].snodes[slots[slotid].snodes_len].port,ptr+1,256);				
				//printf("ip: %s port: %s\n",snodes_file->ip,snodes_file->port);
				slots[slotid].snodes_len++;
				if (slots[slotid].snodes_len > SNODES_MAX){
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



int get_profiles(u8 *buf, u32 len) {
	u8 *ptr;
	int ret;
	u32 i;
	u8 cred[0x188];
	u8 pubkey[0x80];
	u8 profile[0x80];
	u8 ipinfo[0x100];
	u32 ipinfo_len=0;

	u8 userid[0x100];
	u8 ipport_int[0x100];
	u8 ipport_ext[0x100];
	u8 ipport_add[0x100];
	u32 port;


	// dont change !
	// used in decode profile
	u8 skypename[1024];

	memset(skypename,0,sizeof(skypename));

	printf("Len= 0x%x\n",len);

	for(i=0;(i+8)<len;i++){
		ptr=buf+i;
		ret=memcmp(ptr,"\x00\x00\x01\x04\x00\x00\x00\x01",8);
		if (ret==0){
			if (len-i>=0x188) {

				ipport_add[0]=0;
				ipport_ext[0]=0;
				ipport_int[0]=0;
				userid[0]=0;
				ipinfo_len=0;

				memcpy(cred,ptr,0x188);
				
				skypename[0]=0;
				decode_profile(cred, pubkey, profile, skypename);
				
				printf("\n::CREDENTIALS::\n");
				printf("Skypename: %s\n",skypename);

				main_unpack_get(profile+0x15, 0x80-0x15, ipinfo, &ipinfo_len);
				//show_memory(ipinfo,ipinfo_len,"IP:");

				if (ipinfo_len==0) {
					printf("no ip block in profile!\n");
					i=i+0x187;
					continue;
				};

				printf("\nProfile:\n");
				main_unpack(profile+0x15, 0x80-0x15);

				sprintf(userid,"0x%x%x%x%x%x%x%x%x",ipinfo[0],ipinfo[1],ipinfo[2],ipinfo[3],
													ipinfo[4],ipinfo[5],ipinfo[6],ipinfo[7]);

				port=ipinfo[13]*0x100+ipinfo[14];
				sprintf(ipport_int,"%d.%d.%d.%d:%d",ipinfo[9],ipinfo[10],ipinfo[11],ipinfo[12],port);
				port=ipinfo[19]*0x100+ipinfo[20];
				sprintf(ipport_ext,"%d.%d.%d.%d:%d",ipinfo[15],ipinfo[16],ipinfo[17],ipinfo[18],port);

				if (ipinfo_len==27){
					port=ipinfo[25]*0x100+ipinfo[26];
					sprintf(ipport_add,"%d.%d.%d.%d:%d",ipinfo[21],ipinfo[22],ipinfo[23],ipinfo[24],port);
				}else{
					ipport_add[0]=0;
				};

				printf("\nLearned new nodeinfo for %s: ipflag: 0x%x\n",skypename,ipinfo[8]);
				printf("%s-s-%s/%s %s\n",userid,ipport_ext,ipport_int,ipport_add);

				//memcpy(userid,ipinfo,8);
				//flag=ipinfo[9];
				//memcpy(&ipint,9,4);
				//memcpy(&portint,13,2);
				//memcpy(&ipext,15,4);
				//memcpy(&porext,19,2);

				i=i+0x187;
			};
		};
	};

	printf("\n:: END ::\n\n");

	return 0;
};

//
// Supernode udp user request
//
int snode_udp_reqsearch(char *destip, u16 destport, char *our_public_ip, char *skypeuser) {
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
	

	bigbuf_count=0;

	// pkt1
	make_udp_reqsearch_pkt1(our_public_ip,destip,seqnum,rnd,skypeuser,(char *)pkt,&pkt_len);
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
			if (bigbuf_count<0x188){
				return -2;
			};
			break;
		};
		retcode=process_udp_reqsearch_pkt1(resp,resp_len,our_public_ip,destip);
		if (retcode==-1) {
			printf("not skype\n");
			//return -3;
			break;
		};

	} while(resp_len>0);


	get_profiles(bigbuf, bigbuf_count);

	//main_unpack (bigbuf, bigbuf_count);


	printf("our public ip: %s\n",our_public_ip);
	printf("this is supernode\n");

	return 1;
	
}








//
// Main
//
//ip of supernode, from skype.log "probe accept"
int main(int argc, char* argv[]) {
	char *destip;
	u16 destport;
	char *skypeuser;
	char our_public_ip[128];
	u32 userslot;
	int ret;
	u32 i;
	
	srand( time(NULL) );


	if (argc!=3){
		printf("usage: <skypename> <you public ip>\n");
		exit(1);
	};

	skypeuser=strdup(argv[1]);
	MY_ADDR=strdup(argv[2]);

	

	strcpy(our_public_ip,MY_ADDR);

	load_slots_file();

	// signed unsinged .. if -1
	userslot=slot_find(skypeuser);
	printf("slot: #%d (0x%08X)\n",userslot,userslot);
	printf("nodes in slot: %d\n",slots[userslot].snodes_len);

	for (i=0;i<slots[userslot].snodes_len;i++){

		destip=slots[userslot].snodes[i].ip;
		destport=atoi(slots[userslot].snodes[i].port);

		printf("sending search request\n");
		printf("target node ip: %s\n",destip);

		ret=snode_udp_reqsearch(destip,destport,our_public_ip,skypeuser);
		if (ret==1){
			//exit(-1);
		};

	};

			


	return 0;
	
}

