// skyaddr2.c : Defines the entry point for the console application.
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
extern int make_udp_search_by_country_pkt1(char *ourip,char *destip, u16 seqnum, u32 rnd, char *skypeuser, char *req_country,
																		char *pkt, int *pkt_len);
extern int make_udp_profile_pkt1(char *ourip,char *destip, u16 seqnum, u32 rnd, char *skypeuser,
																		char *pkt, int *pkt_len);
extern int process_udp_search_pkt1(char *pkt,int pkt_len,char *ourip,char *destip, char *mainbuf, u32 *mainbuf_len);
extern int udp_talk(char *remoteip, u16 remoteport, char *buf, int len, char *result, int result_maxlen);
extern int udp_recv(char *remoteip, unsigned short remoteport, char *result, int result_maxlen);
extern int show_memory(char *mem, int len, char *text);
extern int decode_profile(u8 *remote_profile, u8 *pubkey, u8 *data, u8 *skypename, u32 sk_len);
extern int process_pkt(char *pkt, int pkt_len, int use_replyto, int *last_recv_pkt_num);


// snodes slot structure
#define SNODES_MAX 0x100
struct _snodes_straddr {
	char *ip;
	char *port;
};
struct _slots {
	struct _snodes_straddr snodes[SNODES_MAX];
	u32 snodes_len;
};
struct _slots slots[2048];
// end 


//
// load nodes in slot structure
//
int load_slots_file(){
	FILE *fp;
	char line[8192];
	int file_ret;
	char *ptr;
	u32 slotid=0;

	fp=fopen("./_getnodes.txt","r");
	if (fp==NULL){
		return -1;
	};
	

	do {
		line[0]=0;
		file_ret=fscanf(fp,"%s\n",&line);
		if (strlen(line)!=0){
			if (strstr(line,"::")!=NULL){
				continue;
			};
			if (strstr(line,"Slot:")!=NULL){
				continue;
			};
			if (strstr(line,"0x")!=NULL){
				sscanf(line,"%x",&slotid);
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
				slots[slotid].snodes_len++;
				if (slots[slotid].snodes_len > SNODES_MAX){
					return -1;
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


//
// Decode profile
// 
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


	u8 skypename[1024];
	u32 sk_len;

	sk_len=sizeof(skypename);

	//printf("Len= 0x%x\n",len);

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
				ret=decode_profile(cred, pubkey, profile, skypename, sk_len);
				if (ret==-1){
					printf("\n::CREDENTIALS::\n");
					printf("Profile decoding failed\n");
					i=i+0x187;
					continue;					
				};
				memcpy(ptr+0x108,profile,0x80);
				
				printf("\n::CREDENTIALS::\n");
				printf("Skypename: %s\n",skypename);

				printf("\nProfile:\n");
				main_unpack(profile+0x15, 0x80-0x15);

				main_unpack(ptr+0x108+0x15, len-i-0x108-0x15);
				printf("ost len:0x%08X\n",len-i-0x108-0x15);

				//main_unpack_get(profile+0x15, 0x80-0x15, ipinfo, &ipinfo_len);
				
				main_unpack_get(ptr+0x108+0x15, len-i-0x108, ipinfo, &ipinfo_len);
				if (ipinfo_len==0) {
					printf("Not found ip block in profile!\n");
				}else{
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
				};

				
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
	char resp[0x1000];
	int resp_len;
	char pkt[0x1000];
	int pkt_len;
	int retcode;
	char *mainbuf;
	u32 mainbuf_len;
	u32 mainbuf_alloc;


	mainbuf=malloc(0x1000);
	mainbuf_len=0;
	mainbuf_alloc=0x1000;

	seqnum=rand() % 0x10000;

	rnd=rand() % 0x10000;
	rnd+=(rand() % 0x10000)*0x10000;
	

	// pkt1
	retcode=make_udp_profile_pkt1(our_public_ip,destip,seqnum,rnd,skypeuser,(char *)pkt,&pkt_len);
	if (retcode==-1) {
		//printf("prepare error\n");
		free(mainbuf);
		return -1;
	};
	resp_len=udp_talk(destip,destport,pkt,pkt_len,resp,sizeof(resp));
	if (resp_len<0) {
		//printf("socket comm error\n");
		free(mainbuf);
		return -1;
	};
	if (resp_len==0) {
		//printf("timeout\n");
		free(mainbuf);
		return -2;
	};
	retcode=process_udp_search_pkt1(resp,resp_len,our_public_ip,destip, mainbuf, &mainbuf_len);
	if (retcode==-1) {
		//printf("not skype\n");
		free(mainbuf);
		return -3;
	};
	
	mainbuf_alloc+=0x1000;
	mainbuf=realloc(mainbuf,mainbuf_alloc);

	do {

		resp_len=udp_recv(destip,destport,resp,sizeof(resp));
		if (resp_len<0) {
			//printf("socket comm error\n");
			//return -1;
			break;
		};
		if (resp_len==0) {
			//printf("timeout\n");
			//return -2;
			if (mainbuf_len<0x188){
				free(mainbuf);
				return -2;
			};
			break;
		};
		retcode=process_udp_search_pkt1(resp,resp_len,our_public_ip,destip, mainbuf, &mainbuf_len);
		if (retcode==-1) {
			//printf("not skype\n");
			//return -3;
			break;
		};
		

		mainbuf_alloc+=0x1000;
		mainbuf=realloc(mainbuf,mainbuf_alloc);


	} while(resp_len>0);


	get_profiles(mainbuf, mainbuf_len);
	main_unpack(mainbuf, mainbuf_len);

	if (0){
		u32 last_recv_pkt_num;
		process_pkt(mainbuf, mainbuf_len, 1, &last_recv_pkt_num);
	};


	free(mainbuf);

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
	char *skypeuser;
	char our_public_ip[128];
	u32 userslot;
	int ret;
	u32 i;
	FILE *fp;
	char line[8192];
	int file_ret;
	char *MY_ADDR;
	

	srand( time(NULL) );



	/*
	if (argc!=3){
		printf("usage: <skypename> <you public ip>\n");
		exit(1);
	};
	skypeuser=strdup(argv[1]);
	MY_ADDR=strdup(argv[2]);
	*/

	if (argc!=2){
		printf("usage: <you public ip>\n");
		exit(1);
	};
	MY_ADDR=strdup(argv[1]);

  
	

	strcpy(our_public_ip,MY_ADDR);

	ret=load_slots_file();
	if (ret==-1){
		printf("load nodes error\n");
		return -1;
	};


	fp=fopen("./_names.txt","r");
	if (fp==NULL){
		printf("file with names not found\n");
		return -1;
	};


	do {
		
		line[0]=0;
		file_ret=fscanf(fp,"%s\n",&line);
		if (strlen(line)==0){
			continue;
		};
		skypeuser=line;

		userslot=slot_find(skypeuser);

		printf("SkypeUser: %s\n",skypeuser);
		printf("User Slot: #%d (0x%08X)\n",userslot,userslot);
		printf("Nodes in slot: %d\n",slots[userslot].snodes_len);

		for (i=0;i<slots[userslot].snodes_len;i++){

			destip=slots[userslot].snodes[i].ip;
			destport=atoi(slots[userslot].snodes[i].port);

			printf("Search request to target node ip: %s\n",destip);

			ret=snode_udp_reqsearch(destip,destport,our_public_ip,skypeuser);
			if (ret==1){
				//exit(1);
			};
		};

	}while(file_ret!=EOF);


	fclose(fp);

			


	return 0;
	
}

