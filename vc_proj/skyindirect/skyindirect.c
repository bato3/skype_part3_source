// skyindirect.c : Defines the entry point for the console application.
//

#include <stdio.h>
#include <stdlib.h>

#include <string.h>  
#include <time.h>

#include <fcntl.h>
#include <io.h>

#include <windows.h>

#include "crypto/miracl.h"

#include "short_types.h"

#include "global_vars.h"




extern int make_tcp_client_sess1_pkt1_calc(_MIPD_ char *globalptr, char *pkt);

extern int make_tcp_client_sess1_pkt2(_MIPD_ char *globalptr, char *pkt, int *pkt_len);
extern int make_tcp_client_sess1_pkt3(_MIPD_ char *globalptr, char *pkt, int *pkt_len);
extern int make_tcp_client_sess1_pkt4(_MIPD_ char *globalptr, char *pkt, int *pkt_len);
extern int make_tcp_client_sess1_pkt5(_MIPD_ char *globalptr, char *pkt, int *pkt_len);
extern int make_tcp_client_sess1_pkt6(_MIPD_ char *globalptr, char *pkt, int *pkt_len);
extern int make_tcp_client_sess1_pkt7(_MIPD_ char *globalptr, char *pkt, int *pkt_len);


extern int process_tcp_client_sess1_pkt1(_MIPD_ char *globalptr, char *resp, int resp_len);
extern int process_tcp_client_sess1_pkt2(_MIPD_ char *globalptr, char *resp, int resp_len);
extern int process_tcp_client_sess1_pkt3(_MIPD_ char *globalptr, char *resp, int resp_len);
extern int process_tcp_client_sess1_pkt4(_MIPD_ char *globalptr, char *resp, int resp_len);
extern int process_tcp_client_sess1_pkt5(_MIPD_ char *globalptr, char *resp, int resp_len);
extern int process_tcp_client_sess1_pkt6(_MIPD_ char *globalptr, char *resp, int resp_len);
extern int process_tcp_client_sess1_pkt7(_MIPD_ char *globalptr, char *resp, int resp_len);


extern int parse_input_line(char *line, u32 *secret_p, u32 *secret_q, char *str_skypename, char *user_cred);
extern int parse_input_line_type2(char *line, char *public_key, char *secret_key, char *str_skypename, char *user_cred);
extern int parse_input_line2(char *line, u8 *userhex, char *str_remote_skype, char *destip, char *destport);
extern int restore_user_keypair(_MIPD_ u32 *secret_p, u32 *secret_q, u8 *public_key, u8 *secret_key);
extern int show_memory(char *mem, int len, char *text);

extern int skyrel_main(char *globalptr, int *retsock);
extern int skyrel_answer(char *globalptr, int *retsock);
extern int skypush_main(char *globalptr, char *destip,u16 destport,char *our_public_ip);


int make_tcp_pkt_confirm(char *globalptr, int last_recv_num, char *pkt, int *pkt_len);


extern int tcpn_talk(int *getsock,char *remoteip,u16 remoteport,char *buf,int buf_len,char *result,int result_len);
extern int tcpn_talk_recv(int *getsock, char *result, int result_len);
extern int tcpn_talk_deinit(int *getsock);



uint DEBUG_LEVEL=100;
//uint DEBUG_LEVEL=0;





//
// init global structure
//	
int global_init(char *globalptr) {
	unsigned int rnd;

	u8 LOCAL_UIC_tmp[0x189]=
"\x00\x00\x01\x04\x00\x00\x00\x01\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
;


	u8 AFTER_CRED_tmp[0x81]=
"\x4B\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB"
"\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB"
"\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB"
"\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBA\xFF\xFF\xFF"
"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
"\xFF\x41\x01\x04\x03\x15\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xBC"
;

	u8 skype_pub_tmp[]=
"\xB8\x50\x6A\xEE\xD8\xED\x30\xFE\x1C\x0E\x67\x74\x87\x4B\x59\x20"
"\x6A\x77\x32\x90\x42\xA4\x9B\xE2\x40\x3D\xA4\x7D\x50\x05\x24\x41"
"\x06\x7F\x87\xBC\xD5\x7E\x65\x79\xB8\x3D\xF0\xBA\xDE\x2B\xEF\xF5"
"\xB5\xCD\x8D\x87\xE8\xB3\xED\xAC\x5F\x57\xFA\xBC\xCD\x49\x69\x59"
"\x74\xE2\xB5\xE5\xF0\x28\x7D\x6C\x19\xEC\xC3\x1B\x45\x04\xA9\xF8"
"\xBE\x25\xDA\x78\xFA\x4E\xF3\x45\xF9\x1D\x33\x9B\x73\xCC\x2D\x70"
"\xB3\x90\x4E\x11\xCA\x57\x0C\xE9\xB5\xDC\x4B\x08\xB3\xC4\x4B\x74"
"\xDC\x46\x35\x87\xEA\x63\x7E\xF4\x45\x6E\x61\x46\x2B\x72\x04\x2F"
"\xC2\xF4\xAD\x55\x10\xA9\x85\x0C\x06\xDC\x9A\x73\x74\x41\x2F\xCA"
"\xDD\xA9\x55\xBD\x98\x00\xF9\x75\x4C\xB3\xB8\xCC\x62\xD0\xE9\x8D"
"\x82\x82\x18\x09\x71\x05\x5B\x45\x7C\x06\xF3\x51\xE6\x11\x64\xFC"
"\x5A\x9D\xE9\xD8\x3D\x1D\x13\x78\x96\x40\x01\x38\x0B\x5B\x99\xEE"
"\x4C\x5C\x7D\x50\xAC\x24\x62\xA4\xB7\xEA\x34\xFD\x32\xD9\x0B\xD8"
"\xD4\xB4\x64\x10\x26\x36\x73\xF9\x00\xD1\xC6\x04\x70\x16\x5D\xF9"
"\xF3\xCB\x48\x01\x6A\xB8\xCA\x45\xCE\x68\x75\xA7\x1D\x97\x79\x15"
"\xCA\x82\x51\xB5\x02\x58\x74\x8D\xBC\x37\xFE\x33\x2E\xDC\x28\x55"
;

	u32 REMOTE_SESSION_ID_tmp=0x0;
	u32 LOCAL_SESSION_ID_tmp=0x216F;

	u8 INIT_UNK_tmp[0x16]=
	"\x75\xAA\xBB\xCC\x38\x36\xAA\xBB\x01\xCC\xA9\x02\x28\xDD\xA5\x43\xA5\x15\xA9\xEF\x08";

	u8 CHAT_RND_ID_tmp[0x100]="4fea66013cdd0000";

	uint const1 = 0x55829E55;
	uint const2 = 0x5F359B29;
	uint const3 = 0xE9C261A9;
	uint const4 = 0x49D198E2;
	uint const5 = 0x49D198E7;

	uint const6 = 0x013AF2C7;
	uint const7 = 0x08DD791A;
	uint const8 = 0x4208B88D;

	uint const9 = 0x3D98FFD0;
	uint const10 = 0x3D98FFD0;
	uint const11 = 0x3D98FFD1;

	uint const12 = 0x718CDA9C;
	uint const13 = 0xA29917A7;



	struct global_s *global;
	global=(struct global_s *)globalptr;

	global->BLOB_0_1=const1;
	global->BLOB_0_2=const2;
	global->BLOB_0_2__1=   const3;
	global->BLOB_0_5=      const4;
	global->BLOB_0_5__1=   const5;
	global->BLOB_0_6=      const6;
	global->BLOB_0_7=      const7;
	global->BLOB_0_7__1=   const8;
	global->BLOB_0_7__2=   const9;
	global->BLOB_0_7__3=   const10;
	global->BLOB_0_7__4=   const11;
	global->BLOB_0_9=      const6;
	global->BLOB_0_9__1=   const9;
	global->BLOB_0_A=      const9;
	global->BLOB_0_15=     const12;
	global->BLOB_0_9__2 =  const11;
	global->BLOB_0_A__1  = const11;
	global->BLOB_0_15__1 = const13;
	global->BLOB_0_F =     const9;
	global->BLOB_0_A__2=   const7;
	global->BLOB_0_A__3=   const8;

	global->BLOB_1_9_ptr=0xDBDBCE66;
	global->BLOB_1_9_size=0xF7BB5566;



	memcpy(global->INIT_UNK, INIT_UNK_tmp, sizeof(INIT_UNK_tmp) );

	global->REMOTE_SESSION_ID=REMOTE_SESSION_ID_tmp;
	global->LOCAL_SESSION_ID=LOCAL_SESSION_ID_tmp;

	memcpy(global->skype_pub, skype_pub_tmp, sizeof(skype_pub_tmp) );

	memcpy(global->AFTER_CRED, AFTER_CRED_tmp, sizeof(AFTER_CRED_tmp) );

	memcpy(global->LOCAL_UIC, LOCAL_UIC_tmp, sizeof(LOCAL_UIC_tmp) );
	
	memcpy(global->CHAT_RND_ID, CHAT_RND_ID_tmp, sizeof(CHAT_RND_ID_tmp) );
	memset(global->CHAT_STRING,0,sizeof(global->CHAT_STRING));
	memset(global->CHAT_PEERS,0,sizeof(global->CHAT_PEERS));
	memset(global->MSG_TEXT,0,sizeof(global->MSG_TEXT));
	memset(global->REMOTE_NAME,0,sizeof(global->REMOTE_NAME));
	

	global->connid=0;

	srand( time(NULL) );	

	rnd=rand() % 0x10000;
	rnd+=(rand() % 0x10000)*0x10000;

	global->rnd=rnd;

	rnd=rand() % 0x10000;
	//global->LOCAL_SESSION_ID=rnd;
	global->LOCAL_SESSION_ID=0x63E0;

	if(DEBUG_LEVEL>=100) printf("local connid 0x%08X\n",global->LOCAL_SESSION_ID);


	return 0;
};


int parse_cmd_lines(int argc, char* argv[], char *globalptr) {
	int len;
	u32 secret_p[17], secret_q[17];
	char public_key[0x81];
	char secret_key[0x81];

	char str_skypename[0x1000];
	char user_cred[0x101];

	char str_remote_skype[1024];
	char tmpdestip[1024];
	char tmpdestport[1024];
	u8   userhex[0x1000];

	char line1[0x1000];
	char line2[0x1000];
	int retcode;

	int fd;

	struct global_s *global;
	global=(struct global_s *)globalptr;

	memset(public_key,0,sizeof(public_key));
	memset(secret_key,0,sizeof(secret_key));

	if (argc!=2){
		printf("usege: skydirect <our public ip>\n");
		return -1;
	};

	strncpy(global->our_public_ip,argv[1],0x100);

	fd=open("a_cred.txt",O_RDONLY);
	len=read(fd,&line1,0x1000);
	close(fd);
	if (len<=0){
		if(DEBUG_LEVEL>=100) printf("file open error\n");
		return -1;
	};
	if (len>=0x1000){
		if(DEBUG_LEVEL>=100) printf("file too big\n");
		return -1;
	};

	line1[len]=0;
	while(len>0){
		if (line1[len]==0x0D){
			line1[len]=0;
		};
		if (line1[len]==0x0A){
			line1[len]=0;
		};
		len--;
	}

	len=strlen(line1);

	//printf("%c %c\n",line1[len-2], line1[len-1] );

	if ( (line1[len-2]==':') && (line1[len-1]=='2') ){

		if (DEBUG_LEVEL>=100) printf("format version 2\n");

		retcode=parse_input_line_type2(line1, (char*)&public_key, (char*)&secret_key, (char*)&str_skypename, (char*)&user_cred);
		if (retcode==-1){
			if(DEBUG_LEVEL>=100) printf("parsing error\n");
			return -1;
		};

		memcpy(global->xoteg_pub,public_key,0x80);
		memcpy(global->xoteg_sec,secret_key,0x80);

		show_memory(global->xoteg_pub,0x80,"xoteg_pubkey:");
		show_memory(global->xoteg_sec,0x80,"xoteg_seckey:");

	}else{

		if (DEBUG_LEVEL>=100) printf("format version 1\n");

		parse_input_line(line1, secret_p, secret_q, (char*)&str_skypename, (char*)&user_cred);

		restore_user_keypair(_MIPP_ secret_p, secret_q, public_key, secret_key);

		memcpy(global->xoteg_pub,public_key,0x80);
		memcpy(global->xoteg_sec,secret_key,0x80);

		show_memory(global->xoteg_pub,0x80,"xoteg_pubkey:");
		show_memory(global->xoteg_sec,0x80,"xoteg_seckey:");
	};




	if(DEBUG_LEVEL>=100) printf("skypename=%s\n",str_skypename);

	show_memory(user_cred,0x100,"cred:");

	memcpy(global->CREDENTIALS,"\x00\x00\x00\x01",4);
	memcpy(global->CREDENTIALS+4,user_cred,0x100);
	global->CREDENTIALS_LEN=0x104;


	//
	fd=open("a_sendto.txt",O_RDONLY);
	len=read(fd,&line2,0x1000);
	close(fd);
	if (len<=0){
		if(DEBUG_LEVEL>=100) printf("file open error\n");
		return -1;
	};
	if (len>=0x1000){
		if(DEBUG_LEVEL>=100) printf("file too big\n");
		return -1;
	};
	line2[len]=0;


	retcode=parse_input_line2(line2, (u8 *)&userhex, (char *)&str_remote_skype, (char *)&tmpdestip, (char *)&tmpdestport);

	if(DEBUG_LEVEL>=100) show_memory(userhex,0x08,"userhex id:");

	memcpy(global->USERHEX,userhex,0x08);

	if (retcode==-1){
		if (DEBUG_LEVEL>=100) printf("load parsing, at sendto file parsing error\n");
		return -1;
	};


	if(DEBUG_LEVEL>=100) printf("remote_skypename=%s\n",str_remote_skype);
	if(DEBUG_LEVEL>=100) printf("destip=%s\n",tmpdestip);
	if(DEBUG_LEVEL>=100) printf("destport=%s\n",tmpdestport);



	strncpy(global->user_snodeip,tmpdestip,1024);
	global->user_snodeport=atoi(tmpdestport);

	show_memory(global->CREDENTIALS,0x104,"CREDENTIALS:");


	strcpy(global->REMOTE_NAME,str_remote_skype);

	strcat(global->CHAT_STRING,"#");
	strcat(global->CHAT_STRING,str_skypename);
	strcat(global->CHAT_STRING,"/$");
	strcat(global->CHAT_STRING,global->REMOTE_NAME);
	strcat(global->CHAT_STRING,";");
	strcat(global->CHAT_STRING,global->CHAT_RND_ID);

	strcat(global->CHAT_PEERS,global->REMOTE_NAME);
	strcat(global->CHAT_PEERS," ");
	strcat(global->CHAT_PEERS,str_skypename);


	if(DEBUG_LEVEL>=100) printf("CHAT_STRING: %s\n",global->CHAT_STRING);
    if(DEBUG_LEVEL>=100) printf("REMOTE_NAME: %s\n",global->REMOTE_NAME);
    if(DEBUG_LEVEL>=100) printf("CHAT_PEERS: %s\n",global->CHAT_PEERS);


	fd=open("a_msg.txt",O_RDONLY);
	len=read(fd,&global->MSG_TEXT,0x1000);
	close(fd);
    
	if (len<=0){
		if(DEBUG_LEVEL>=100) printf("file open error\n");
		return -1;
	};
	if (len>=0x1000){
		if(DEBUG_LEVEL>=100) printf("file too big\n");
		return -1;
	};

	global->MSG_TEXT[len]=0;

 	if(DEBUG_LEVEL>=100) printf("\nMSG_TEXT: %s\n",global->MSG_TEXT);


	return 0;
}



int main_skypeclient_tcpconnect(char *globalptr, int *retsock){
	char *destip;
	u16 destport;

	unsigned int rnd;

	char resp[0x2005];
	int resp_len;
	char pkt[0x2005];
	int pkt_len;

	int retcode;
	int resp_maxlen;
	//u32 last_recv_num;
	//u8 confirm[0x100];
	//u32 confirm_len;

	struct global_s *global;
	global=(struct global_s *)globalptr;


	destip=global->remoteip;
	destport=global->remoteport;

	/*

	rnd=rand() % 0x10000;
	rnd+=(rand() % 0x10000)*0x10000;

	global->rnd=rnd;
	*/
	rnd=global->rnd;

	resp_maxlen=sizeof(resp)-1;

	memset(pkt,0,sizeof(pkt));

	
	make_tcp_client_sess1_pkt1_calc(_MIPP_ globalptr, (char *)pkt);

	/*
	// pkt 1
		resp_len=tcp1_talk(destip,destport,pkt,pkt_len,resp,0);
	if (resp_len==-1){
		if(DEBUG_LEVEL>=100) printf("socket comm error\n");
		//tcp1_talk_deinit();
		return -11;
	};
	if (resp_len==0){
		if(DEBUG_LEVEL>=100) printf("connection failed\n");
		//tcp1_talk_deinit();
		return -12;
	};
	if (resp_len==-2){
		if(DEBUG_LEVEL>=100) printf("timeout\n");
		//tcp1_talk_deinit();
		return -13;
	};
	retcode=process_tcp_client_sess1_pkt1(_MIPP_ globalptr, resp, resp_len);
	if (retcode==-1) {
		if(DEBUG_LEVEL>=100) printf("process1 failed\n");
		//tcp1_talk_deinit();
		return -10;
	};

	*/
	// pkt 2
	//make_tcp_client_sess1_pkt2(_MIPP_ globalptr, (char *)pkt, &pkt_len);


	resp_len=tcpn_talk_recv(retsock,resp,resp_maxlen);
	if (resp_len==-1){
		if(DEBUG_LEVEL>=100) printf("socket comm error\n");
		tcpn_talk_deinit(retsock);
		return -21;
	};
	if (resp_len==0){
		if(DEBUG_LEVEL>=100) printf("connection failed\n");
		tcpn_talk_deinit(retsock);
		return -22;
	};
	if (resp_len==-2){
		if(DEBUG_LEVEL>=100) printf("timeout\n");
		tcpn_talk_deinit(retsock);
		return -23;
	};
	retcode=process_tcp_client_sess1_pkt2(_MIPP_ globalptr, resp, resp_len);
	if (retcode==-1) {
		if(DEBUG_LEVEL>=100) printf("process2 failed\n");
		tcpn_talk_deinit(retsock);
		return -20;
	};


	// pkt 3
	make_tcp_client_sess1_pkt3(_MIPP_ globalptr, (char *)pkt, &pkt_len);

	/*
	/////////////
	// confirm
	/////////////
	last_recv_num=global->last_recv_num;
	retcode=make_tcp_pkt_confirm(globalptr, last_recv_num, (char *)confirm, &confirm_len);
	if (retcode==-1) {
		printf("build pkt fail confirm\n");
		return -1;
	};

	memcpy(pkt+pkt_len,confirm,confirm_len);
	pkt_len+=confirm_len;
	// pkt send confirm
	resp_len=tcp2_talk_send_sock(confirm,confirm_len,0);
	if (resp_len<0) {
		printf("pkt3, socket error\n");
		//tcp2_talk_deinit();
		return -1;
	};
	*/
	


	resp_len=tcpn_talk(retsock,destip,destport,pkt,pkt_len,resp,resp_maxlen);
	if (resp_len==-1){
		if(DEBUG_LEVEL>=100) printf("socket comm error\n");
		tcpn_talk_deinit(retsock);
		return -31;
	};
	if (resp_len==0){
		if(DEBUG_LEVEL>=100) printf("connection failed\n");
		tcpn_talk_deinit(retsock);
		return -32;
	};
	if (resp_len==-2){
		if(DEBUG_LEVEL>=100) printf("timeout\n");
		tcpn_talk_deinit(retsock);
		return -33;
	};
	retcode=process_tcp_client_sess1_pkt3(_MIPP_ globalptr, resp, resp_len);
	if (retcode==-1) {
		if(DEBUG_LEVEL>=100) printf("process3 failed\n");
		tcpn_talk_deinit(retsock);
		return -30;
	};



	//Sleep(5000);
	//return -1;


	// pkt 4
	make_tcp_client_sess1_pkt4(_MIPP_ globalptr, (char *)pkt, &pkt_len);
	resp_len=tcpn_talk(retsock,destip,destport,pkt,pkt_len,resp,resp_maxlen);
	if (resp_len==-1){
		if(DEBUG_LEVEL>=100) printf("socket comm error\n");
		tcpn_talk_deinit(retsock);
		return -41;
	};
	if (resp_len==0){
		if(DEBUG_LEVEL>=100) printf("connection failed\n");
		tcpn_talk_deinit(retsock);
		return -42;
	};
	if (resp_len==-2){
		if(DEBUG_LEVEL>=100) printf("timeout\n");
		tcpn_talk_deinit(retsock);
		return -43;
	};
	retcode=process_tcp_client_sess1_pkt4(_MIPP_ globalptr, resp, resp_len);
	if (retcode==-1) {
		if(DEBUG_LEVEL>=100) printf("process4 failed\n");
		tcpn_talk_deinit(retsock);
		return -40;
	};

	// pkt 5
	make_tcp_client_sess1_pkt5(_MIPP_ globalptr, (char *)pkt, &pkt_len);
	resp_len=tcpn_talk(retsock,destip,destport,pkt,pkt_len,resp,resp_maxlen);
	if (resp_len==-1){
		if(DEBUG_LEVEL>=100) printf("socket comm error\n");
		tcpn_talk_deinit(retsock);
		return -51;
	};
	if (resp_len==0){
		if(DEBUG_LEVEL>=100) printf("connection failed\n");
		tcpn_talk_deinit(retsock);
		return -52;
	};
	if (resp_len==-2){
		if(DEBUG_LEVEL>=100) printf("timeout\n");
		tcpn_talk_deinit(retsock);
		return -53;
	};
	retcode=process_tcp_client_sess1_pkt5(_MIPP_ globalptr, resp, resp_len);
	if (retcode==-1) {
		if(DEBUG_LEVEL>=100) printf("process5 failed\n");
		tcpn_talk_deinit(retsock);
		return -50;
	};


	// pkt 6
	make_tcp_client_sess1_pkt6(_MIPP_ globalptr, (char *)pkt, &pkt_len);
	resp_len=tcpn_talk(retsock,destip,destport,pkt,pkt_len,resp,resp_maxlen);
	if (resp_len==-1){
		if(DEBUG_LEVEL>=100) printf("socket comm error\n");
		tcpn_talk_deinit(retsock);
		return -61;
	};
	if (resp_len==0){
		if(DEBUG_LEVEL>=100) printf("connection failed\n");
		tcpn_talk_deinit(retsock);
		return -62;
	};
	if (resp_len==-2){
		if(DEBUG_LEVEL>=100) printf("timeout\n");
		tcpn_talk_deinit(retsock);
		return -63;
	};
	retcode=process_tcp_client_sess1_pkt6(_MIPP_ globalptr, resp, resp_len);
	if (retcode==-1) {
		if(DEBUG_LEVEL>=100) printf("process6 failed\n");
		tcpn_talk_deinit(retsock);
		return -60;
	};


	// pkt 7
	make_tcp_client_sess1_pkt7(_MIPP_ globalptr, (char *)pkt, &pkt_len);
	resp_len=tcpn_talk(retsock,destip,destport,pkt,pkt_len,resp,resp_maxlen);
	if (resp_len==-1){
		if(DEBUG_LEVEL>=100) printf("socket comm error\n");
		tcpn_talk_deinit(retsock);
		return -71;
	};
	if (resp_len==0){
		if(DEBUG_LEVEL>=100) printf("connection failed\n");
		tcpn_talk_deinit(retsock);
		return -72;
	};
	if (resp_len==-2){
		if(DEBUG_LEVEL>=100) printf("timeout\n");
		tcpn_talk_deinit(retsock);
		return -73;
	};
	retcode=process_tcp_client_sess1_pkt7(_MIPP_ globalptr, resp, resp_len);
	if (retcode==-1) {
		if(DEBUG_LEVEL>=100) printf("process7 failed\n");
		tcpn_talk_deinit(retsock);
		return -70;
	};




	return 1;
};



int main(int argc, char* argv[]){
	struct global_s global;
	int retcode;
	miracl *mr_mip;
	int retsock=-1;
	//char our_public_ip[0x100];

	//mr_mip=mirsys(_MIPP_ 100, 0);
	mr_mip=mirsys(100, 0);




	global_init((char *)&global);
	
	retcode=parse_cmd_lines(argc, argv, (char *)&global);
	if (retcode==-1){
		if (DEBUG_LEVEL>=100) printf("argv error\n");
		return -1;
	};

	/////////////
	// new code
	///////////

	// relay
	retcode=skyrel_main((char *)&global, &retsock);
	if (retcode==-1){
		if (DEBUG_LEVEL>=100) printf("Not found good relays\n");
		return -1;
	};
	if (retsock==-1){
		if (DEBUG_LEVEL>=100) printf("Socket error in relay setup\n");
		return -1;
	};

	if (DEBUG_LEVEL>=100) printf("retsock main: 0x%08X\n",retsock);
	if (DEBUG_LEVEL>=100) printf("Relay node ip: %s:%d\n",global.relayip,global.relayport);
	if (DEBUG_LEVEL>=100) printf("Got connid: 0x%08X\n",global.connid);

	//strcpy(our_public_ip,"95.52.137.99");


	// push
	retcode=skypush_main((char *)&global,global.user_snodeip,global.user_snodeport,global.our_public_ip);
	if (retcode==-1){
		if (DEBUG_LEVEL>=100) printf("Bad answer from user snode\n");
		return -1;
	};




	
	// recv
	retcode=skyrel_answer((char *)&global, &retsock);
	if (retcode==-1){
		if (DEBUG_LEVEL>=100) printf("Remote peer fail relay\n");
		return -1;
	};
	
	
	
	
	//Sleep(1000);

	/////////////////
	// end new code
	/////////////////

	

	retcode=main_skypeclient_tcpconnect( (char *)&global, &retsock);

	if (retcode==0){
		if(DEBUG_LEVEL>=100) printf("message delivered\n");
	};

	mirexit();

	return 0;
};



