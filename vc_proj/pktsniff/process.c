// process.c : Processing data in packets.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <winsock2.h>

#include "rc4/Expand_IV.h"

#include "session.h"

extern unsigned int Calculate_CRC32(char *crc32, int bytes);
extern int main_unpack(FILE *fp, u8 *indata, u32 inlen);
extern int process_pkt(FILE *fp, char *pkt, int pkt_len, int use_replyto);
extern int show_memory(FILE *fp, char *mem, int len, char *text);


extern int session_udp_count;
extern int session_tcp_count;
extern int DEBUG;

int process_tcp_first_send(FILE *fp, char *pkt, int pkt_len, RC4_context *rc4);
int process_tcp_other_send(FILE *fp, char *pkt, int pkt_len, RC4_context *rc4);
int process_tcp_first_recv(FILE *fp, char *pkt, int pkt_len, RC4_context *rc4);
int process_tcp_other_recv(FILE *fp, char *pkt, int pkt_len, RC4_context *rc4);


int process_udp_first_send(FILE *fp, char *pkt, int pkt_len, RC4_context *rc4, u32 destip);
int process_udp_other_send(FILE *fp, char *pkt, int pkt_len, RC4_context *rc4);
int process_udp_first_recv(FILE *fp, char *pkt, int pkt_len, RC4_context *rc4, u32 destip);
int process_udp_other_recv(FILE *fp, char *pkt, int pkt_len, RC4_context *rc4);

int process_udp_nack_recv(FILE *fp, char *pkt, int pkt_len, u32 *remote_udp_rnd, u32 *public_ip);


extern u8 MY_ADDR[0x100];

//
// process TCP send
//
int process_tcp_send(FILE *fp, char *pkt, int pkt_len, u32 srcip, u16 sport, u32 destip, u16 dport) {
	int i;
	int ifound;
	RC4_context *rc4;

	//fprintf(fp,"tcp send session check begin\n");
	//fprintf(fp,"pkt destip=0x%08X\n",destip);
	//fprintf(fp,"pkt dport=0x%08X\n",dport);
	//fprintf(fp,"pkt srcip=0x%08X\n",srcip);
	//fprintf(fp,"pkt sport=0x%08X\n",sport);
	ifound=-1;
	for (i=0;i<session_tcp_count;i++){

		//fprintf(fp,"destip=0x%08X\n",session_tcp[i].dest_ip);
		//fprintf(fp,"dport=0x%08X\n",session_tcp[i].dport);
		//fprintf(fp,"srcip=0x%08X\n",session_tcp[i].src_ip);
		//fprintf(fp,"sport=0x%08X\n",session_tcp[i].sport);

		if((destip==session_tcp[i].dest_ip) && (dport==session_tcp[i].dport)){
			ifound=i;
		};

	};
	//fprintf(fp,"tcp send session check end\n");

	
	fprintf(fp,"tcp send ifound=%d\n",ifound);
	fprintf(fp,"session_tcp_count=%d\n",session_tcp_count);



	// add new session
	if (ifound==-1){

		ifound=session_tcp_count;
		session_tcp[ifound].dest_ip=destip;
		session_tcp[ifound].dport=dport;
		session_tcp[ifound].src_ip=srcip;
		session_tcp[ifound].sport=sport;
		session_tcp[ifound].send_count=0;
		session_tcp[ifound].recv_count=0;

		session_tcp_count++;

		if (session_tcp_count>MAX_TCP_SESSION){
			printf("tcp session limit exceed\n");
			exit(-1);
		}

	};



	rc4=&session_tcp[ifound].rc4_send;

	if (session_tcp[ifound].send_count==0) {
		process_tcp_first_send(fp, pkt, pkt_len, rc4);
	}else{
		process_tcp_other_send(fp, pkt, pkt_len, rc4);
	};

	session_tcp[ifound].send_count++;

	return 0;
};



//
// process TCP recv
//
int process_tcp_recv(FILE *fp, char *pkt, int pkt_len, u32 srcip, u16 sport, u32 destip, u16 dport) {
	int i;
	int ifound;
	RC4_context *rc4;


	//fprintf(fp,"tcp recv session check begin\n");
	//fprintf(fp,"pkt destip=0x%08X\n",destip);
	//fprintf(fp,"pkt dport=0x%08X\n",dport);
	//fprintf(fp,"pkt srcip=0x%08X\n",srcip);
	//fprintf(fp,"pkt sport=0x%08X\n",sport);
	ifound=-1;
	for (i=0;i<session_tcp_count;i++){

		//fprintf(fp,"destip=0x%08X\n",session_tcp[i].dest_ip);
		//fprintf(fp,"dport=0x%08X\n",session_tcp[i].dport);
		//fprintf(fp,"srcip=0x%08X\n",session_tcp[i].src_ip);
		//fprintf(fp,"sport=0x%08X\n",session_tcp[i].sport);

		if((srcip==session_tcp[i].dest_ip) && (sport==session_tcp[i].dport)){
			ifound=i;
		};

	};
	//fprintf(fp,"tcp recv session check end\n");


	fprintf(fp,"tcp recv ifound=%d\n",ifound);
	fprintf(fp,"session_tcp_count=%d\n",session_tcp_count);


	// add new session
	if (ifound==-1){

		ifound=session_tcp_count;
		session_tcp[ifound].dest_ip=destip;
		session_tcp[ifound].dport=dport;
		session_tcp[ifound].src_ip=srcip;
		session_tcp[ifound].sport=sport;
		session_tcp[ifound].send_count=0;
		session_tcp[ifound].recv_count=0;

		session_tcp_count++;

		if (session_tcp_count>MAX_TCP_SESSION){
			printf("tcp session limit exceed\n");
			exit(-1);
		}

	};


	rc4=&session_tcp[ifound].rc4_recv;

	if (session_tcp[ifound].recv_count==0) {
		process_tcp_first_recv(fp, pkt, pkt_len, rc4);
	}else{
		process_tcp_other_recv(fp, pkt, pkt_len, rc4);
	};

	session_tcp[ifound].recv_count++;


	return 0;
};





//
// process TCP first pkt send
//
int process_tcp_first_send(FILE *fp, char *pkt, int pkt_len, RC4_context *rc4) {
	u32 rnd;
	u32	iv;


	show_memory(fp,pkt,pkt_len,"result:");

	if (pkt_len < 0x0E) {
		fprintf(fp,"Not First TCP packet send!\n");
		fprintf(stdout,"Not First TCP packet send!\n");
		return -1;
	};


	//get rnd
	memcpy((char*)&rnd,pkt,4);
	rnd=bswap32(rnd);
	
	iv = rnd;


	Skype_RC4_Expand_IV (rc4, iv, 1);
	RC4_crypt (pkt+4, 10, rc4, 1);

	show_memory(fp,pkt+4,10,"rc4 decoded:");
	main_unpack(fp, pkt+4, 10);
	
	if (pkt_len > 0x0E) {
		RC4_crypt (pkt+14, pkt_len-14, rc4, 0);
	
		show_memory(fp, pkt+14, pkt_len-14,"rc4 decoded:");
		main_unpack(fp, pkt+14, pkt_len-14);
	};

	
	return 0;
};


//
// process TCP other pkt send
//
int process_tcp_other_send(FILE *fp, char *pkt, int pkt_len, RC4_context *rc4) {

	show_memory(fp,pkt,pkt_len,"result:");

	RC4_crypt (pkt, pkt_len, rc4, 0);

	show_memory(fp, pkt, pkt_len,"rc4 decoded:");
	main_unpack(fp, pkt, pkt_len);
	

	return 0;
};


//
// process TCP first pkt recv
//
int process_tcp_first_recv(FILE *fp, char *pkt, int pkt_len, RC4_context *rc4) {
	u32 rnd;
	u32	iv;


	show_memory(fp,pkt,pkt_len,"result:");

	if (pkt_len < 0x0E) {
		fprintf(fp,"Not First TCP packet send!\n");
		fprintf(stdout,"Not First TCP packet send!\n");
		return -1;
	};


	//get rnd
	memcpy((char*)&rnd,pkt,4);
	rnd=bswap32(rnd);
	
	iv = rnd;


	Skype_RC4_Expand_IV (rc4, iv, 1);
	RC4_crypt (pkt+4, 10, rc4, 1);

	show_memory(fp,pkt+4,10,"rc4 decoded:");
	main_unpack(fp, pkt+4, 10);
	
	if (pkt_len > 0x0E) {
		RC4_crypt (pkt+14, pkt_len-14, rc4, 0);
	
		show_memory(fp, pkt+14, pkt_len-14,"rc4 decoded:");
		main_unpack(fp, pkt+14, pkt_len-14);
	};


	return 0;
};


//
// process TCP other pkt recv
//
int process_tcp_other_recv(FILE *fp, char *pkt, int pkt_len, RC4_context *rc4) {

	show_memory(fp,pkt,pkt_len,"result:");

	RC4_crypt (pkt, pkt_len, rc4, 0);

	show_memory(fp, pkt, pkt_len,"rc4 decoded:");
	main_unpack(fp, pkt, pkt_len);


	return 0;
};



/////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////

//
// UDP Section
//




//
// process UDP send
//
int process_udp_send(FILE *fp, char *pkt, int pkt_len, u32 srcip, u16 sport, u32 destip, u16 dport) {
	int i;
	int ifound;
	RC4_context *rc4;

	//fprintf(fp,"udp send session check begin\n");
	//fprintf(fp,"pkt destip=0x%08X\n",destip);
	//fprintf(fp,"pkt dport=0x%08X\n",dport);
	//fprintf(fp,"pkt srcip=0x%08X\n",srcip);
	//fprintf(fp,"pkt sport=0x%08X\n",sport);
	ifound=-1;
	for (i=0;i<session_udp_count;i++){

		//fprintf(fp,"destip=0x%08X\n",session_udp[i].dest_ip);
		//fprintf(fp,"dport=0x%08X\n",session_udp[i].dport);
		//fprintf(fp,"srcip=0x%08X\n",session_udp[i].src_ip);
		//fprintf(fp,"sport=0x%08X\n",session_udp[i].sport);

		if((destip==session_udp[i].dest_ip) && (dport==session_udp[i].dport)){
			ifound=i;
		};

	};
	//fprintf(fp,"udp send session check end\n");


	fprintf(fp,"udp send ifound=%d\n",ifound);
	fprintf(fp,"session_udp_count=%d\n",session_udp_count);
	

	// new session
	if (ifound==-1){
		
		ifound=session_udp_count;
		
		session_udp[ifound].dest_ip=destip;
		session_udp[ifound].dport=dport;
		session_udp[ifound].src_ip=srcip;
		session_udp[ifound].sport=sport;
		session_udp[ifound].send_count=0;
		session_udp[ifound].recv_count=0;

		session_udp_count++;

		if (session_udp_count>MAX_UDP_SESSION){
			printf("udp session limit exceed\n");
			exit(-1);
		};
	};
	

	rc4=&session_udp[ifound].rc4_send;


	if (session_udp[ifound].send_count==0) {
		
		process_udp_first_send(fp, pkt, pkt_len, rc4, destip);

	}else{
		
		process_udp_first_send(fp, pkt, pkt_len, rc4, destip);
		//process_udp_other_send(fp, pkt, pkt_len, rc4);

	};


	session_udp[ifound].send_count++;


	return 0;
};



//
// process UDP recv
//
int process_udp_recv(FILE *fp, char *pkt, int pkt_len, u32 srcip, u16 sport, u32 destip, u16 dport) {
	int i;
	int ifound;
	RC4_context *rc4;
	u32 remote_udp_rnd;
	u32 public_ip;


	//fprintf(fp,"udp recv session check begin\n");
	//fprintf(fp,"pkt destip=0x%08X\n",destip);
	//fprintf(fp,"pkt dport=0x%08X\n",dport);
	//fprintf(fp,"pkt srcip=0x%08X\n",srcip);
	//fprintf(fp,"pkt sport=0x%08X\n",sport);
	ifound=-1;
	for (i=0;i<session_udp_count;i++){

		//fprintf(fp,"destip=0x%08X\n",session_udp[i].dest_ip);
		//fprintf(fp,"dport=0x%08X\n",session_udp[i].dport);
		//fprintf(fp,"srcip=0x%08X\n",session_udp[i].src_ip);
		//fprintf(fp,"sport=0x%08X\n",session_udp[i].sport);

		if((srcip==session_udp[i].dest_ip) && (sport==session_udp[i].dport)){
			ifound=i;
		};

	};
	//fprintf(fp,"udp recv session check end\n");


	fprintf(fp,"udp recv ifound=%d\n",ifound);
	fprintf(fp,"session_udp_count=%d\n",session_udp_count);


	// new session
	if (ifound==-1){

		ifound=session_udp_count;
		session_udp[ifound].dest_ip=destip;
		session_udp[ifound].dport=dport;
		session_udp[ifound].src_ip=srcip;
		session_udp[ifound].sport=sport;
		session_udp[ifound].send_count=0;
		session_udp[ifound].recv_count=0;

		session_udp_count++;

		if (session_udp_count>MAX_UDP_SESSION){
			printf("udp session limit exceed\n");
			exit(-1);
		};
	};


	rc4=&session_udp[ifound].rc4_recv;


	if (session_udp[ifound].recv_count==0) {

		if (pkt_len==0x0B) {
			process_udp_nack_recv(fp, pkt, pkt_len, &remote_udp_rnd, &public_ip);
		
			session_udp[ifound].remote_udp_rnd=remote_udp_rnd;
			session_udp[ifound].public_ip=public_ip;

			session_udp[ifound].recv_count--;

		}else{
			
			process_udp_first_recv(fp, pkt, pkt_len, rc4, srcip);

		};
	
	}else{
	
		process_udp_other_recv(fp, pkt, pkt_len, rc4);

	};


	session_udp[ifound].recv_count++;


	return 0;
};






//
// process UDP first pkt send
//
int process_udp_first_send(FILE *fp, char *pkt, int pkt_len, RC4_context *rc4, u32 destip) {
	int len;
	u32 rnd;
	u32	iv, iv3[3];
	u32 pkt_crc32;
	u32 targetip;
	u32 publicip;
	u16 seqnum;
	u32 tmp;

	if (DEBUG) fprintf(fp,"udp first send\n");

	show_memory(fp,pkt,pkt_len,"result:");

	if (pkt_len < 0x0B) {
		fprintf(fp,"Not First udp packet send!\n");
		fprintf(stdout,"Not First udp packet send!\n");
		return -1;
	};



	//get seqnum
	memcpy((char*)&seqnum,pkt,2);
	seqnum=bswap16(seqnum);

	//02 - tip dannih
	//if (memncmp(pkt+2,"\x02",1)==0){};

	//get our rnd seed?
	memcpy((char*)&rnd,pkt+3,4);
	rnd=bswap32(rnd);

	//get crc32
	memcpy((char *)&pkt_crc32,pkt+7,4);
	pkt_crc32=bswap32(pkt_crc32);

	
	//targetip=inet_addr(destip);
	targetip=destip;


	//publicip=inet_addr("0.0.0.0");
	publicip=inet_addr(MY_ADDR);

	//init data for rc4
	iv3[0] = ntohl(publicip);   // our public ip
	iv3[1] = ntohl(targetip);	// target_IP
	iv3[2] = seqnum;   // pkt seq num

	//init seed for rc4
	iv = crc32(iv3,3) ^ rnd;

	//iv = pkt_crc32 ^ rnd;

	tmp=crc32(iv3,3);
	if (DEBUG) fprintf(fp,"iv3[0]=0x%08X\n",iv3[0]);
	if (DEBUG) fprintf(fp,"iv3[1]=0x%08X\n",iv3[1]);
	if (DEBUG) fprintf(fp,"iv3[2]=0x%08X\n",iv3[2]);
	if (DEBUG) fprintf(fp,"crc32=0x%08X\n",tmp);
	if (DEBUG) fprintf(fp,"rnd=0x%08X\n",rnd);
	if (DEBUG) fprintf(fp,"pkt_crc32=0x%08X\n",pkt_crc32);
	if (DEBUG) fprintf(fp,"iv=0x%08X\n",iv);




	len=pkt_len-11;

	Skype_RC4_Expand_IV (rc4, iv, 1);
	RC4_crypt (pkt+11, len, rc4, 0);
	
	show_memory(fp,pkt+11,len,"rc4 decoded:");

	

	//pkt_crc32=Calculate_CRC32( (char *)pkt+11,len);

	//process_pkt(fp, pkt+11, pkt_len,1);
	main_unpack(fp, pkt+11, len);
	
	//rc4 data
	//memcpy(pkt+11,(char *)&send_probe_pkt,len);
	//len=18;



	return 0;
};




//
// process UDP other pkt
//
int process_udp_other_send(FILE *fp, char *pkt, int pkt_len, RC4_context *rc4) {
	int len;
	u32 remote_udp_rnd;
	u32	iv;
//	u32 pkt_crc32;
//	u32 targetip;
	u16 seqnum;


	if (DEBUG) fprintf(fp,"udp other send\n");

	show_memory(fp,pkt,pkt_len,"result:");

	if (pkt_len < 0x0B) {
		fprintf(fp,"Not other udp packet send!\n");
		fprintf(stdout,"Not other udp packet send!\n");
		return -1;
	};

	
	//get seqnum
	memcpy((char*)&seqnum,pkt,2);
	seqnum=bswap16(seqnum);

	//memncpy(pkt+2,"\x02",1);
	//len=3

	//get remote rnd seed
	memcpy((char*)&remote_udp_rnd,pkt+3,4);
	remote_udp_rnd=bswap32(remote_udp_rnd);

	//get targetip
	//memcpy((char *)&targetip,pkt+7,4);
	//targetip=bswap32(targetip);

	//get pkt_crc32
	//memcpy((char *)&pkt_crc32,pkt+12,4);
	//pkt_crc32=bswap32(pkt_crc32);


	iv = seqnum ^ remote_udp_rnd;

	if (DEBUG) fprintf(fp,"remote_udp_rnd=0x%08X\n",remote_udp_rnd);
	if (DEBUG) fprintf(fp,"seqnum=0x%08X\n",seqnum);
	if (DEBUG) fprintf(fp,"iv=0x%08X\n",iv);


	len=pkt_len-11;

	Skype_RC4_Expand_IV (rc4, iv, 1);
	RC4_crypt (pkt, len, rc4, 0);
	
	show_memory(fp,pkt+11,len,"rc4 decoded:");

	
	//pkt_crc32=Calculate_CRC32( (char *)pkt+11,len);

	//process_pkt(fp, pkt+11, pkt_len,1);
	main_unpack(fp, pkt+11, len);
	
	//rc4 data
	//memcpy(pkt+16,(char *)&send_probe_pkt,len);
	//len=18;



	return 0;
};



//
// process UDP first pkt recv
//
int process_udp_first_recv(FILE *fp, char *pkt, int pkt_len, RC4_context *rc4, u32 destip) {
	int len;
	u32 rnd;
	u32	iv, iv3[3];
	u32 pkt_crc32;
	u32 targetip;
	u32 publicip;
	u16 seqnum;
	u32 tmp;


	show_memory(fp,pkt,pkt_len,"result:");

	if (pkt_len < 0x0B) {
		fprintf(fp,"Not First udp packet recv!\n");
		fprintf(stdout,"Not First udp packet recv!\n");
		return -1;
	};

	
	//get seqnum
	memcpy((char*)&seqnum,pkt,2);
	seqnum=bswap16(seqnum);

	//02 - tip dannih
	//if (memncmp(pkt+2,"\x02",1)==0){};

	//get our rnd seed?
	memcpy((char*)&rnd,pkt+3,4);
	rnd=bswap32(rnd);

	//get crc32
	memcpy((char *)&pkt_crc32,pkt+7,4);
	pkt_crc32=bswap32(pkt_crc32);

	
	//targetip=inet_addr(destip);
	targetip=destip;


	//publicip=inet_addr("0.0.0.0");
	publicip=inet_addr(MY_ADDR);

	//init data for rc4
	iv3[1] = ntohl(publicip);   // our public ip
	iv3[0] = ntohl(targetip);	// target_IP
	iv3[2] = seqnum;   // pkt seq num

	//init seed for rc4
	iv = crc32(iv3,3) ^ rnd;

	//iv = pkt_crc32 ^ rnd;

	tmp=crc32(iv3,3);

	if (DEBUG) fprintf(fp,"iv3[0]=0x%08X\n",iv3[0]);
	if (DEBUG) fprintf(fp,"iv3[1]=0x%08X\n",iv3[1]);
	if (DEBUG) fprintf(fp,"iv3[2]=0x%08X\n",iv3[2]);
	if (DEBUG) fprintf(fp,"crc32=0x%08X\n",tmp);
	if (DEBUG) fprintf(fp,"rnd=0x%08X\n",rnd);
	if (DEBUG) fprintf(fp,"pkt_crc32=0x%08X\n",pkt_crc32);
	if (DEBUG) fprintf(fp,"iv=0x%08X\n",iv);




	len=pkt_len-11;

	Skype_RC4_Expand_IV (rc4, iv, 1);
	RC4_crypt (pkt+11, len, rc4, 0);
	
	show_memory(fp,pkt+11,len,"rc4 decoded:");

	

	//pkt_crc32=Calculate_CRC32( (char *)pkt+11,len);

	//process_pkt(fp, pkt+11, pkt_len,1);
	main_unpack(fp, pkt+11, len);
	
	//rc4 data
	//memcpy(pkt+11,(char *)&send_probe_pkt,len);
	//len=18;



	return 0;
};




//
// process UDP other pkt recv
//
int process_udp_other_recv(FILE *fp, char *pkt, int pkt_len, RC4_context *rc4) {
	int len;
	u32 remote_udp_rnd;
	u32	iv;
	u32 pkt_crc32;
	u32 targetip;
	u16 seqnum;


	show_memory(fp,pkt,pkt_len,"result:");

	if (pkt_len < 0x0B) {
		fprintf(fp,"Not other udp packet send!\n");
		fprintf(stdout,"Not other udp packet send!\n");
		return -1;
	};

	
	//get seqnum
	memcpy((char*)&seqnum,pkt,2);
	seqnum=bswap16(seqnum);

	//memncpy(pkt+2,"\x03\x01",2);
	//len=4;

	//get remote rnd seed
	memcpy((char*)&remote_udp_rnd,pkt+4,4);
	remote_udp_rnd=bswap32(remote_udp_rnd);

	//get targetip
	memcpy((char *)&targetip,pkt+8,4);
	targetip=bswap32(targetip);

	//get pkt_crc32
	memcpy((char *)&pkt_crc32,pkt+12,4);
	pkt_crc32=bswap32(pkt_crc32);


	iv = seqnum ^ remote_udp_rnd;

	if (DEBUG) fprintf(fp,"remote_udp_rnd=0x%08X\n",remote_udp_rnd);
	if (DEBUG) fprintf(fp,"seqnum=0x%08X\n",seqnum);
	if (DEBUG) fprintf(fp,"iv=0x%08X\n",iv);


	len=pkt_len-16;

	Skype_RC4_Expand_IV (rc4, iv, 1);
	RC4_crypt (pkt+16, len, rc4, 0);
	
	show_memory(fp,pkt+16,len,"rc4 decoded:");

	
	//pkt_crc32=Calculate_CRC32( (char *)pkt+16,len);

	//process_pkt(fp, pkt+16, pkt_len,1);
	main_unpack(fp, pkt+16, len);
	
	//rc4 data
	//memcpy(pkt+16,(char *)&send_probe_pkt,len);
	//len=18;



	return 0;
};


//
// process UDP nack pkt recv
//
int process_udp_nack_recv(FILE *fp, char *pkt, int pkt_len, u32 *remote_udp_rnd, u32 *public_ip) {

	show_memory(fp,pkt,pkt_len,"result:");

	
	if (pkt_len != 0x0B) {
		fprintf(fp,"Not Nack packet recv!\n");
		return -1;
	};

	fprintf(fp,"UDP Nack packet recv!\n");

	memcpy(remote_udp_rnd,pkt+7,4);
	*remote_udp_rnd=bswap32(*remote_udp_rnd);

	memcpy(public_ip,pkt+3,4);


	fprintf(fp,"public_ip=0x%08X\n",public_ip);
	fprintf(fp,"remote_udp_rnd=0x%08X\n",*remote_udp_rnd);


	return 0;
};
