//
//udp communication
//

#include<stdio.h>

#include <winsock.h>  
#include "rc4/Expand_IV.h"


extern unsigned int Calculate_CRC32(char *crc32, int bytes);



/////////////////////
// udp first packet//
/////////////////////
int make_udp_probe_pkt1(char *ourip,char *destip,unsigned short seqnum,u32 rnd, char *pkt, int *pkt_len) {
	RC4_context rc4;
	int len;
	u32 tmp;

	u32	iv, iv3[3];
	u32 targetip;
	u32 publicip;
	u32 pkt_crc32;

	u8 send_probe_pkt[]="\x04\xda\x01\xFF\xFF\x42\x15";
	len=sizeof(send_probe_pkt)-1;


	seqnum=bswap16(seqnum);
	memcpy(send_probe_pkt+3,(char *)&seqnum,2);
	seqnum=bswap16(seqnum);

	targetip=inet_addr(destip);
	publicip=inet_addr(ourip);

	//init data for rc4
	iv3[0] = ntohl(publicip);   // our public ip
	iv3[1] = ntohl(targetip);	// target_IP
	iv3[2] = seqnum+1;   // pkt seq num

	//init seed for rc4
	iv = crc32(iv3,3) ^ rnd;
	
	//crc32
	pkt_crc32=Calculate_CRC32( (char *)send_probe_pkt,len);

	tmp=crc32(iv3,3);
	printf("iv3[0]=0x%08X\n",iv3[0]);
	printf("iv3[1]=0x%08X\n",iv3[1]);
	printf("iv3[2]=0x%08X\n",iv3[2]);
	printf("crc32=0x%08X\n",tmp);
	printf("rnd=0x%08X\n",rnd);
	printf("pkt_crc32=0x%08X\n",pkt_crc32);
	printf("iv=0x%08X\n",iv);


	//init rc4 structure by iv
	Skype_RC4_Expand_IV (&rc4, iv, 1);
	

	// encrypt rc4 data
	RC4_crypt (send_probe_pkt, len, &rc4, 0);

	//make send pkt
	//pktnum+1,
	seqnum++;
	seqnum=bswap16(seqnum);
	memcpy(pkt,(char*)&seqnum,2);
	seqnum=bswap16(seqnum);
	//02 - tip dannih
	memcpy(pkt+2,"\x02",1);
	//init data//our rnd seed?
	tmp=bswap32(rnd);
	memcpy(pkt+3,(char*)&tmp,4);
	//crc32
	pkt_crc32=bswap32(pkt_crc32);
	memcpy(pkt+7,(char *)&pkt_crc32,4);
	pkt_crc32=bswap32(pkt_crc32);
	//rc4 data
	memcpy(pkt+11,(char *)&send_probe_pkt,len);
	len=18;

	*pkt_len=len;

	return 0;
};


int process_udp_probe_pkt1(char *pkt, int pkt_len, u32 *remote_udp_rnd, u32 *public_ip) {

	if (pkt_len != 0x0B) {
		//printf("Not Nack packet recv!\n");
		return 0;
	};

	memcpy(remote_udp_rnd,pkt+7,4);
	*remote_udp_rnd=bswap32(*remote_udp_rnd);

	memcpy(public_ip,pkt+3,4);

	return 1;
};




///////////////////////
// udp second packet //
///////////////////////
int make_udp_probe_pkt2(char *ourip,char *ip,unsigned short seqnum,u32 rnd,u32 remote_udp_rnd,char *pkt,int *pkt_len) {
	RC4_context rc4;
	u32	iv;
	u32 targetip;
	u32 publicip;
	u32 pkt_crc32;
	int len;

	u8 send_probe_pkt[]="\x04\xda\x01\xFF\xFF\x42\x15";
	len=sizeof(send_probe_pkt)-1;


	seqnum=bswap16(seqnum);
	memcpy(send_probe_pkt+3,(char *)&seqnum,2);
	seqnum=bswap16(seqnum);

	targetip=inet_addr(ip);
	publicip=inet_addr(ourip);

	
	seqnum++;
	seqnum=bswap16(seqnum);
	iv = bswap16(seqnum) ^ remote_udp_rnd;
	seqnum=bswap16(seqnum);
	seqnum--;

	printf("remote_udp_rnd=0x%08X\n",remote_udp_rnd);
	printf("seqnum=0x%08X\n",seqnum);
	printf("iv=0x%08X\n",iv);

	pkt_crc32=Calculate_CRC32( (char *)send_probe_pkt,len);

	Skype_RC4_Expand_IV (&rc4, iv, 1);
		
	RC4_crypt (send_probe_pkt, len, &rc4, 0);

	//make send pkt

	//pktnum+1,
	seqnum++;
	seqnum=bswap16(seqnum);
	memcpy(pkt,(char*)&seqnum,2);
	seqnum=bswap16(seqnum);
	len=2;

	//13 01 tip dannih? 13 resend 01
	memcpy(pkt+2,"\x03\x01",2);
	len=4;
	
	//remote newrnd
	remote_udp_rnd=bswap32(remote_udp_rnd);
	memcpy(pkt+4,(char*)&remote_udp_rnd,4);
	remote_udp_rnd=bswap32(remote_udp_rnd);
	len=8;

	//dst ip
	targetip=bswap32(targetip);
	memcpy(pkt+8,(char*)&targetip,4);
	targetip=bswap32(targetip);
	len=12;

	//crc32
	pkt_crc32=bswap32(pkt_crc32);
	memcpy(pkt+12,(char *)&pkt_crc32,4);
	pkt_crc32=bswap32(pkt_crc32);
	len=16;

	//rc4
	memcpy(pkt+16,(char *)&send_probe_pkt,len);
	len=23;

	*pkt_len=len;


	return 0;

};


int process_udp_probe_pkt2(char *pkt,int pkt_len,char *ourip,char *destip) {
	RC4_context rc4;
	u32 newrnd;
	u32 targetip;
	u32 publicip;
	u32	iv3[3];
	u32 iv;

	targetip=inet_addr(destip);
	publicip=inet_addr(ourip);


	if (pkt_len!=0x12) {
		//printf("probe accepted len mismatch\n");
		return 0;
	};

	pkt_len=pkt_len-0x0B;

	newrnd = bswap32(dword(pkt+3)); //last byte in Nack, first in reply

	iv3[2] = bswap16(word(pkt)); //pkt seq num
	iv3[1] = bswap32(publicip);	// target_IP
	iv3[0] = bswap32(targetip);	// source_IP

	iv = crc32(iv3,3) ^ newrnd;

	Skype_RC4_Expand_IV (&rc4, iv, 1);
	
	RC4_crypt (pkt+0x0B, pkt_len, &rc4, 0);

	if (strncmp(pkt+0x0B,"\x04\xE3\x01",3)!=0) {
		//printf("probe not accepted, its usual skype client\n");
		return 0;
	};



	return 1;
};


////////////////////////////////
// end udp section
////////////////////////////////
