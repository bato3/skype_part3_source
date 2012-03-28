/*  
*
* Utils
*
* little help tools
*
*
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


// for 41 
#include "decode41.h"




//////////////////////
// Util             //
//////////////////////
int show_memory(char *mem, int len, char *text){
	int zz;
	int i;

	printf("%s\n",text);
	printf("Len: 0x%08X\n",len);

	zz=0;
	for(i=0;i<len;i++){
		printf("%02X ",mem[i] & 0xff);
		zz++;if (zz == 16) { zz=0; printf("\n ");};
	};
	printf("\n");

	return 0;
};



/*
*
*
* Get Packet Size
* 
* reading first bytes(1-3), while (byte <= 0x80)
* and return size of rest message or block
*
*
*/
//in ida called
//unpack_7_bit_encoded_to_dword
int get_packet_size(char *data,int len){
	unsigned int ebx, edi, esi, eax, ecx, ebp, edx;
	char *buf_eax;


	//printf("ENTER unpack_7_bit_encoded_to_dword \n");
	
	ebx=len;

	esi=0;
	edi=0;

	eax=ebx;

	// if len == 0 
	if (eax==0){
			printf("konchilsya buffer,smth like terra nova here, jmp hz kuda\n");
			exit(-1);
	};


	// len - 1 
	ecx=eax-1;
	ebx=ecx;
    
	//ptr on data buffer
	ebp=(int )data;

	do{
		eax=ebp;

		ecx=esi;

		esi=esi+7;

		buf_eax=(char *)eax;
		edx=buf_eax[0] & 0xff;//ptr

		//printf("readed byte edx=%X\n",edx);

		eax++;

		ebp=eax;

		eax=edx;

		eax=eax & 0x7f;
		eax=eax << ecx;

		ecx=edi;

		ecx=ecx | eax;

		edi=ecx;

	    //printf("accamulated int ecx=%X\n",ecx);

	}while(edx >= 0x80);  
	//loop, while byte readed from buf >=0x80


	// size specific
	// diveded by 2
	edi=edi>>1;

	printf("PKT SIZE=0x%08X\n",edi);


	//printf("LEAVE unpack_7_bit_encoded_to_dword \n");

	return edi;

};


//
// Set packet size
//
int set_packet_size(char *a1, int c){
  char *block;
  unsigned int b;


  b = c;
  for ( block = a1; b > 0x7F; ++*block )
  {
    *block = (char)b | 0x80;
	printf("1 cikl,  block[0]=0x%08X block[1]=0x%08X block[2]=0x%08X\n",block[0],block[1],block[2]);
    b >>= 7;
  }
  
  printf("2 aft, block[0]=0x%08X block[1]=0x%08X block[2]=0x%08X\n",block[0],block[1],block[2]);
  *block++;
  printf("3 inc, block[0]=0x%08X block[1]=0x%08X block[2]=0x%08X\n",block[0],block[1],block[2]);

  *block=b;

  printf("4 set, block[0]=0x%08X block[1]=0x%08X block[2]=0x%08X\n",block[0],block[1],block[2]);
  //*block--;
  *block--;

  printf("5 back,block[0]=0x%08X block[1]=0x%08X block[2]=0x%08X\n",block[0],block[1],block[2]);


  return 0;
}


//
// Encode bytes to 7 bit
//
int encode_to_7bit(char *buf, uint word, int limit){
	int ldebug=0;
	uint to[10];
	int i;
	int n;
	uint a;



	n=0;
	for(i=0;i<10;i++){
		to[i]=0;
	};


    for (a = word; a > 0x7F; a >>= 7, n++){ 
		
		if (n > 10) {
			printf("7bit encoding fail\n");
			exit(1);
		};

        to[n] = (u8) a | 0x80; 
		to[n+1] = (u8) a; 

		if (ldebug){
			printf("n=0x%08X i=0x%08X\n",n,i);
			printf("\ta: 0x%08X\n",a);
			printf("\tn: 0x%08X\n",to[n]);
			printf("\tn+1: 0x%08X\n",to[n+1]);
		};
	};
	to[n]=a;

	if (ldebug){
		printf("after cikl, n=0x%08X\n",n);
		printf("after cikl, a=0x%08X\n",a);
		printf("\n");

		printf("0: 0x%08X\n",to[0]);
		printf("1: 0x%08X\n",to[1]);
		printf("2: 0x%08X\n",to[2]);
		printf("3: 0x%08X\n",to[3]);
		printf("4: 0x%08X\n",to[4]);
		printf("5: 0x%08X\n",to[5]);
	};


	if (n > limit) {
		printf("not enought buffer\n");
		exit(1);
	};

	for(i=0;i<=n;i++){
		buf[i]=to[i] & 0xff;
	};



    return n+1;
}


//
// Decode 41 sequence
//
int decode41(char *data, int len, char *text){
		struct self_s self;
		int ret;
		u8 *pkt_my;
		u32 pkt_my_len;


		pkt_my=data;
		pkt_my_len=len;

		ret=unpack41_structure(pkt_my,pkt_my_len,(char *)&self);
		if (ret==-1) {
			printf("possible not all bytes decoded! (not found last 2 bytes of crc16)\n");
		};

		if (ret==-2){
			return 0;
		};

		print_structure(text,(char *)&self,1);		

		free_structure((char *)&self);


	return 0;
};
