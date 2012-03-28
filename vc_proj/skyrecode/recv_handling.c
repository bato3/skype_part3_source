//
// process received data
//


// for rc4
#include "rc4/Expand_IV.h"

// for aes
#include "crypto/rijndael.h"

// for global structure
#include "global_vars.h"

// for types
#include "short_types.h"

// for 41
#include "decode41.h"

// for mip miracl
#include "crypto/miracl.h"


extern int show_memory(char *mem, int len, char *text);

//unpack 41
extern int main_unpack41(u8 *indata, u32 inlen);
extern int main_unpack_getdata3 (u8 *indata, u32 inlen, u8 *nonce);

// sha1 and rsa crypto function
extern int _get_sha1_data(char *buf, int len, char *outbuf, int need_convert);
extern int _get_decode_data(_MIPD_ char *globalptr, char *buf, int len, char *outbuf);


extern uint DEBUG_LEVEL;


//
// answer on 57_41 pkt
//
int process_57_41(char *globalptr, char *resp, int resp_len){
	char nonce[0x80];

	struct global_s *global;
	global=(struct global_s *)globalptr;



	show_memory(resp, resp_len, "57 41 input");


	/*
	process_aes_crypt(globalptr, recvbuf+5, recvlen-5, 0, blkseq, 0);
	*/



	/////////////////////////////
	// 41 decode
	/////////////////////////////
	// for getting crypted nonce
	if (1){
		u8 *data;
		u32 datalen;
		
		data = resp;//+5;
		datalen=resp_len;//-5;

		main_unpack41(data, datalen);

		main_unpack_getdata3 (data,datalen,nonce);

		/*
		ret=unpack41_structure(data,datalen,(char *)&self);
		if (ret==-1) {
			if(DEBUG_LEVEL>=100) printf("decode41 fail\n");
			return -1;
		};
		if (ret==-2) {
			if(DEBUG_LEVEL>=100) printf("possible not all bytes decoded! (not found last 2 bytes of crc16)\n");
		};


		if(DEBUG_LEVEL>=100) print_structure("Handshake pkt 57",(char *)&self,1);
		
		mybuf=self.heap_alloc_struct_array[0];
		mysize=self.heap_alloc_struct_array_size[0];
		*/

		// copy encrypted nonce from 41 encoding blob
		//memcpy(nonce,mybuf,0x80);

		// display crypted nonce
		show_memory(nonce, 0x80, "RSA encrypted remote nonce");
		
		//free_structure((char *)&self);
	};



	/////////////////////////////
	// RSA decode
	/////////////////////////////
	// for decrypting remote nonce
	if (1) {
		char *buf;
		char *outbuf;

		buf=malloc(0x1000);
		outbuf=malloc(0x1000);

		memset(buf,0,0x200);
		memset(outbuf,0,0x200);

		// copy encrypted nonce
		memcpy(buf,nonce,0x80);
		
		// rsa decrypt nonce
		show_memory(buf, 0x80, "Before RSA decrypt nonce");
		_get_decode_data(_MIPP_ globalptr, buf, 0x80, outbuf);
		show_memory(outbuf, 0x80, "After RSA decrypt nonce");

		// copy decrypted nonce
		memcpy(nonce,outbuf,0x80);

	};




	/////////////////////////////
	// SHA1 digest
	/////////////////////////////
	// for getting aes key nonce2 (remote)
	if (1) {
		char *buf;
		char *outbuf;

		buf=malloc(0x1000);
		outbuf=malloc(0x1000);

		memset(buf,0,0x200);
		memset(outbuf,0,0x200);

		// first integer is 0x00000000 !!!
		memcpy(buf+4,nonce,0x80);
		
		// show data for hashing
		// integer(0x00) and 0x80 nonce
		show_memory(buf, 0x84, "NONCE input");

		// making sha1 hash on nonce
		//get_sha1_data(buf, 0x84, outbuf, 1);
		
		_get_sha1_data(buf, 0x84, outbuf, 0);


		// copy remote part of aes key
		memcpy(global->AES_KEY+0x10,outbuf,0x10);

		// show full aes session key
		show_memory(global->AES_KEY, 0x20, "AES KEY");


	};


	global->session_setup_completed=1;


	return 0;
};


//
// answer on 6D_41 pkt
//
int process_6D_41(char *globalptr, char *resp, int resp_len){
	char header41[5];

	struct global_s *global;
	global=(struct global_s *)globalptr;



	show_memory(resp, resp_len, "6D 41 input");


	if (1){

		//2bytes of size, encode rest of length
		//tmplen-2 , rest of len - 2 bytes of crc32 ^ sessid
		//decode41(recvbuf+i+4, tmplen-2,"PKT 6D reply1");

		//processing headers, need for cmd confirmation

		memcpy(header41,resp,5);

		//remember first byte sess id, for send in confirmation
		if (header41[2]==0x6d){
			if (header41[3]==0x41){
				memcpy(&global->confirm[global->confirm_count],header41,2);
				global->confirm_count++;
			};
		};
		if (header41[3]==0x6d){
			if (header41[4]==0x41){
				memcpy(&global->confirm[global->confirm_count],header41,3);
				global->confirm_count++;
			};
		};
		if (header41[2]==0x4D){
			if (header41[3]==0x41){
				memcpy(&global->confirm[global->confirm_count],header41,2);
				global->confirm_count++;
			};
		};
		if (header41[3]==0x4D){
			if (header41[4]==0x41){
				memcpy(&global->confirm[global->confirm_count],header41,3);
				global->confirm_count++;
			};
		};

		/*
		if (header41[2]==0x4C){
			if (header41[3]==0x41){
				memcpy(&confirm[confirm_count],header41,2);
				confirm_count++;
			};
		};
		if (header41[3]==0x4C){
			if (header41[4]==0x41){
				memcpy(&confirm[confirm_count],header41,3);
				confirm_count++;
			};
		};
		*/


	};


	return 0;
};
