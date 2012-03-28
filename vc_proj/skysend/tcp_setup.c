/*  
*
* Direct TCP connect to skype client
*
*/

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

// rc4 obfuscation
extern int Skype_RC4_Expand_IV (RC4_context * const rc4, const u32 iv, const u32 flags);
extern void RC4_crypt (u8 * buffer, u32 bytes, RC4_context * const rc4, const u32 test);

extern int Calculate_CRC32_For41(char *a2, int a3);
extern unsigned int Calculate_CRC32(char *crc32, int bytes);

// socket comm
extern int udp_talk(char *remoteip, unsigned short remoteport, char *buf, int len, char *result);
extern int tcp_talk(char *remoteip, unsigned short remoteport, char *buf, int len, char *result,int need_close);

// sha1 and rsa crypto function
extern int _get_sha1_data(char *buf, int len, char *outbuf, int need_convert);

extern int _get_decode_data(_MIPD_ char *globalptr, char *buf, int len, char *outbuf);
extern int _get_sign_data(_MIPD_ char *globalptr, char *buf, int len, char *outbuf);
extern int _get_unsign_cred(_MIPD_ char *globalptr, char *buf, int len, char *outbuf);
extern int _get_encode_data(_MIPD_ char *globalptr, char *buf, int len, char *outbuf);

// utils
extern int process_aes_crypt(char *globalptr, char *data, int datalen, int usekey, int blkseq, int need_xor);
extern int show_memory(char *mem, int len, char *text);
extern int get_packet_size(char *data,int len);
extern int decode41(char *data, int len, char *text);
extern int process_aes(char *globalptr, char *buf, int buf_len, int usekey, int blkseq, int need_xor);
extern int first_bytes_correction(char *globalptr, char *header, int header_len, char *buf, int buf_len);

// blobs encode
int encode41_setup1pkt(char *globalptr, char *buf, int buf_limit_len);
int encode41_setup2pkt(char *globalptr, char *buf, int buf_limit_len);


extern uint DEBUG_LEVEL;

//////////////////////
// tcp first packet //
//////////////////////
int make_tcp_client_sess1_pkt1(_MIPD_ char *globalptr, char *pkt, int *pkt_len)
{
	u32 local_rnd;
	u32	iv;
	int len;
	u8 send_pkt[]="\x00\x01\x00\x00\x00\x01\x00\x00\x00\x03";
	int send_pkt_len=sizeof(send_pkt)-1;

	struct global_s *global;
	global=(struct global_s *)globalptr;



	memcpy(global->CREDENTIALS188,"\x00\x00\x01\x04",4);
	memcpy(global->CREDENTIALS188+0x04,global->CREDENTIALS,global->CREDENTIALS_LEN);
	global->CREDENTIALS188_LEN=0x188;

	/////////////////////
	// SHA1 hash
	/////////////////////
	//make hash of CREDENTIALS 0x104 bytes.
	//save to CREDENTIALS_HASH
	if (1) {
		char *buf;
		char *outbuf;

		buf=malloc(0x1000);
		outbuf=malloc(0x1000);

		memset(buf,0,0x200);
		memset(outbuf,0,0x200);

		//prepare data for hashing
		memcpy(buf,global->CREDENTIALS,global->CREDENTIALS_LEN);

		//print it
		show_memory(buf, global->CREDENTIALS_LEN, "SHA1 input");

		//make sha1 hash
		_get_sha1_data(buf, global->CREDENTIALS_LEN, outbuf, 1);

		//print it
		show_memory(outbuf, 0x14, "SHA1 output(hash)");

		//copy hash
		memcpy(global->CREDENTIALS_HASH,outbuf,0x14);

	};


	// modify hash
	memcpy(global->AFTER_CRED+0x3D,global->CREDENTIALS_HASH, 0x14);
	//modify init_unk
	memcpy(global->AFTER_CRED+0x56,global->INIT_UNK, 0x15);

	
	/////////////////////
	// SHA1 hash
	/////////////////////
	//make hash of AFTER_CRED 0x80 bytes.
	//save to CREDENTIALS_HASH
	if (1) {
		char *buf;
		char *outbuf;

		buf=malloc(0x1000);
		outbuf=malloc(0x1000);

		memset(buf,0,0x200);
		memset(outbuf,0,0x200);

		//prepare data for hashing
		memcpy(buf,global->AFTER_CRED+0x3D,0x80-0x14-1-0x3D);

		//print it
		show_memory(buf, 0x80-0x14-1-0x3D, "SHA1 input");

		//make sha1 hash
		_get_sha1_data(buf, 0x80-0x14-1-0x3D, outbuf, 1);

		//print it
		show_memory(outbuf, 0x14, "SHA1 output(hash)");

		//copy hash
		memcpy(global->AFTER_CRED+0x80-0x14-1,outbuf,0x14);

	};




	///////////////////////
	//RSA sign
	///////////////////////
	//for sign 0x80 byte after credentials
	if (1) {
		char *buf;
		char *outbuf;


		buf=malloc(0x1000);
		outbuf=malloc(0x1000);

		memset(buf,0,0x200);
		memset(outbuf,0,0x200);


		//copy
		memcpy(buf,global->AFTER_CRED,0x80);
		
		//before RSA sign-ing
		show_memory(buf, 0x80, "RSA SIGN input");

		//make rsa sign
		_get_sign_data(_MIPP_ globalptr, buf, 0x80, outbuf);

		//copy rsa sign to credentials188 buffer
		memcpy(global->CREDENTIALS188+0x100+0x08,outbuf,0x80);

		//print credentials 0x188
		show_memory(global->CREDENTIALS188, global->CREDENTIALS188_LEN, "RSA SIGN cred188");

	};

	


	global->UIC_CRC=Calculate_CRC32( (char *)global->CREDENTIALS,global->CREDENTIALS_LEN);
	if(DEBUG_LEVEL>=100) printf("UIC_CRC = %08X\n",global->UIC_CRC);




	if(DEBUG_LEVEL>=100) printf("Sending first TCP packet\n");


	if(DEBUG_LEVEL>=100) printf("send_pkt_len=0x%08X\n",send_pkt_len);


	// Make pkt for send
	len=0;

	// 0-3: 4 byte of our local IV, e.g. rnd data
	local_rnd=global->rnd;
	local_rnd=bswap32(local_rnd);
	memcpy(pkt,(char*)&local_rnd,4);
	local_rnd=bswap32(local_rnd);
	len=len+4;

	// 4-14: 10 bytes of send_pkt data, tcp setup indicator
	memcpy(pkt+4,(char *)&send_pkt,send_pkt_len);
	len=len+send_pkt_len;
	
	// Encrypt data

	// Initialize RC4 obfuscation
	iv = global->rnd;
	if(DEBUG_LEVEL>=100) printf("Local RC4 IV=0x%08X\n",iv);

	// Expand IV(our rnd)
	Skype_RC4_Expand_IV (&global->rc4_send, iv, 1);

	// Encrypt RC4
	show_memory(pkt+4, send_pkt_len, "Before RC4 encrypt");
	RC4_crypt (pkt+4, send_pkt_len, &global->rc4_send, 0);
	show_memory(pkt+4, send_pkt_len, "After RC4 encrypt");



	// Display pkt before sending
	show_memory(pkt, len, "Send pkt");


	*pkt_len=len;


	return 0;

};


int process_tcp_client_sess1_pkt1(_MIPD_ char *globalptr, char *resp, int resp_len){
	u8 recvbuf[0x1000];
	u32 recvlen;
	u32 remote_rnd;
	u32	iv;
	u8 send_pkt[]="\x00\x01\x00\x00\x00\x01\x00\x00\x00\x03";

	struct global_s *global;
	global=(struct global_s *)globalptr;

	if (resp_len>=1023) {
		if(DEBUG_LEVEL>=100) printf("Not all data receive, len: 0x%08X\n",resp_len);
		if(DEBUG_LEVEL>=100) printf("Too big pkt recv..\n");
		return -1;
	};

	// Display received pkt
	show_memory(resp, resp_len, "Result");



	// Sanity check
	if (resp_len < 14){
		if(DEBUG_LEVEL>=100) printf("Wrong packet length: 0x%08X, must >= 14\n");
		return -1;
	};


	// Parse received packet

	// 0-3: Remote IV
	memcpy(&remote_rnd,resp,4);

	// 4-14:Copy first 10(0x0a) bytes  of RC4 encoded data to recvbuf
	recvlen=10;
	memcpy(recvbuf,resp+4,recvlen);


	// Decrypt RC4 data
	// first 0x0a

	// Initialize RC4 obfuscation
	// based on remote iv
	iv = bswap32(remote_rnd);
	if(DEBUG_LEVEL>=100) printf("Remote RC4 iv=0x%08X\n",iv);

	// Expand RC4 remote IV
	Skype_RC4_Expand_IV (&global->rc4_recv, iv, 1);
	
	// Decrypt RC4
	// first 0x0a, not saving state !! so rc4_crypt 4-param test is - 1 !!!
	show_memory(recvbuf, recvlen, "Before RC4 decrypt");	
	RC4_crypt (recvbuf, recvlen, &global->rc4_recv, 1);
	show_memory(recvbuf, recvlen, "After RC4 decrypt");	

	// Check decoded data

	// Check, if answer was correct
	// and rc4 initilization completed
	if (memcmp(recvbuf+2,send_pkt+2,8)!=0){
		if(DEBUG_LEVEL>=100) printf("RC4 tcp flow handshake failed\n");
		return -1;
	};


	//14-...

	// Sanity check
	if (resp_len > 14){
		//printf("Wrong packet length: 0x%08X, must >= 14\n");


		recvlen=resp_len-10-4;
		memcpy(recvbuf,resp+14,recvlen);


		// Decrypt RC4
		// now we MUST save state !! so rc4_crypt 4-param test is - 0(not test) !!!
		show_memory(recvbuf, recvlen, "Before RC4 decrypt");	
		RC4_crypt (recvbuf, recvlen, &global->rc4_recv, 0);
		show_memory(recvbuf, recvlen, "After RC4 decrypt");	


		// Check decoded data

		// Check, if answer was correct
		// and rc4 initilization completed
		if (memcmp(recvbuf+1,"\x03",1)!=0){
			if(DEBUG_LEVEL>=100) printf("next msg len decode fail, RC4 tcp flow handshake failed (2)\n");
			return -1;
		};

	};


	return 0;
};



///////////////////////////////
//tcp second packet
///////////////////////////////
int make_tcp_client_sess1_pkt2(_MIPD_ char *globalptr, char *pkt, int *pkt_len)
{
	int len;
	int blkseq;
	u32 iv;

	u8 buf1[0x1000];
	int buf1_len;
	u8 buf1header[0x10];
	int buf1header_len;

	struct global_s *global;
	global=(struct global_s *)globalptr;


	if(DEBUG_LEVEL>=100) printf("Sending second TCP packet\n");


	///////////////////////////////
	// first 41 
	///////////////////////////////

	memset(buf1,0,sizeof(buf1));
  	buf1_len=encode41_setup1pkt(globalptr, buf1, sizeof(buf1));
	show_memory(buf1, buf1_len, "setup1pkt");


	// aes encrypt block 1
	blkseq=0x00;
	buf1_len=process_aes(globalptr, buf1, buf1_len, 0, blkseq, 0);


	/////////////////////////////////////
	// first bytes correction
	/////////////////////////////////////
	// calculate for 4 and 5 byte fixing
	buf1header_len=first_bytes_correction(globalptr, buf1header, sizeof(buf1header)-1, buf1, buf1_len);
	show_memory(buf1header, buf1header_len, "setup1header");


	/////////////////////////////////
	// assembling pkt for sending
	/////////////////////////////////
	len=0;

	// header
	memcpy(pkt+len,buf1header,buf1header_len);
	len=len+buf1header_len;
	// aes
	memcpy(pkt+len,buf1,buf1_len);
	len=len+buf1_len;


	// Encrypt data

	// Initialize RC4 obfuscation
	iv = global->rnd;
	if(DEBUG_LEVEL>=100) printf("Local RC4 IV=0x%08X\n",iv);

	// Expand IV(our rnd)
	Skype_RC4_Expand_IV (&global->rc4_send, iv, 1);

	// Encrypt RC4
	show_memory(pkt, len, "Before RC4 encrypt");
	RC4_crypt (pkt, len, &global->rc4_send, 0);
	show_memory(pkt, len, "After RC4 encrypt");

	// display pkt
	show_memory(pkt, len, "Send pkt");

	*pkt_len=len;


	return 0;
};

	
int process_tcp_client_sess1_pkt2(_MIPD_ char *globalptr, char *resp, int resp_len){
	u8 recvbuf[0x1000];
	int tmplen;
	int recvlen;
	int blkseq;
	u8 sha1[0x14];
	u8 rnd64bit[0x8];


	struct global_s *global;
	global=(struct global_s *)globalptr;

	
	// recv pkt
	show_memory(resp, resp_len, "Result");
	
	// copy pkt
	recvlen=resp_len;
	memcpy(recvbuf,resp,recvlen);



	show_memory(recvbuf, recvlen, "Before RC4 decrypt");
	RC4_crypt (recvbuf, recvlen, &global->rc4_recv, 0);
	show_memory(recvbuf, recvlen, "After RC4 decrypt");


	/////////////////////////////////
	// Process received pkt
	/////////////////////////////////

	// check pkt size
	tmplen=get_packet_size(recvbuf, 4);
	tmplen=tmplen-1;
	if (tmplen > 0x1000){
		if(DEBUG_LEVEL>=100) printf("pkt block size too big, len: 0x%08X\n",tmplen);
		return -1;
	};
	if (tmplen <= 0){
		if(DEBUG_LEVEL>=100) printf("pkt block size too small, len: 0x%08X\n",tmplen);
		return -1;
	};

	// show header
	show_memory(recvbuf, 5, "Header");

	// doing aes decrypt
	blkseq=0x00;
	process_aes_crypt(globalptr, recvbuf+5, recvlen-5, 0, blkseq, 0);



	/////////////////////////////
	// 41 decode
	/////////////////////////////
	// for getting remote session id
	// and rnd64bit challenge
	// and pubkey from credentials
	if (1){
		struct self_s self;
		int ret;
		u8 *data;
		u32 datalen;
		char *block_alloc2;
		u8 tmpbuf[0x100];
		int kk;

		data = recvbuf+5;
		datalen=recvlen-5;

		ret=unpack41_structure(data,datalen,(char *)&self);
		if (ret==-1) {
			if(DEBUG_LEVEL>=100) printf("decode41 fail\n");
			return -1;
		};
		if (ret==-2) {
			if(DEBUG_LEVEL>=100) printf("possible not all bytes decoded! (not found last 2 bytes of crc16)\n");
		};

		if (DEBUG_LEVEL>=100) print_structure("Handshake pkt 44",(char *)&self,1);

		//get REMOTE_SESSION_ID
		memcpy(&global->REMOTE_SESSION_ID, self.heap_alloc_buf+8, 4);

		//print it
		if(DEBUG_LEVEL>=100) printf("remote session id: 0x%08X\n",global->REMOTE_SESSION_ID);

		//get rnd64bit challenge
		memcpy(rnd64bit, self.heap_alloc_buf+0x34, 4);
		memcpy(rnd64bit+4, self.heap_alloc_buf+0x38, 4);

		//print it
		show_memory(rnd64bit, 8, "rnd64bit");

		// get credentials
		if (self.heap_alloc_struct_array_size[1]<0x188){
				if(DEBUG_LEVEL>=100) printf("credentials size error\n");
				return -1;
		};
        block_alloc2=self.heap_alloc_struct_array[1];
		memcpy(global->REMOTE_CREDENTIALS, block_alloc2+0x08, 0x100);
		show_memory(global->REMOTE_CREDENTIALS, 0x100, "remote credentials");

		//decrypt/unsign credentials by skype_pub
		_get_unsign_cred(_MIPP_ globalptr, global->REMOTE_CREDENTIALS, 0x100, tmpbuf);
        show_memory(tmpbuf, 0x100, "decrypt credentials");

		for(kk=0;kk<(0x100-1);kk++){
			if ( (tmpbuf[kk]==0x80) && (tmpbuf[kk+1]==0x01) ) {
				if(DEBUG_LEVEL>=100) printf("1 kk=0x%08X\n",kk);
				break;
			};
		};
		
		kk=kk+2;
		if(DEBUG_LEVEL>=100) printf("2 kk=0x%08X\n",kk);

		if ((kk+0x80) < 0x100) {
			memcpy(global->REMOTE_PUBKEY,tmpbuf+kk,0x80);
		}else{
			if(DEBUG_LEVEL>=100) printf("failed to find pubkey in credentials, kk=0x%08X\n",kk);
			return -1;
		};

        show_memory(global->REMOTE_PUBKEY, 0x80, "remote peer pubkey");

		free_structure((char *)&self);

	};



	/////////////////////
	// SHA1 digest
	/////////////////////
	//make hash of remote rnd64bit challenge(8byte) + 0x01(9byte)
	if (1) {
		char *buf;
		char *outbuf;

		buf=malloc(0x1000);
		outbuf=malloc(0x1000);

		memset(buf,0,0x200);
		memset(outbuf,0,0x200);

		//prepare data for hashing
		memset(buf,0x1,0x9);
		memcpy(buf,rnd64bit,8);

		//print it
		show_memory(buf, 9, "SHA1 input");

		//make sha1 hash
		//get_sha1_data(buf, 9, outbuf);
		_get_sha1_data(buf, 9, outbuf, 1);


		//print it
		show_memory(outbuf, 0x14, "SHA1 output(hash)");

		//copy hash
		memcpy(sha1,outbuf,0x14);

	};
	


	///////////////////////
	//RSA sign
	///////////////////////
	//for sign rnd64bit challenge and sha1 hash of it
	if (1) {
		char *buf;
		char *outbuf;

// response on challenge
u8 challenge[]=
"\x4B\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB"
"\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB"
"\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB"
"\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB"
"\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB"
"\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB"
"\xBB\xBA\x66\xCE\x3F\xDB\xAA\x55\xB4\xF7\x01\xE9\x26\x8E\x38\x4C"
"\x3C\x06\x30\xF8\xD9\xA4\xBF\x47\x63\xDC\xB8\x4C\x33\xCF\x2C\xBC"
;
//padding
//64bit challenge
//sha160bit hash


		buf=malloc(0x1000);
		outbuf=malloc(0x1000);

		memset(buf,0,0x200);
		memset(outbuf,0,0x200);


		//copy challenge template
		memcpy(buf,challenge,0x80);
		
		//modify sha1 hash in challenge response
		memcpy(buf+0x80-0x14-1,sha1,0x14);

		//modify rnd64bit challenge in challenge response
		memcpy(buf+0x62,rnd64bit,8);

		//print challenge response data
		//before RSA sign-ing
		show_memory(buf, 0x80, "RSA SIGN input");

		//make rsa sign
		_get_sign_data(_MIPP_ globalptr, buf, 0x80, outbuf);

		//copy rsa sign to challenge_response buffer
		//for send this response in next pkt
		memcpy(global->CHALLENGE_RESPONSE,outbuf,0x80);

		//print rsa signed challenge response data
		show_memory(global->CHALLENGE_RESPONSE, 0x80, "RSA SIGN output");

	};
	



	return 0;
};





///////////////////////////////
//tcp third(3) packet
////////////////////////////////
int make_tcp_client_sess1_pkt3(_MIPD_ char *globalptr, char *pkt, int *pkt_len){
	int len;
	int blkseq;

	u8 buf1[0x1000];
	int buf1_len;
	u8 buf1header[0x10];
	int buf1header_len;

	struct global_s *global;
	global=(struct global_s *)globalptr;


	if(DEBUG_LEVEL>=100) printf("Sending third(3) TCP packet\n");


	/////////////////////////////
	// SHA1 digest
	/////////////////////////////
	// for getting aes key nonce1 (local)
	if (1) {
		char *buf;
		char *outbuf;

		//make local nonce
		char tmp[]=
"\xF5\x4A\x48\xA6\x37\x73\xE3\x42\xB6\x75\x1A\x61\x4D\x08\xDB\xB6"
"\xF5\x4A\x48\xA6\x37\x73\xE3\x42\xB6\x75\x1A\x61\x4D\x08\xDB\xB6"
"\xF5\x4A\x48\xA6\x37\x73\xE3\x42\xB6\x75\x1A\x61\x4D\x08\xDB\xB6"
"\xF5\x4A\x48\xA6\x37\x73\xE3\x42\xB6\x75\x1A\x61\x4D\x08\xDB\xB6"
"\xF5\x4A\x48\xA6\x37\x73\xE3\x42\xB6\x75\x1A\x61\x4D\x08\xDB\xB6"
"\xF5\x4A\x48\xA6\x37\x73\xE3\x42\xB6\x75\x1A\x61\x4D\x08\xDB\xB6"
"\xF5\x4A\x48\xA6\x37\x73\xE3\x42\xB6\x75\x1A\x61\x4D\x08\xDB\xB6"
"\xF5\x4A\x48\xA6\x37\x73\xE3\x42\xB6\x75\x1A\x61\x4D\x08\xDB\xB6"
;
		memcpy(global->LOCAL_NONCE, tmp, 0x80);
		// some strange thing, but needed
		global->LOCAL_NONCE[0]=0x01;

		
		buf=malloc(0x1000);
		outbuf=malloc(0x1000);

		memset(buf,0,0x200);
		memset(outbuf,0,0x200);

		// first integer is 0x00000000 !!!
		memcpy(buf+4,global->LOCAL_NONCE,0x80);
		
		// show data for hashing
		// integer(0x00) and 0x80 nonce
		show_memory(buf, 0x84, "local NONCE input");

		// making sha1 hash on nonce
		//get_sha1_data(buf, 0x84, outbuf, 1);
		
		_get_sha1_data(buf, 0x84, outbuf, 0);


		// copy local part of aes key
		memcpy(global->AES_KEY,outbuf,0x10);

		// show full aes session key
		show_memory(global->AES_KEY, 0x10, "AES KEY local");
	};

	/////////////////////////////
	// RSA encode
	/////////////////////////////
	// for encrypting local nonce
	if (1) {
		char *buf;
		char *outbuf;


		buf=malloc(0x1000);
		outbuf=malloc(0x1000);

		memset(buf,0,0x200);
		memset(outbuf,0,0x200);

		// copy encrypted nonce
		memcpy(buf,global->LOCAL_NONCE,0x80);
		
		// rsa decrypt nonce
		show_memory(buf, 0x80, "Before RSA encrypt nonce");
		_get_encode_data(_MIPP_ globalptr, buf, 0x80, outbuf);
		show_memory(outbuf, 0x80, "After RSA encrypt nonce");

		// copy decrypted nonce
		memcpy(global->LOCAL_NONCE,outbuf,0x80);

	};





	//////////////////////////////////////////////////
	// modify nonce blob, in aes data
	//////////////////////////////////////////////////
	//memcpy(aes_41data+0x22d,local_nonce,0x80);


	//////////////////////////////////////////////////
	// modify challenge response blob, in aes data
	//////////////////////////////////////////////////
	//emcpy(aes_41data+0x1a6,CHALLENGE_RESPONSE,0x80);

	//////////////////////////////////////////////////
	// change uic cert to new, becouse of expire 
	//////////////////////////////////////////////////
	//memcpy(aes_41data+0x17,aes_41data_remote_uic,0x188);

	//////////////////////////////////////////////////
	// change uic cert2, becouse of keys change
	//////////////////////////////////////////////////
	//memcpy(aes_41data+0x02B1,aes_41data_local_uic,0x188);
	
	
	
	///////////////////////////////
	// first 41 
	///////////////////////////////

	memset(buf1,0,sizeof(buf1));
  	buf1_len=encode41_setup2pkt(globalptr, buf1, sizeof(buf1));
	show_memory(buf1, buf1_len, "setup2pkt");

	// aes encrypt block 1
	blkseq=0x01;
	buf1_len=process_aes(globalptr, buf1, buf1_len, 0, blkseq, 0);



	/////////////////////////////////////
	// first bytes correction
	/////////////////////////////////////
	// calculate for 4 and 5 byte fixing
	buf1header_len=first_bytes_correction(globalptr, buf1header, sizeof(buf1header)-1, buf1, buf1_len);
	show_memory(buf1header, buf1header_len, "setup1header");


	/////////////////////////////////
	// assembling pkt for sending
	/////////////////////////////////

	len=0;

	//header
	memcpy(pkt+len,buf1header,buf1header_len);
	len=len+buf1header_len;
	
	//aes
	memcpy(pkt+len,buf1,buf1_len);
	len=len+buf1_len;
	

	/////////////////////////////////
	// RC4 encrypt pkt
	/////////////////////////////////
	show_memory(pkt, len, "Before RC4 encrypt");		
	RC4_crypt (pkt, len, &global->rc4_send, 0);
	show_memory(pkt, len, "After RC4 encrypt");		


	// display pkt
	show_memory(pkt, len, "Send pkt");


	*pkt_len=len;

	return 0;

};




int process_tcp_client_sess1_pkt3(_MIPD_ char *globalptr, char *resp, int resp_len){
	u8 recvbuf[0x1000];
	int tmplen;
	int recvlen;
	int blkseq;
	char nonce[0x80];

	struct global_s *global;
	global=(struct global_s *)globalptr;



	// recv pkt
	show_memory(resp, resp_len, "Result");

	// copy pkt
	recvlen=resp_len;
	memcpy(recvbuf,resp,recvlen);


	/////////////////////////////////
	// RC4 decrypt pkt
	/////////////////////////////////
	show_memory(recvbuf, recvlen, "Before RC4 decrypt");
	RC4_crypt (recvbuf, recvlen, &global->rc4_recv, 0);
	show_memory(recvbuf, recvlen, "After RC4 decrypt");


	/////////////////////////////////
	// Process received pkt
	/////////////////////////////////

	// check pkt size
	tmplen=get_packet_size(recvbuf, 4);
	tmplen=tmplen-1;
	if (tmplen > 0x1000){
		if(DEBUG_LEVEL>=100) printf("pkt block size too big, len: 0x%08X\n",tmplen);
		return -1;
	};
	if (tmplen <= 0){
		if(DEBUG_LEVEL>=100) printf("pkt block size too small, len: 0x%08X\n",tmplen);
		return -1;
	};

	// show header
	show_memory(recvbuf, 5, "Header");

	// doing aes decrypt
	blkseq=0x01;
	process_aes_crypt(globalptr, recvbuf+5, recvlen-5, 0, blkseq, 0);




	/////////////////////////////
	// 41 decode
	/////////////////////////////
	// for getting crypted nonce
	if (1){
		struct self_s self;
		int ret;
		char *mybuf;
		int mysize;
		u8 *data;
		u32 datalen;
		
		data = recvbuf+5;
		datalen=recvlen-5;

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

		// copy encrypted nonce from 41 encoding blob
		memcpy(nonce,mybuf,0x80);

		// display crypted nonce
		show_memory(nonce, 0x80, "RSA encrypted remote nonce");
		
		free_structure((char *)&self);
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



	///////////////////////
	// pre-defined data
	///////////////////////
	
	// aes key nonce1 (local)

	//for old xot_iam key
	//memcpy(aes_key,"\xA9\x45\x5C\x42\x7E\xCC\x79\x52\xF8\xA3\x07\xBD\xEA\xC8\x5B\x35",0x10);
	//memcpy(aes_key,"\xBD\x2E\xC3\x04\x10\xD8\x29\x03\x1A\xE4\x00\x97\x94\xB2\x3B\xE4",0x10);

	//for xot_iam
	//memcpy(aes_key,"\xE5\x9A\xA2\x55\xFD\xFF\xE5\xA0\x13\x66\xC8\x15\x3C\x69\x6D\xE6",0x10);

	//for xotabba
	//memcpy(aes_key,"\xC5\xC9\xEA\x82\x77\xFC\x51\x3C\x1A\xB2\xF1\x37\xEE\xCF\x4B\x39",0x10);




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


	return 0;
};



