//
// recv packet data loop/processing
//


// for rc4
#include "rc4/Expand_IV.h"

// for aes
#include "crypto/rijndael.h"

// for global variables
#include "global_vars.h"

// for types
#include "short_types.h"

// for 41
#include "decode41.h"

// for mip miracl
#include "crypto/miracl.h"

extern int process_tcp_packet3(char *globalptr, char *resp, int resp_len);
extern int process_tcp_packet4(char *globalptr, char *resp, int resp_len);
extern int show_memory(char *mem, int len, char *text);


extern int get_packet_size(char *data,int len);
extern int get_blkseq(char *data, int datalen);
extern int process_aes_crypt(char *globalptr, char *data, int datalen, int usekey, int blkseq, int need_xor);

extern uint DEBUG_LEVEL;




int process_tcp_client_sess1_pkt3n(_MIPD_ char *globalptr, char *resp, int resp_len){
	struct global_s *global;
	global=(struct global_s *)globalptr;


	// recv pkt
	show_memory(resp, resp_len, "Result");

	process_tcp_packet3(globalptr, resp, resp_len);



	return 0;
};


int process_tcp_client_sess1_pkt4n(_MIPD_ char *globalptr, char *resp, int resp_len){
	struct global_s *global;
	global=(struct global_s *)globalptr;


	// recv pkt
	show_memory(resp, resp_len, "Result");

	process_tcp_packet4(globalptr, resp, resp_len);


	return 0;
};



/////////////////////////////////////////////////////////////////////////////////////////

int process_tcp_client_sess1_pkt4(_MIPD_ char *globalptr, char *resp, int resp_len){
	u8 recvbuf[0x2000];
	char header41[5];
	int pkt_block;
	int i;
	int len;
	int tmplen;
	int recvlen;
	int remote_blkseq;

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
	// processing response
	/////////////////////////////////
	// by aes blocks with 109 cmd each

	i=0;
	pkt_block=0;
	global->confirm_count=0;

	len=resp_len;
	while(len > 0){
		pkt_block++;

		if(DEBUG_LEVEL>=100) printf("PKT BLK: %d\n\n",pkt_block);

		// 1-2 bytes: - size,
		// 3 byte: 05
		// 4-5 byte - crc32 ^ sessid
		tmplen=get_packet_size(recvbuf+i, 4);
		tmplen=tmplen-1;
		if (tmplen > 0x1000){
			if(DEBUG_LEVEL>=100) printf("pkt block size too big, len: 0x%08X\n",tmplen);
			return -1;
		};
		if (tmplen <= 0){
			if(DEBUG_LEVEL>=100) printf("pkt block size too small, len: 0x%08X\n",tmplen);
			return -1;
		};

		//for small packets, header len - 4
		show_memory(recvbuf+i, 4, "Header");

		//get blkseq, need full aes len with crc32
		remote_blkseq=get_blkseq(recvbuf+i+4,tmplen-2);

		//aes decode
		process_aes_crypt(globalptr, recvbuf+i+4, tmplen-2, 1, remote_blkseq, 1);

		//2bytes of size, encode rest of length
		//tmplen-2 , rest of len - 2 bytes of crc32 ^ sessid
		//decode41(recvbuf+i+4, tmplen-2,"PKT 6D reply1");

		//processing headers, need for cmd confirmation
		memcpy(header41,recvbuf+i+4,5);

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

		len=len-tmplen-2;
		i=i+tmplen+2;

		if(DEBUG_LEVEL>=100) printf("len(left)=%d i(bytes processed)=%d\n",len,i);
		if(DEBUG_LEVEL>=100) printf("len(current block)=%d\n",tmplen);
		if(DEBUG_LEVEL>=100) printf("confirm_count=%d\n",global->confirm_count);

	};


	return 0;
};



