//
// recv utils
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
extern int main_unpack_once(u8 *indata, u32 inlen);
extern int main_unpack41(u8 *indata, u32 inlen);
extern int main_unpack_getdata4 (u8 *indata, u32 inlen, u32 *sess_id);


extern int get_packet_size(char *data,int len);
extern int get_blkseq(char *data, int datalen);
extern int process_aes_crypt(char *globalptr, char *data, int datalen, int usekey, int blkseq, int need_xor);


// handling recv'd packets
extern int process_57_41(char *globalptr, char *resp, int resp_len);
extern int process_6D_41(char *globalptr, char *resp, int resp_len);



extern uint DEBUG_LEVEL;



//in ida called
//unpack_7_bit_encoded_to_dword
int get_packet_size_new(char *data,int len, int *size_bytes){
	unsigned int ebx, edi, esi, eax, ecx, ebp, edx;
	char *buf_eax;
	int len_bytes=0;

	//printf("ENTER unpack_7_bit_encoded_to_dword \n");
	
	ebx=len;

	esi=0;
	edi=0;

	eax=ebx;

	// if len == 0 
	if (eax==0){
			//printf("konchilsya buffer,smth like terra nova here, jmp hz kuda\n");
			return -1;
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

		len_bytes++;

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
	// diveded by 2 and -1
	edi=edi>>1;
	
	if(DEBUG_LEVEL>=100) printf("PKT SIZE=0x%08X\n",edi);

	edi=edi-1;


	*size_bytes=len_bytes;

	//printf("LEAVE unpack_7_bit_encoded_to_dword \n");

	return edi;

};


/*
* Get Cmd Size
*/
int get_cmd_size_old(char *data,int len, int *size_bytes){
	unsigned int edi, esi, eax, ecx, ebp, edx;
	char *buf_eax;
	int len_bytes=0;


	if (len==0){
			//printf("buf len=0\n");
			return -1;
	};

	esi=0;
	edi=0;
	ebp=(int )data;
	do{
		eax=ebp;

		buf_eax=(char *)eax;
		edx=buf_eax[0] & 0xff;

		eax++;
		len_bytes++;
		ebp=eax;

		eax=edx;
		eax=eax & 0x7f;
		eax=eax << esi;

		ecx=edi;
		ecx=ecx | eax;
		edi=ecx;

		esi=esi+7;

	}while(edx >= 0x80);  
	
	edi=edi>>3;


	*size_bytes=len_bytes;
	return edi;
};




//
// process tcp packet4 (second)
//
int process_tcp_packet4(char *globalptr, char *resp, int resp_len){
	u8 recvbuf[0x2000];
	int pkt_block;
	int i;
	int len;
	int recvlen;
	int remote_blkseq;
	int id_sess;
	int id_sess_len;
	int offset;

	int current_pkt_size;
	int current_pkt_size_len;

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


		offset=0;

		current_pkt_size=get_packet_size_new(recvbuf+i+offset, 5, &current_pkt_size_len);
		if (current_pkt_size==-1){
			return -1;
		};

		show_memory(recvbuf+i+offset, 5, "Header");

		printf("current pkt size = 0x%X\n",current_pkt_size);
		printf("current pkt size length = %d\n",current_pkt_size_len);


		if (current_pkt_size > 0x1000){
			if(DEBUG_LEVEL>=100) printf("pkt block size too big, len: 0x%08X\n",current_pkt_size);
			return -1;
		};
		if (current_pkt_size <= 0){
			if(DEBUG_LEVEL>=100) printf("pkt block size too small, len: 0x%08X\n",current_pkt_size);
			return -1;
		};


		// usually
		// 1-2 bytes: - size,
		// 3 byte: 05
		// 4-5 byte - crc32 ^ sessid

		// "05" + "FF FF" 2 bytes of crc16^sessid
		offset=current_pkt_size_len+3;

		//for small packets, header len - 4
		show_memory(recvbuf+i+offset, 5, "Header");

		//get blkseq, need full aes len with crc32(2 bytes)
		remote_blkseq=get_blkseq(recvbuf+i+offset,current_pkt_size-2);

		//aes decode
		if ( global->session_setup_completed==0 ){
			process_aes_crypt(globalptr, recvbuf+i+offset, current_pkt_size-2, 0, remote_blkseq, 0);
		};
		if ( global->session_setup_completed==1 ){
			process_aes_crypt(globalptr, recvbuf+i+offset, current_pkt_size-2, 1, remote_blkseq, 1);
		};


		show_memory(recvbuf+i+offset, 5, "Header2");

		id_sess=get_packet_size_new(recvbuf+i+offset, 5, &id_sess_len);
		if (id_sess==-1){
			return -1;
		};
		if (DEBUG_LEVEL>=100) printf("session id, id_sess: 0x%08X\n",id_sess);


		offset=offset+id_sess_len;

		if (DEBUG_LEVEL>=100) printf("session cmd: 0x%08X\n",recvbuf[i+offset]);


		/*
		//sess cmd
		if (recvbuf[i+5+3]==0x57){
			//process_57_41(globalptr, recvbuf+i+5, tmplen-4);
		};
		if (recvbuf[i+5+3]==0x6D){
			
			//process_6D_41(globalptr, recvbuf+i+5, tmplen-4);
			
			sess_id=0;
			main_unpack_getdata4 (recvbuf+i+5, tmplen-4, &sess_id);

			if ((sess_id>0) && (global->sess_id==0)) {
				global->sess_id=sess_id;
			};

		};
		*/

		main_unpack41(recvbuf+i+offset, current_pkt_size-offset);



		len=len-current_pkt_size-1-current_pkt_size_len;
		i=i+current_pkt_size+1+current_pkt_size_len;

		if(DEBUG_LEVEL>=100) printf("len(left)=%d i(bytes processed)=%d\n",len,i);
		if(DEBUG_LEVEL>=100) printf("len(current block)=%d\n",current_pkt_size);
		if(DEBUG_LEVEL>=100) printf("confirm_count=%d\n",global->confirm_count);


	};



	return 0;
};





//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////



//
// process tcp packet (first)
//
int process_tcp_packet3(char *globalptr, char *resp, int resp_len){
	u8 recvbuf[0x2000];
	int pkt_block;
	int i;
	int len;
	int tmplen;
	int recvlen;
	int remote_blkseq;
	int tmp2;

	u32 sess_id;

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

		if(DEBUG_LEVEL>=100) printf("TMPLEN: 0x%08X\n",tmplen);

		//for small packets, header len - 4
		show_memory(recvbuf+i, 5, "Header");

		//get blkseq, need full aes len with crc32
		remote_blkseq=get_blkseq(recvbuf+i+5,tmplen-2);

		if (remote_blkseq > 0x1000){
			if(DEBUG_LEVEL>=100) printf("remote_blkseq too big, len: 0x%08X\n",remote_blkseq);
			return -1;
		};
		if (remote_blkseq <= 0){
			if(DEBUG_LEVEL>=100) printf("remote_blkseq too small, len: 0x%08X\n",remote_blkseq);
			return -1;
		};


		//aes decode
		if ( global->session_setup_completed==0 ){
			process_aes_crypt(globalptr, recvbuf+i+5, tmplen-4, 0, remote_blkseq, 0);
		};
		if ( global->session_setup_completed==1 ){
			process_aes_crypt(globalptr, recvbuf+i+5, tmplen-4, 1, remote_blkseq, 1);
		};


		show_memory(recvbuf+i+5, 5, "Header2");

		tmp2=get_packet_size(recvbuf+i+5, 4);

		if (DEBUG_LEVEL>=100) printf("session cmd: 0x%08X\n",recvbuf[i+5+3]);
		if (DEBUG_LEVEL>=100) printf("session id, tmp2: 0x%08X\n",tmp2);

		//sess cmd
		if (recvbuf[i+5+3]==0x57){
			process_57_41(globalptr, recvbuf+i+5, tmplen-4);
		};

		if (recvbuf[i+5+3]==0x6D){
			
			process_6D_41(globalptr, recvbuf+i+5, tmplen-4);
			
			sess_id=0;
			main_unpack_getdata4 (recvbuf+i+5, tmplen-4, &sess_id);

			if ((sess_id>0) && (global->sess_id==0)) {
				global->sess_id=sess_id;
			};

		};

		main_unpack41(recvbuf+i+5, tmplen-4);



		len=len-tmplen-3;
		i=i+tmplen+3;

		if(DEBUG_LEVEL>=100) printf("len(left)=%d i(bytes processed)=%d\n",len,i);
		if(DEBUG_LEVEL>=100) printf("len(current block)=%d\n",tmplen);
		if(DEBUG_LEVEL>=100) printf("confirm_count=%d\n",global->confirm_count);

	};


	return 0;
};



//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////


//
// process pkt 
//
int process_pkt(char *pkt, int pkt_len, int use_replyto, int *last_recv_pkt_num){
	int i;
	int j;
	int k;
	int len;
	int offset;

	int current_pkt_size;
	int current_pkt_size_len;
	int recv_pkt_num;
	int len_42_pkt;
	int len_42_pkt_size;
	int cmd;
	int cmd_len;
	int reply_on_pkt;
	int len_42_processed;

	len=pkt_len;

	/////////////////////////////////
	// processing response
	/////////////////////////////////

	i=0;j=0;k=0;
	while(len > 0){
		j++;
		offset=0;



		printf("\npkt in seq: %d\n",j);
		show_memory(pkt+i+offset, 5, "pkt head at");

		current_pkt_size=get_packet_size_new(pkt+i+offset, 5, &current_pkt_size_len);
		if (current_pkt_size==-1){
			return -1;
		};
		current_pkt_size+=2;

		printf("current pkt size + 2(with header): 0x%X\n",current_pkt_size);
		printf("current pkt size length: %d\n",current_pkt_size_len);

		if (current_pkt_size > 0x1000){
			printf("pkt block size too big, len: 0x%08X\n",current_pkt_size_len);
			

			offset++;
			printf("\npkt in seq: %d\n",j);
			show_memory(pkt+i+offset, 5, "pkt head at");

			current_pkt_size=get_packet_size_new(pkt+i+offset, 5, &current_pkt_size_len);
			if (current_pkt_size==-1){
				return -1;
			};
			current_pkt_size+=2;

			printf("current pkt size + 2(with header): 0x%X\n",current_pkt_size);
			printf("current pkt size length: %d\n",current_pkt_size_len);


		};

		if (current_pkt_size <= 0){
			printf("pkt block size too small, len: 0x%08X\n",current_pkt_size_len);
			return -1;
		};

		offset+=current_pkt_size_len;
		
		//for confirm 07 01 FF FF
		if (current_pkt_size==4){
			offset+=1;
			j--;
		};

		//

		recv_pkt_num=0;
		if (0){
			memcpy(&recv_pkt_num,pkt+i+offset,2);
			*last_recv_pkt_num=recv_pkt_num;
			printf("recv_pktnum=0x%04X\n",bswap16(recv_pkt_num));
			offset+=2;
		};



	   if (offset < current_pkt_size) {

		do {
			k++;
			len_42_pkt=0;

			memcpy(&len_42_pkt,pkt+i+offset,1);
			printf("len_42_pkt: 0x%X\n",len_42_pkt);
			offset+=1;
			
			if (len_42_pkt > 0x7f) {
				offset+=1;

				//current_pkt_size++;

				show_memory(pkt+i+offset-2, 5, "pkt 42 size head at");
				len_42_pkt=0;
				len_42_pkt=get_packet_size_new(pkt+i+offset-2, 5, &len_42_pkt_size);
				if (len_42_pkt==-1){
					return -1;
				};
				len_42_pkt=(len_42_pkt+1)*2;
				//len_42_pkt--;
				printf("len_42_pkt: 0x%X\n",len_42_pkt);
			};

			if (0) {
				cmd=get_cmd_size_old(pkt+i+offset, 5, &cmd_len);
				if (cmd==-1){
					return -1;
				};
				printf("cmd: $%d\n",cmd);
				printf("cmd len: %d\n",cmd_len);		
				offset+=cmd_len;
			};

			if ( (pkt[i+offset]!=0x42) && (use_replyto) ){
				reply_on_pkt=0;
				memcpy(&reply_on_pkt,pkt+i+offset,2);
				printf("reply_on_pkt=0x%04X\n",bswap16(reply_on_pkt));
				offset+=2;
				len_42_pkt-=2;
			};

			if (pkt[i+offset]!=0x42){
				printf("next byte not 0x42 ! it is 0x%08X\n",pkt[i+offset] & 0xFF);
				return -1;
			};

			len_42_processed=main_unpack_once(pkt+i+offset,len_42_pkt);
			offset+=len_42_processed;

			if (len_42_processed != len_42_pkt){
				printf("len_42_pkt=0x%08X\n",len_42_pkt);
				printf("len_42_processed=0x%08X\n",len_42_processed);
				return -1;
			};


			printf("offset at end = 0x%08X\n",offset);
			printf("current pkt size = 0x%08X\n",current_pkt_size);

		} while (offset < current_pkt_size);

		if (offset > current_pkt_size){
			current_pkt_size=offset;
		}

       }

		//
		len=len-current_pkt_size;
		i=i+current_pkt_size;

		printf("left = %d, bytes processed = %d\n",len,i);


	};
	
	return 0;

};

