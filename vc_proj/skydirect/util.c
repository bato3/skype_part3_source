/*  
*
* Utils
*
* little help tools
*
*
*/


// for rc4
#include "rc4/Expand_IV.h"

// for aes
#include "crypto/rijndael.h"

// for 41 
#include "decode41.h"

// for global structure
#include "global_vars.h"


extern int main_unpack (u8 *indata, u32 inlen);

extern unsigned int Calculate_CRC32(char *crc32, int bytes);
extern int Calculate_CRC32_For41(char *a2, int a3);
extern int encode_to_7bit(char *buf, uint word, int limit);

int show_memory(char *mem, int len, char *text);


extern uint DEBUG_LEVEL;

//////////////////////
// Util             //
//////////////////////


//
// show memory
//
int show_memory(char *mem, int len, char *text){
	int zz;
	int i;

	if(DEBUG_LEVEL>=100) {

		printf("%s\n",text);
		printf("Len: 0x%08X\n",len);

		zz=0;
		for(i=0;i<len;i++){
			printf("%02X ",mem[i] & 0xff);
			zz++;if (zz == 16) { zz=0; printf("\n ");};
		};
		printf("\n");

	};

	return 0;
};

//
// show memory with ascii
//
int show_memory_withascii(char *mem, int len, char *text){
	int zz;
	int i;
	int k;
	char b[16+1];
	int t;

	if(DEBUG_LEVEL>=100) {
		printf("%s\n",text);
		printf("Len: 0x%08X\n",len);
		zz=0;
		k=0;
		b[16]=0;
		for(i=0;i<len;i++){
			printf("%02X ",mem[i] & 0xff);
			t=mem[i] & 0xff;
			if ((t>=0x20) && (t<=0x7f)){
				memcpy(b+k,mem+i,1);
			}else{
				memcpy(b+k,"\x20",1);
			};
			zz++;
			k++;
			if (zz == 16) { 
				zz=0;
				k=0;
				printf(" ; %s",b);
				printf("\n ");
			};
		};
		printf("\n");
	};

	return 0;
};


/*
/////////////////////////////////////////
// tmp count remote session id
/////////////////////////////////////////

int first_bytes_calc(){	
	u32 pkt_crc32;
	u32 total;
	u32 last2b;

	u8 buf[]=
"\x7C\x6C\xC3\x3D\xE3\x4A\x89\x9F\xAC\x48\xB8\x15\x92\x86\xE0\x09"
"\x81\xF6\x8F\xFF\xC2\xCD\x35\xB9\xA9\x62\xB0\xF1\xC4\xCB\x72\x86"
"\xE8\xF4\x69\x00\x00\x54\x73\x90\x35\x62\xF2\x85\x5E\x58\xC2\x8D"
"\x40\x14\x38\x8E\x93\x21\x3A\x6A\x21\xB9\xD9\x9C\xDF\x71\xAD\x1C"
"\x4C\xE9\x4F\x60\xA4\x5E\x8A\x32\x92\x20\xA1\x47\x69\x33\x19\x18"
"\xDC\x99\x34\x80\xB3\x18\x3C\xC5\xA9\x56\xF4\xFE\x33\x49\x0C\x8D"
"\xB1\x54\xAD\x25\x88\x6D\x2E\x95\x3B\xC5\xEE\x6C\x6A\xB6\xC3\x00"
"\x1B\xB2\xAD\xE0\xF2\x71\xFD\x29\xE2\xBD\xFA\x2D\x28\x46\x76\x79"
"\x6A\xC3\x45\xF2\x68\x04\xAB\x71\xCF\xA2\x75\x67\x11\x34\x0D\x8B"
"\xBB\x91\xB9\x5D\x5A\x3C\x62\x10\x09\xEF\x16\x27\xB1\x1E\x37\xF3"
"\x5F\x22\xE6\x19\x57\xBB\xCD\x24\x39\x7A\x8C\xE8\x56\x16\xBB\xA2"
"\xAA\x69\x6C\x99\x38\xAF\xBA\xA9\x4D\x0E\xB9\x16\x9A\x74\x5B\xAA"
"\xF9\xEE\x42\x3E\x64\x80\xA8\xBF\x2C\xB2\x88\xE4\x68\x3F\x42\x30"
"\x5B\x3F\x35\x16\xF3\x61\xE5\xDD\xAC\xC8\x5F\x55\xD4\x52\x16\x3B"
"\x8E\x28\x1F\x67\xD7\xCE\xB7\x28\xD7\x4D\x71\x89\x26\xD1\xA3\x0F"
"\x86\x5A\xDB\x01\x9B\x22\x88\xB6\x4C\xD2\xC7\x3A\xDE\x17\xDC\x91"
"\x88\x46\xA6\xEA\x3F\x40\x92\x3C\xF7\xA7\x22\x9E\x89\x91\x29\xB9"
"\x33\x1F\x1C\x0D\x06\xA0\x15\xB7\x2E\x7E\x12\x70\x32\xD2\x36\x73"
"\xC6\x9D\x3B\x05\x47\x67\x75\xCB\xE0\x4D\x5A\xAE\xE5\xE6\x1D\x8D"
"\x9C\x10\x9A\x7E\x24\x03\xD5\x6B\x11\xB4\x3C\xD5\x47\x65\xC9\xDF"
"\x37\x6C\xEC\x4C\x24\x23\x83\xCF\xC4\x6B\x0B\x65\x05\x49\xF7\xAA"
"\xA0\x98\xDE\x49\xCC\x9C\x15\x21\x8D\xD2\x8E\x65\x55\x06\x76\x2D"
"\x65\xAE\x7D\x6E\xB2\x2D\x21\x11\x22\x17\x87\x68\x42\x0C\x25\x77"
"\x9C\xF9\x77\x3B\xF9\x78\x8A\x33\x33\x20\x5B\xD6\x8D\xD9\x0B\x3B"
"\x99\xFF\xFC\xB8\x35\x65\x9F\xCE\x28\x42\xBE\x18\xE5\xB7\x6B\xEF"
"\xC8\x32\x6A\x8D\x42\x64\xEF\x68\x65\xDD\x4F\x20\x96\x95\x71\x4C"
"\xCF\x6A\xFD\x1E\x34\x9B\x37\x34\xE2\x4B\xE3\xE0\x4D\x55\x94\x93"
"\x2F\x27\x49\xF0\x09\xAD\xFB\x54\x9E\x5C\x90\xC8\xAD\x09\xFE\x44"
"\xD9\xCD\xBE\x4E\x3B\x20\x34\xA8\x83\xCC\x06\x48\xDD\x64\x30\x34"
"\x1D\x82\x00\xEC\xCF\xFB\x9D\xF0\x3A\x4B\xA9\x3A\xD9\x13\xC4\xFE"
"\x70\x82\x8F\x65\x66\x06\x77\xF0\x4C\x6D\xC1\xB8\x5A\xE4\xA0\xD7"
"\x82\x61\xBB\x3F\x71\x54\x2B\xA7\x4E\xF5\x69\x55\xE9\x64\x5A\xB7"
"\xEA\x8C\x4F\xD2\x34\xEE\x15\x7D\x29\x7B\x3E\x8F\xF2\xD2\x81\x56"
"\x71\x0D\x21\xA6\x4D\xEE\x7E\x71\xCB\x9D\xFA\xBA\x0C\x9A\x17\x8A"
"\x6C\xD0\x88\x7E\xA3\xF1\x12\x86\xC2\x90\x59\x07\xD0\x99\x24\xD3"
"\x5C\x43\x73\x39\xE5\xA4\x4E\xD8\x6B\xB3\xE1\x5A\x2A\x75\x23\x3E"
"\x26\xDC\x2D\xAC\x7F\x54\x7D\x5C\x16\xDA\x95\x8A\x09\xAA\x9A\xF5"
"\xF4\x59\x5D\x0F\xEB\x91\x1D\x71\x05\x5E\x10\x4B\x4F\x25\xB7\x63"
"\x7F\x0A\x32\x14\x70\x81\xF0\x15\x6E\x2E\x73\x91\x48\xD8\xA1\x82"
"\xE0\x59\x30\xCC\xD8\x2B\x2A\xBF\x15\xF2\x28\xB3\xE8\x49\x74\x57"
"\xFD\x3D\xDB\xF7\x56\xDD\x0F\x2E\x4A\xCF\x30\xDF\x5E\x42\x61\x40"
"\x0D\xB1\xB4\xC5\x0B\xCA\x00\x9A\x71\xA5\x83\xC0\xCF\x93\x4A\xF4"
"\x20\xDD\xEE\x3D\xDE\x59\xEB\xB9\x63\x7A\x06\x00\x80\x50\x6E\xC8"
"\xE8\x08\x08\x9A\xE2\xA5\x67\x51\x79\x1B\xA7\xCE\x05\xD1\x02\x38"
"\x24\xC9\x1B\xA6\x11\xF6\x4F\x22\xF2\x48\x95\xC6\xCE\x25\x40\x11"
"\x75\x96\xF4\x7E\xF8\x7E\x9C\x1F\x81\x08\xCA\xFB\xAC\xB4\x48\x6D"
"\x5D\xB9\xA2\x1D\x03\x56\xBD\xFF\x0B\x30\xCB\xD9\x8D\xF5\x86\xC6"
"\x6A\xB6\xCF\xB0\x50\xFD\x23\x1F\x82\x5A\x9A\x21\xEB\x34\x61\xD0"
"\x55\xED\x3D\xB2\xA3\xEE\x88\x6C\xB2\x9B\xA8\x99\x2E\x6E\x42\x80"
"\x82\x9B\xF6\x6F\x08\x27\x22\xBD\xFC\x8D\xA0\x6E\x9F\x05\xDC\xD2"
"\x35\xCD\x40\x78\x87\x69\x82\x8A\x2F\x4B\x2D\xFD\xF8\x1E\xA9\x58"
"\xB0\xC3\x3C\xBC\xD6\x3E\xE0\x02\x5F\xF8\xD0\x7F\xBC\xA7\xAE\x6E"
"\x85\x77\xF4\x3C\xCF\x6B\x8E\x3A\x90\x8A\xAF\x17\x89\x6C\x49\x3C"
"\x84\xA6\x9D\xAA\x7C\x4C\x0E\x08\xBC\xF3\xC5\x3F\x8A\xB6\xE9\x36"
"\x5D\x59\x0D\xDA\xED\x1A\x6A\x5F\x18\x22\x97\x46\x80\xD0\x42\xBC"
"\xA7\x18\x8D\x4E\x31\xCE\x1A\x01\x20\xFF\x57\x51\xDA\xAA\x41\x7B"
"\x18\x32\xE8\xED\x9D\xD9\x5A\x9C\x6D\x59\x8E\xBD\x0E\x89\x17\x57"
"\x5B\x58\x03\xC4\x67\x15\xC3\xD4\x46\x69\x59\x92\xE3\xA1\xED\xC0"
"\x24\xE8\x82\x17\x99\xA5\x74\xB2\x8F\xA4\x3E\x91\x9E\x15\x68\x4C"
"\xA8\x1A\x8C\x38\x1D\x42\x74\x39\x4C\xED\xB2\xFB\x06\xA4\x2A\x7A"
"\x63\xBC\x07\xAB\x60\xC4\x65\x84\x60\x52\x8A\x87\xB6\xD2\x25\x8C"
"\xC1\x17\x13\x6A\x70\x08\x59\x86\x16\xD6\xC2\xBA\xC1\xA4\x3D\xF4"
"\x7D\x89\x7D\xC3\x99\xB8\x4C\xB1\xF9\xC6\x02\x7C\xFF\x5B\xA5\x0B"
"\x52\x80\x60\x60\x91\x48\x9D\xDF\xE3\x66\xA6\x0E\x99\x53\x55\x78"
"\xBB\x52\x1D\x9F\x46\x17\x03\xC2\xEB\x36\xC2\x3E\xCF\xE9\x81\xB2"
"\x50\xBA\x39\x1D\x68\x6E\x6B\x40\x35\x18\x63\x7D\x76\x29\x5F\xBB"
"\xBC\xD5\x4B\x47\xC0\xF0\x65\x40\x8A\xC7\x6D\x48\x7C\x87\x91\x69"
"\x91\x2A\x18\xEA\x07\x42\x68\xA1\xF2\x4F\x0F\xF0\xFC\xE6\x8D\xC6"
;

	u32 buf_len=sizeof(buf)-1;

	
	char *ptr;
	int tmplen;	
	int REMOTE_SESSION_ID=0;



	// calculate for 4 and 5 byte fixing
	ptr=(char *)buf;
	tmplen=buf_len;
    

	pkt_crc32=Calculate_CRC32(ptr, tmplen);
	pkt_crc32=pkt_crc32 & 0xffff;
	printf("pkt block crc32=%08X\n",pkt_crc32);


	last2b=0x43D2;
	printf("last2b=0x%08X\n",last2b);

	total=pkt_crc32 ^ last2b;
	printf("total=0x%08X\n",total);

	total=total>>1;
	printf("total sess id=0x%08X\n",total);



	return 1;

};

*/



/////////////////////////////////////////
// get blk seq
/////////////////////////////////////////
int get_blkseq(char *data, int datalen){	
	int tmplen;
	int blkseq;
	u32 pkt_crc32;
	u32 frompkt;


	//data without crc32
	tmplen=datalen-2;

	//crc32 from pkt
	memcpy(&frompkt, data+tmplen, 2);
	frompkt=frompkt & 0xffff;

	//show_memory(data, tmplen, "CRC32(tmp)");

	//crc32 on aes encrypt
	pkt_crc32=Calculate_CRC32( (char *)data,tmplen);
	pkt_crc32=pkt_crc32 & 0xffff;
	blkseq=pkt_crc32 ^ frompkt;
	
	//printf("frompkt = %08X\n",frompkt);
	//printf("pkt_crc32 = %08X\n",pkt_crc32);
	if(DEBUG_LEVEL>=100) printf("blkseq from remote = %08X\n",blkseq);


	return blkseq;

};

int first_bytes_correction(char *globalptr, char *header, int header_len, char *buf, int buf_len){	
	u32 pkt_crc32;
	u32 total;
	u32 last2b;
	int tmplen;
	char *ptr;

	struct global_s *global;
	global=(struct global_s *)globalptr;

	// calculate for 4 and 5 byte fixing
	ptr=(char *)buf;
	tmplen=buf_len;
    

	pkt_crc32=Calculate_CRC32(ptr, tmplen);
	pkt_crc32=pkt_crc32 & 0xffff;
	if(DEBUG_LEVEL>=100) printf("pkt block crc32=%08X\n",pkt_crc32);


	//total=global->REMOTE_SESSION_ID<<1;
	total=global->connid << 1;
	if(DEBUG_LEVEL>=100) printf("total=0x%08X\n",total);

	last2b=pkt_crc32 ^ total;
	if(DEBUG_LEVEL>=100) printf("last2b=0x%08X\n",last2b);

	if(DEBUG_LEVEL>=100) printf("encode len: 0x%08X\n",buf_len+3);

    //encode buf1 len
	// + 3 for 0x05 and 2 byte crc
	header_len=encode_to_7bit(header, (buf_len+3)*2+1, header_len);

	header[header_len]=0x05;
	header_len++;

	header[header_len]=(unsigned char ) ((last2b & 0x0000ff00) >> 8);
	header_len++;
	header[header_len]=(unsigned char ) (last2b & 0xff);
	header_len++;

	return header_len;

};


/////////////////////////////////////////
// aes crypt
/////////////////////////////////////////
int process_aes_crypt(char *globalptr, char *data, int datalen, int usekey, int blkseq, int need_xor){	
	static u8 zero[32];
	static u32 ks[60];
	u32 blk[0x10];
	int j;
	int k;
	char *ptr;

	struct global_s *global;
	global=(struct global_s *)globalptr;


	memset(ks,0,sizeof(ks));

	// if no key, use zero
	memset(zero,0,sizeof(zero));

	// use real key
	if (usekey){
		memcpy(zero,global->AES_KEY,0x20);
	};

	// setup key
	aes_256_setkey (zero, ks);
	
	// for debug aes encoding
	// print key material
	if (0) {
		ptr=(char *)ks;
		show_memory(ptr, 60*4, "KeyMat");
	};

	// setup control block
	memset (blk, 0, 0x10);

	//if using key, control block have local and remote session id data.
	if (usekey){
		blk[0]=global->LOCAL_SESSION_ID * 0x10000 + global->REMOTE_SESSION_ID;
	};
	
	// need xor session id in control block
	if (need_xor){
		blk[0]=blk[0] ^ 0xFFFFFFFF;
	};

	blk[1]=blk[0];
	blk[3]=blk[3] + (blkseq * 0x10000);
	

	show_memory(data, datalen, "Before AES crypt");

	// process aes crypt
	for (j = 0; j+16 < datalen; j += 16){
		aes_256_encrypt (blk, blk+4, ks);
		dword(data+j+ 0) ^= bswap32(blk[4]);
		dword(data+j+ 4) ^= bswap32(blk[5]);
		dword(data+j+ 8) ^= bswap32(blk[6]);
		dword(data+j+12) ^= bswap32(blk[7]);
		blk[3]++;
	};
	if (j < datalen){
		aes_256_encrypt (blk, blk+4, ks);
		for (k = 0; j < datalen; j++, k++) data[j] ^= ((u8 *)(blk+4))[k^3];
	};

	show_memory(data, datalen, "After AES crypt");


	return 0;

};


//
// Process aes
//
int process_aes(char *globalptr, char *buf, int buf_len, int usekey, int blkseq, int need_xor){	
	u32 aes_checksum_crc32;
	u32 pkt_crc32;

	struct global_s *global;
	global=(struct global_s *)globalptr;

	// Re-calculate 41 checksum(crc32)
	aes_checksum_crc32=Calculate_CRC32_For41(buf,buf_len);
	if(DEBUG_LEVEL>=100) printf("aes_checksum_crc32=0x%08X\n",aes_checksum_crc32);
	aes_checksum_crc32=bswap16(aes_checksum_crc32);	
	memcpy(buf+buf_len,&aes_checksum_crc32,2);
	buf_len+=2;

	
	//aes encrypt block 3
	//blkseq=0x06;	
	process_aes_crypt(globalptr, buf, buf_len, usekey, blkseq, need_xor);

	//crc32 after aes encrypt
	pkt_crc32=Calculate_CRC32( (char *)buf,buf_len);
	pkt_crc32=pkt_crc32 & 0xffff;
	pkt_crc32=pkt_crc32 ^ blkseq;
	if(DEBUG_LEVEL>=100) printf("crc32(after aes crypt)=%08X\n",pkt_crc32);
	memcpy(buf+buf_len, &pkt_crc32, 2);
	buf_len+=2;

	return buf_len;

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
			if(DEBUG_LEVEL>=100) printf("konchilsya buffer,smth like terra nova here, jmp hz kuda\n");
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

	if(DEBUG_LEVEL>=100) printf("PKT SIZE=0x%08X\n",edi);


	//printf("LEAVE unpack_7_bit_encoded_to_dword \n");

	return edi;

};


int set_packet_size(char *a1, int c){
  char *block;
  unsigned int b;


  b = c;
  for ( block = a1; b > 0x7F; ++*block )
  {
    *block = (char)b | 0x80;
	if(DEBUG_LEVEL>=100) printf("1 cikl,  block[0]=0x%08X block[1]=0x%08X block[2]=0x%08X\n",block[0],block[1],block[2]);
    b >>= 7;
  }
  
  if(DEBUG_LEVEL>=100) printf("2 aft, block[0]=0x%08X block[1]=0x%08X block[2]=0x%08X\n",block[0],block[1],block[2]);
  *block++;
  if(DEBUG_LEVEL>=100) printf("3 inc, block[0]=0x%08X block[1]=0x%08X block[2]=0x%08X\n",block[0],block[1],block[2]);

  *block=b;

  if(DEBUG_LEVEL>=100) printf("4 set, block[0]=0x%08X block[1]=0x%08X block[2]=0x%08X\n",block[0],block[1],block[2]);
  //*block--;
  *block--;

  if(DEBUG_LEVEL>=100) printf("5 back,block[0]=0x%08X block[1]=0x%08X block[2]=0x%08X\n",block[0],block[1],block[2]);


  return 0;
}


//
//
//
int first_bytes_header(u16 seqnum, char *header, int header_len, char *buf, int buf_len){	
	int len;

	len=encode_to_7bit(header, (buf_len+6)*2, 5);
	if (len==-1){
		return -1;
	};

	seqnum=bswap16(seqnum);
	memcpy(header+len,(char *)&seqnum,2);
	seqnum=bswap16(seqnum);
	len+=2;
	
	header[len]=buf_len+2;
	len++;

	header[len]=0x32;
	len++;

	seqnum--;
	seqnum=bswap16(seqnum);
	memcpy(header+len,(char *)&seqnum,2);
	len+=2;

	return len;

};


int first_bytes_header2(u16 seqnum, char *header, int header_len, char *buf, int buf_len){	
	int len;
	
	len=0;

	header[len]=buf_len+2;
	len++;

	header[len]=0x32;
	len++;

	seqnum=bswap16(seqnum);
	memcpy(header+len,(char *)&seqnum,2);
	len+=2;

	return len;

};

int first_bytes_size(u16 seqnum, char *header, int header_len, char *buf, int buf_len){	
	int len;
	
	len=0;
	len=encode_to_7bit(header, (buf_len+2)*2, 5);

	if (len==-1){
		return -1;
	};

	seqnum=bswap16(seqnum);
	memcpy(header+len,(char *)&seqnum,2);
	len+=2;

	return len;

};


//
// Encode bytes to 7 bit
//
int encode_to_7bit(char *buf, uint word, int limit){
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
			if(DEBUG_LEVEL>=100) printf("7bit encoding fail\n");
			return -1;
		};

        to[n] = (u8) a | 0x80; 
		to[n+1] = (u8) a; 

		//printf("n=0x%08X i=0x%08X\n",n,i);
        //printf("\ta: 0x%08X\n",a);
		//printf("\tn: 0x%08X\n",to[n]);
		//printf("\tn+1: 0x%08X\n",to[n+1]);
	};
	to[n]=a;

	//printf("after cikl, n=0x%08X\n",n);
    //printf("after cikl, a=0x%08X\n",a);
	//printf("\n");

	//printf("0: 0x%08X\n",to[0]);
	//printf("1: 0x%08X\n",to[1]);
	//printf("2: 0x%08X\n",to[2]);
	//printf("3: 0x%08X\n",to[3]);
	//printf("4: 0x%08X\n",to[4]);
	//printf("5: 0x%08X\n",to[5]);


	if (n > limit) {
		if(DEBUG_LEVEL>=100) printf("not enought buffer\n");
		return -1;
	};

	for(i=0;i<=n;i++){
		buf[i]=to[i] & 0xff;
	};



    return n+1;
}



int decode41(char *data, int len, char *text){
	struct self_s self;
	int ret;
	u8 *pkt_my;
	u32 pkt_my_len;


	if(DEBUG_LEVEL>=100){

		pkt_my=data;
		pkt_my_len=len;

        ret=unpack41_structure(pkt_my,pkt_my_len,(char *)&self);
		if (ret==-1) {
			if(DEBUG_LEVEL>=100) printf("decode 41 failed\n");
			return -1;
		};
		if (ret==-2) {
			if(DEBUG_LEVEL>=100) printf("possible not all bytes decoded! (not found last 2 bytes of crc16)\n");
		};

		print_structure(text,(char *)&self,1);		

		free_structure((char *)&self);

	};

	return 0;
};



