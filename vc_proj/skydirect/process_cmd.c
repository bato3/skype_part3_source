// 

#include <stdlib.h>
#include <string.h>


#include "crypto/miracl.h"
#include "short_types.h"


extern uint DEBUG_LEVEL;



//
// converting 2 bytes of ptr from ascii to hex
//
int convert_str_to_hex(char *ptr) {
		int hex_digit=0;

		if ((ptr[0]>=0x30) && (ptr[0]<=0x39)){
			hex_digit=ptr[0]-0x30;
		};
		if ((ptr[0]>='A') && (ptr[0]<='F')){
			hex_digit=ptr[0]-0x41+0x0A;
		};
		if ((ptr[0]>='a') && (ptr[0]<='f')){
			hex_digit=ptr[0]-0x61+0x0A;
		};
		hex_digit=hex_digit<<4;

		//printf("ptr[i]=0x%08X\n",ptr[i]);
		//printf("hex_digit=0x%08X\n",hex_digit);


		if ((ptr[1]>=0x30) && (ptr[1]<=0x39)){
			hex_digit+=ptr[1]-0x30;
		};
		if ((ptr[1]>='A') && (ptr[1]<='F')){
			hex_digit+=ptr[1]-0x41+0x0A;
		};
		if ((ptr[1]>='a') && (ptr[1]<='f')){
			hex_digit+=ptr[1]-0x61+0x0A;
		};
		
		//printf("ptr[i]=0x%08X\n",ptr[i+1]);
		//printf("hex_digit=0x%08X\n",hex_digit);

		return hex_digit;
};


//
// parse argv2
//
int parse_input_line2(char *line, u8 *userhex, char *str_remote_skype, char *destip, char *destport) {
	int len;
	char str_userhex[0x200];
	u32 hex_digit;
	char *ptr;
	int i;

	memset(str_userhex,0,sizeof(str_userhex));
	//printf("input line argv2: %s\n",line);

	// replace ":" to " "
	len=strlen(line);
	while(len){
		if (line[len]==':') line[len]=' ';
		len--;
	};

	sscanf(line,"%s %s %s %s",str_userhex,str_remote_skype,destip,destport);

	if (strlen(str_userhex)!=18){
		if (DEBUG_LEVEL>=100) printf("userhex id fail to parse, hexlen: %d\n",strlen(str_userhex));
		return -1;
	};

	ptr=str_userhex+2;
	for(i=0; i<0x8;i++){
		hex_digit=convert_str_to_hex(ptr);
		
		//printf("str=%x %x\n",ptr[0],ptr[1]);
		//printf("hex_digit=0x%08X\n",hex_digit);		

		userhex[i]=(char)hex_digit;

		ptr+=2;
	};


	return 0;
};




//
// Parse cred inputs argv1
//
int parse_input_line(char *line, u32 *secret_p, u32 *secret_q, char *str_skypename, char *user_cred) {
	u32					i;
	struct bigtype		p = {16, secret_p}, q = {16, secret_q};
	int len;
	u32 hex_digit;

	char str_password[0x1000];
	char str_firstname[0x1000];
	char str_lastname[0x1000];
	char str_email[0x1000];
	char str_version[0x1000];
	char str_cred[0x1000];
	char str_p[0x1000];
	char str_q[0x1000];
	char *ptr;
	char *p_ptr;
	char *q_ptr;

	//printf("input line argv1: %s\n",line);

	// replace ":" to " "
	len=strlen(line);
	while(len){
		if (line[len]==':') line[len]=' ';
		len--;
	};

	sscanf(line,"%s %s %s %s %s %s %s %s %s",str_skypename,&str_password,&str_firstname,&str_lastname,&str_email,&str_version,
										  &str_cred,&str_p,&str_q);

	//printf("p=%s\n",str_p);
	//printf("q=%s\n",str_q);
	//printf("cred len=0x%08X\n",strlen(str_cred));

	ptr=strstr(str_cred,"00000001");
	if (ptr==NULL){
		if (DEBUG_LEVEL>=100) printf("cred parsing error, no 00 00 00 01 sequence\n");
		return -1;
	};

	ptr=ptr+8;

	for(i=0;i<0x100;i++){
		hex_digit=convert_str_to_hex(ptr);
		//printf("hex_digit=0x%08X\n",hex_digit);		

		user_cred[i]=(char)hex_digit;

		ptr+=2;
	};
	
	//show_memory(user_cred,0x100,"cred bytes:");
	

	p_ptr=str_p;
	q_ptr=str_q;
	for (i = 0; i < 16; i++) {
		sscanf(p_ptr,"%x.", &p.w[i]);
		sscanf(q_ptr,"%x.", &q.w[i]);
		p_ptr+=9;
		q_ptr+=9;
	};


	p.w[15] |= 0x80000000, p.w[16] = 0;
	q.w[15] |= 0x80000000, q.w[16] = 0;

	//show_memory((char *)p.w,0x40,"p bytes:");
	//show_memory((char *)q.w,0x40,"q bytes:");

	
	return 0;
}



//
// restore pub/sec key
//
int restore_user_keypair (_MIPD_ u32 *secret_p, u32 *secret_q, char *public_key_bytes, char *secret_key_bytes) {
	struct bigtype		p = {16, secret_p}, q = {16, secret_q};
	
	u32 public_key[33];
	u32 secret_key[33];
	struct bigtype		y = {32, (unsigned int *)&public_key};
	struct bigtype		z = {32, (unsigned int *)&secret_key};

	u32					_w[2] = {0x10001, 0};
	struct bigtype		w = {1, _w};

	p.w[16] = 0;
	q.w[16] = 0;
	multiply(_MIPP_ &p, &q, &y);		// p*q = public key (not exactly, it's the common RSA modulus)
	decr (_MIPP_ &p, 1, &p);			// p-1
	decr (_MIPP_ &q, 1, &q);			// q-1
	multiply (_MIPP_ &p, &q, &z);		// z = (p-1)*(q-1)
	incr (_MIPP_ &p, 1, &p);			// p restored
	incr (_MIPP_ &q, 1, &q);			// q restored
	xgcd (_MIPP_ &w, &z, &z, &z, &z);	// z = 1/0x10001 mod (p-1)*(q-1), the secret exponent

	big_to_bytes(_MIPP_ 0x80,&y,public_key_bytes,TRUE);
	big_to_bytes(_MIPP_ 0x80,&z,secret_key_bytes,TRUE);


	return 0;
}
