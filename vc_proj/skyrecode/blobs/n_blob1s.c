// n_blob1s.c
//


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../decode41.h"

#include "../global_vars.h"

extern int show_memory(char *mem, int len, char *text);
extern int set_packet_size(char *a1, int c);
extern int encode_to_7bit(char *buf, uint word, uint limit);

extern int make_41cmdencode_recurs(char *buf, int buf_len, uint blob_count, int dodebug);
extern int make_41cmdencode(char *buf, int buf_len, uint blob_count, uint session_id, uint session_cmd, int dodebug);
extern int make_41encode(char *buf, int buf_len, char *blobptr, int dodebug);



extern int main_unpack_sync_first(u8 *buf, int buf_len, u8 *chatstr, uint blob_sid);
extern int main_unpack_sync_confirm(u8 *buf, int buf_len, int seq, uint blob_sid);

extern int main_unpack_sync_24(u8 *buf, int buf_len);
extern int main_unpack_sync_27(u8 *buf, int buf_len);


extern uint DEBUG_LEVEL;

int make_41cmdencode2(char *buf, int buf_len, uint session_id, uint session_cmd, int dodebug){
	int len;


	// encode sess_id to 7bit
	len=encode_to_7bit(buf+buf_len,session_id,10);
	buf_len=buf_len+len;

	// one byte of session cmd
	buf[buf_len]=session_cmd & 0xff;
	buf_len++;

	if (dodebug){
		show_memory(buf, buf_len, "blob header:");
	};

	return buf_len;

};



int encode41_sess1pkt1_first(char *globalptr, char *buf, int buf_limit_len){
	uint session_id;
	uint session_cmd;
	int buf_len;
	u8 *chatstr;
	uint blob_sid;
	
	struct global_s *global;
	global=(struct global_s *)globalptr;


	session_id=0x6406;
	session_cmd=0x6D;

	memset(buf,0,sizeof(buf));
    buf_len=0;
    buf_len=make_41cmdencode2(buf, buf_len, session_id, session_cmd, 0);

	chatstr=global->CHAT_STRING;
	blob_sid=global->BLOB_0_1;

	buf_len=main_unpack_sync_first(buf,buf_len,chatstr,blob_sid);

	if (buf_len > buf_limit_len) {
		printf("buf error !\n");
		printf("buflen:%d !\n",buf_len);
		printf("buf limit len:%d !\n",buf_limit_len);
		return -1;
	};




	return buf_len; 

};

///////////////////////////////////////////////////////////////////////////////////////


//
// pkt confirm
//
int encode41_sess2pkt_confirm(char *globalptr, char *buf, int buf_limit_len, int seq){
	uint session_id;
	uint session_cmd;
	int buf_len;
	uint blob_sid;
	
	struct global_s *global;
	global=(struct global_s *)globalptr;


	session_id=0x6406;
	session_cmd=0x6D;

	memset(buf,0,sizeof(buf));
    buf_len=0;
    buf_len=make_41cmdencode2(buf, buf_len, session_id, session_cmd, 0);

	blob_sid=global->BLOB_0_1;

	buf_len=main_unpack_sync_confirm(buf,buf_len,seq,blob_sid);

	if (buf_len > buf_limit_len) {
		printf("buf error !\n");
		printf("buflen:%d !\n",buf_len);
		printf("buf limit len:%d !\n",buf_limit_len);
		return -1;
	};




	return buf_len;

};


///////////////////////////////////////////////////////////////////////////////////////




//
// pkt7
//
int encode41_sess2pkt7(char *globalptr, char *buf, int buf_limit_len){
	uint session_id;
	uint session_cmd;
	int buf_len;
	
	struct global_s *global;
	global=(struct global_s *)globalptr;


	session_id=0x6406;
	session_cmd=0x6D;

	memset(buf,0,sizeof(buf));
    buf_len=0;
    buf_len=make_41cmdencode2(buf, buf_len, session_id, session_cmd, 0);


	buf_len=main_unpack_sync_27(buf,buf_len);

	if (buf_len > buf_limit_len) {
		printf("buf error !\n");
		printf("buflen:%d !\n",buf_len);
		printf("buf limit len:%d !\n",buf_limit_len);
		return -1;
	};




	return buf_len;

};
