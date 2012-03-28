//
// session 2 pkt
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


extern uint DEBUG_LEVEL;

int encode41_sess2pkt4(char *globalptr, char *buf, int buf_limit_len);
int encode41_sess2pkt4_recurs(char *globalptr, char *buf, int buf_limit_len);




int encode41_sess2pkt4(char *globalptr, char *buf, int buf_limit_len){
	struct blob_s blob;
	uint session_id;
	uint session_cmd;
	int buf_len;

	char intbuf[0x1000];
	int intbuf_len;

	struct global_s *global;
	global=(struct global_s *)globalptr;

	session_id=0xAA58;
	session_cmd=0x6D;

	memset(buf,0,sizeof(buf));
    buf_len=0;
    buf_len=make_41cmdencode(buf, buf_len, 3, session_id, session_cmd, 0);


    // hz .. blob1
    blob.obj_type = 0;
	blob.obj_index = 1;
    blob.obj_data = global->BLOB_0_1;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // hz .. blob2
    blob.obj_type = 0;
	blob.obj_index = 3;
    blob.obj_data = 1;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);


    // blob3 ALLOC1 recursive 41
	intbuf_len=encode41_sess2pkt4_recurs(globalptr,intbuf,sizeof(intbuf));
	if (intbuf_len == -1) {	return -1;	};

    blob.obj_type = 4;
	blob.obj_index = 0x04;
    blob.obj_data = 0;
	blob.data_ptr = (int)intbuf;
	blob.data_size = intbuf_len;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);



	if ( buf_len > buf_limit_len ){
		if (DEBUG_LEVEL>=100) printf("buffer limit overrun\n");
		return -1;
	};

	return buf_len;

};





int encode41_sess2pkt4_recurs(char *globalptr, char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;


	struct global_s *global;
	global=(struct global_s *)globalptr;


	memset(buf,0,sizeof(buf));
    buf_len=0;

    buf_len=make_41cmdencode_recurs(buf, buf_len, 9, 0);

	
    // hz .. blob1 
    blob.obj_type = 0;
	blob.obj_index = 1;
    blob.obj_data = 0x2A;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);
	
    // hz .. blob11 
    blob.obj_type = 0;
	blob.obj_index = 0;
    blob.obj_data = 0x0164;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // hz .. blob2
    blob.obj_type = 0;
	blob.obj_index = 1;
    blob.obj_data = 1;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // hz .. blob3
    blob.obj_type = 0;
	blob.obj_index = 2;
    //blob.obj_data = global->BLOB_0_2__1;
    blob.obj_data = 0x05147C5E;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);
	
    // blob4 newblk...
    blob.obj_type = 4;
	blob.obj_index = 3;
    blob.obj_data = 0;
	blob.data_ptr = (int)global->NEWBLK;
	blob.data_size = global->NEWBLK_LEN;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);
	
    // blob5 credentials
    blob.obj_type = 4;
	blob.obj_index = 4;
    blob.obj_data = 0;
	blob.data_ptr = (int)global->CREDENTIALS;
	blob.data_size = global->CREDENTIALS_LEN;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);
	
    // hz .. 
    blob.obj_type = 0;
	blob.obj_index = 6;
    blob.obj_data = 0x1;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // hz .. credential crc
    blob.obj_type = 0;
	blob.obj_index = 7;
    //blob.obj_data = 0xCE2395AD;
	blob.obj_data = global->UIC_CRC;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // hz .. 
    blob.obj_type = 0;
	blob.obj_index = 9;
    blob.obj_data = 0x0140B905;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);
	
	if ( buf_len > buf_limit_len ){
		if (DEBUG_LEVEL>=100) printf("buffer limit overrun\n");
		return -1;
	};

	return buf_len;
};
