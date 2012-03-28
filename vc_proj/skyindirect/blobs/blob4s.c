//
// session 3 pkt
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



int encode41_sess4pkt1_ack(char *globalptr, char *buf, int buf_limit_len){
	uint session_id;
	uint session_cmd;
	int buf_len;

	struct global_s *global;
	global=(struct global_s *)globalptr;

	session_id=0x01C7;
	session_cmd=0x47;

	memset(buf,0,sizeof(buf));
    buf_len=0;
    buf_len=make_41cmdencode(buf, buf_len, 0, session_id, session_cmd, 0);



	if ( buf_len > buf_limit_len ){
		if (DEBUG_LEVEL>=100) printf("buffer limit overrun\n");
		return -1;
	};

	return buf_len;

};


int encode41_sess4pkt2_ack(char *globalptr, char *buf, int buf_limit_len){
	uint session_id;
	uint session_cmd;
	int buf_len;

	struct global_s *global;
	global=(struct global_s *)globalptr;

	session_id=0x06EB;
	session_cmd=0x47;

	memset(buf,0,sizeof(buf));
    buf_len=0;
    buf_len=make_41cmdencode(buf, buf_len, 0, session_id, session_cmd, 0);



	if ( buf_len > buf_limit_len ){
		if (DEBUG_LEVEL>=100) printf("buffer limit overrun\n");
		return -1;
	};

	return buf_len;

};





int encode41_sess4pkt3_recurs2(char *globalptr, char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;
    

	struct global_s *global;
	global=(struct global_s *)globalptr;



	memset(buf,0,sizeof(buf));
    buf_len=0;

    buf_len=make_41cmdencode_recurs(buf, buf_len, 5, 0);



    // hz .. blob1
    blob.obj_type = 0;
	blob.obj_index = 0x0A;
	blob.obj_data = global->BLOB_0_A__1;
    //blob.obj_data = 0x3D98FDA1;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);
	

    // hz .. blob2
    blob.obj_type = 0;
	blob.obj_index = 0;
    blob.obj_data = 3;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);
	
    // hz .. blob3
    blob.obj_type = 0;
	blob.obj_index = 1;
    blob.obj_data = 1;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);
	
	// blob4 uic crc 
	// CRC of CREDENTIALS
    blob.obj_type = 0;
	blob.obj_index = 2;
    blob.obj_data = global->UIC_CRC;//0xEFE9B321;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);
	

    // hz .. blob5
    blob.obj_type = 4;
	blob.obj_index = 3;
    blob.obj_data = 0;
	blob.data_ptr = (int)global->NEWBLK;
	blob.data_size = global->NEWBLK_LEN;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);
	
	
	
	
	
	if ( buf_len > buf_limit_len ){
		if (DEBUG_LEVEL>=100) printf("buffer limit overrun\n");
		return -1;
	};

	return buf_len;
};




int encode41_sess4pkt3_recurs(char *globalptr, char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;
    
	char intbuf[0x1000];
	int intbuf_len;

	struct global_s *global;
	global=(struct global_s *)globalptr;


	memset(buf,0,sizeof(buf));
    buf_len=0;

    buf_len=make_41cmdencode_recurs(buf, buf_len, 2, 0);


    // hz .. blob1
    blob.obj_type = 0;
	blob.obj_index = 1;
    blob.obj_data = 0x2B;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);


    // blob2 recursive 41
	intbuf_len=encode41_sess4pkt3_recurs2(globalptr,intbuf,sizeof(intbuf));
	if (intbuf_len == -1) {	return -1;	};
	
    // blob2 
    blob.obj_type = 5;
	blob.obj_index = 0x20;
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






int encode41_sess4pkt3(char *globalptr, char *buf, int buf_limit_len){
	struct blob_s blob;
	uint session_id;
	uint session_cmd;
	int buf_len;

	char intbuf[0x1000];
	int intbuf_len;

	struct global_s *global;
	global=(struct global_s *)globalptr;


	session_id=0xA077;
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
    blob.obj_data = 4;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);


    // blob3 ALLOC1 recursive 41
	intbuf_len=encode41_sess4pkt3_recurs(globalptr,intbuf,sizeof(intbuf));
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







int encode41_sess4pkt4(char *globalptr, char *buf, int buf_limit_len){
	struct blob_s blob;
	uint session_id;
	uint session_cmd;
	int buf_len;

	struct global_s *global;
	global=(struct global_s *)globalptr;

	session_id=0xC3A0;
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
    blob.obj_data = 4;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // hz .. blob3
    blob.obj_type = 0;
	blob.obj_index = 8;
    blob.obj_data = 1;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);





	if ( buf_len > buf_limit_len ){
		if (DEBUG_LEVEL>=100) printf("buffer limit overrun\n");
		return -1;
	};

	return buf_len;

};




int encode41_sess4pkt5_ack(char *globalptr, char *buf, int buf_limit_len){
	uint session_id;
	uint session_cmd;
	int buf_len;

	struct global_s *global;
	global=(struct global_s *)globalptr;

	session_id=0x2A14;
	session_cmd=0x47;

	memset(buf,0,sizeof(buf));
    buf_len=0;
    buf_len=make_41cmdencode(buf, buf_len, 0, session_id, session_cmd, 0);



	if ( buf_len > buf_limit_len ){
		if (DEBUG_LEVEL>=100) printf("buffer limit overrun\n");
		return -1;
	};

	return buf_len;

};




/*

  session 4 pkt 4

==============================================
PKT:
==============================================
Session id:  0x0000C3A0 (50080)
Session cmd: 0x0000006D (109)
MAIN: size(0x0000003C)
00000000 00000001 55819F87 00000000 | 00000000 00000000 00000003 00000004 
00000000 00000000 00000000 00000008 | 00000001 00000000 00000000 

next bytes: 0x00000000 0x00000001 0x55819F87 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000001
data:       0x55819F87
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000000 0x00000003 0x00000004 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000003
data:       0x00000004
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000000 0x00000008 0x00000001 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000008
data:       0x00000001
data_ptr:   0x00000000 0x00000000



*/


/*

session 4 pkt 3
==============================================
PKT:
==============================================
Session id:  0x0000A077 (41079)
Session cmd: 0x0000006D (109)
MAIN: size(0x0000003C)
00000000 00000001 55819F87 00000000 | 00000000 00000000 00000003 00000004 
00000000 00000000 00000004 00000004 | 00000000 00320A60 000000AD 

next bytes: 0x00000000 0x00000001 0x55819F87 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000001
data:       0x55819F87
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000000 0x00000003 0x00000004 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000003
data:       0x00000004
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000004 0x00000004 0x00000000 0x00320A60 0x000000AD 
obj_type :  0x00000004
obj_index:  0x00000004
data:       0x00000000
data_ptr:   0xALLOC001 0x000000AD


ALLOCATED: 1 size(0x000000AD)
41020001 2B052041 05000AA1 FBE3EC03 | 00000300 01010002 A1E6A6FF 0E04038C 
0169CDFA 20F7BAB1 C2777C6B 2A36BD7C | FECE152E B6982FB6 30713165 19C57145 
17A39E5C 5C9BD076 37901E10 36783975 | 25B80897 ECD2D809 C660868C 5E878A68 
B0BCA07E 6EFDFA90 1B173EE6 9E6CC031 | 9DE11D6A FC944190 E878DC6B 3D34CD90 
A722546A FB88D6B4 2ED281DC DD62D88F | F1680F96 2A07CBBC 144A0765 D28A85C4 
E802686F 686F6165 65610032 D7000000 | 


====



MAIN PTR: 1
ALLOCATED: 1 size(0x00000010)
00953898 00000000 00000000 00000000 | 

MAIN PTR: 2
ALLOCATED: 2 size(0x0000008C)
69CDFA20 F7BAB1C2 777C6B2A 36BD7CFE | CE152EB6 982FB630 71316519 C5714517 
A39E5C5C 9BD07637 901E1036 78397525 | B80897EC D2D809C6 60868C5E 878A68B0 
BCA07E6E FDFA901B 173EE69E 6CC0319D | E11D6AFC 944190E8 78DC6B3D 34CD90A7 
22546AFB 88D6B42E D281DCDD 62D88FF1 | 680F962A 07CBBC14 4A0765D2 8A85C4E8 
02686F68 6F616565 610032D7 

MAIN OTHER: 1 size(0x00000280)
next bytes: 0x00000000 0x00000001 0x0000002B 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000001
data:       0x0000002B
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000005 0x00000020 0x00000000 0x00320A60 0x00000000 
obj_type :  0x00000005
obj_index:  0x00000020
data:       0x00000000
data_ptr:   0x00320A60 0x00000000


MAIN OTHER: 2 size(0x00000280)
next bytes: 0x00000000 0x0000000A 0x3D98FDA1 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x0000000A
data:       0x3D98FDA1
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000000 0x00000000 0x00000003 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000000
data:       0x00000003
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000000 0x00000001 0x00000001 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000001
data:       0x00000001
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000000 0x00000002 0xEFE9B321 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000002
data:       0xEFE9B321
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000004 0x00000003 0x00000000 0x003233B0 0x0000008C 
obj_type :  0x00000004
obj_index:  0x00000003
data:       0x00000000
data_ptr:   0x003233B0 0x0000008C


*/