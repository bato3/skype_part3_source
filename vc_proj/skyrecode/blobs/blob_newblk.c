//
// session newblk
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




int encode41_newblk2(char *globalptr, char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;
	u8 str_null[]="";

	struct global_s *global;
	global=(struct global_s *)globalptr;

	memset(buf,0,sizeof(buf));
    buf_len=0;

    buf_len=make_41cmdencode_recurs(buf, buf_len, 8, 0);


    // hz .. blob1
    blob.obj_type = 0;
	blob.obj_index = 0;
    blob.obj_data = 4;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // hz .. blob2
    blob.obj_type = 4;
	blob.obj_index = 3;
    blob.obj_data = 0;
	blob.data_ptr = (int)global->INIT_UNK;
	blob.data_size = sizeof(global->INIT_UNK)-1;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // hz .. blob3
    blob.obj_type = 0;
	blob.obj_index = 5;
	blob.obj_data = global->BLOB_0_5;
    //blob.obj_data = 0x49D079E2;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // hz .. blob4
    blob.obj_type = 0;
	blob.obj_index = 6;
	blob.obj_data = global->BLOB_0_6;
    //blob.obj_data = 0x013AF0D7;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// hz .. blob5
    blob.obj_type = 0;
	blob.obj_index = 7;
	blob.obj_data = global->BLOB_0_7__3;
    //blob.obj_data = 0x3D98FD9F; //0x3D98FDA0-1
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// hz .. blob6
    blob.obj_type = 3;
	blob.obj_index = 0x0E;
    blob.obj_data = 0;
	blob.data_ptr = (int)str_null;
	blob.data_size = strlen(str_null)+1;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// hz .. blob7
    blob.obj_type = 0;
	blob.obj_index = 0x0F;
    blob.obj_data = 0;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// hz .. blob8
    blob.obj_type = 0;
	blob.obj_index = 0x0A;
	blob.obj_data = global->BLOB_0_A__3;
    //blob.obj_data = 0x4208B69D;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	


	if ( buf_len > buf_limit_len ){
		if (DEBUG_LEVEL>=100) printf("buffer limit overrun\n");
		return -1;
	};

	return buf_len;

};



int encode41_newblk3(char *globalptr, char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;

	struct global_s *global;
	global=(struct global_s *)globalptr;


	memset(buf,0,sizeof(buf));
    buf_len=0;

    buf_len=make_41cmdencode_recurs(buf, buf_len, 6, 0);


    // hz .. blob1
    blob.obj_type = 0;
	blob.obj_index = 0;
    blob.obj_data = 3;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // hz .. blob2
    blob.obj_type = 4;
	blob.obj_index = 3;
    blob.obj_data = 0;
	blob.data_ptr = (int)global->INIT_UNK;
	blob.data_size = sizeof(global->INIT_UNK)-1;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // blob3, // timestampt !
    blob.obj_type = 0;
	blob.obj_index = 5;
	blob.obj_data = global->BLOB_0_5__1;
    //blob.obj_data = 0x49D079E7; //0x49D079E2 - before was. timestamp !
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // hz .. blob4
    blob.obj_type = 0;
	blob.obj_index = 6;
	blob.obj_data = global->BLOB_0_6;
    //blob.obj_data = 0x013AF0D7;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// hz .. blob5
    blob.obj_type = 0;
	blob.obj_index = 7;
	blob.obj_data = global->BLOB_0_7__4;
    //blob.obj_data = 0x3D98FDA1;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	// hz .. blob6
    blob.obj_type = 3;
	blob.obj_index = 2;
    blob.obj_data = 0;
	blob.data_ptr = (int)global->MSG_TEXT;
	blob.data_size = strlen(global->MSG_TEXT)+1;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);


	


	if ( buf_len > buf_limit_len ){
		if (DEBUG_LEVEL>=100) printf("buffer limit overrun\n");
		return -1;
	};

	return buf_len;

};



/*

  newblk3


  "\x41\x06\x00\x00\x03\x04\x03"
"\x15\x75\x4E\xCB\x75\x38\x34\xFA\x8E\x01\xC0\xA8\x01\x28\x81\xA5"
"\x43\xA3\x14\xA9\xEF\x08\x00\x05\xE7\xF3\xC1\xCE\x04\x00\x06\xD7"
"\xE1\xEB\x09\x00\x07\xA1\xFB\xE3\xEC\x03\x03"
"\x02\x50\x6C\x65\x61\x73\x65\x20\x76\x69\x73\x69\x74\x20\x6F\x72"
"\x20\x73\x69\x74\x65\x20\x68\x65\x72\x65\x3A\x20\x77\x77\x77\x2E"
"\x72\x65\x2E\x6F\x72\x67\x0A\x00"
;


==============================================
PKT:
==============================================
Session id:  0x000013D3 (5075)
Session cmd: 0x0000006D (109)
MAIN: size(0x00000078)
00000000 00000000 00000003 00000000 | 00000000 00000004 00000003 00000000 
00320A60 00000015 00000000 00000005 | 49D079E7 00000000 00000000 00000000 
00000006 013AF0D7 00000000 00000000 | 00000000 00000007 3D98FDA1 00000000 
00000000 00000003 00000002 00000000 | 00320AA8 00000027 

next bytes: 0x00000000 0x00000000 0x00000003 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000000
data:       0x00000003
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000004 0x00000003 0x00000000 0x00320A60 0x00000015 
obj_type :  0x00000004
obj_index:  0x00000003
data:       0x00000000
data_ptr:   0xALLOC001 0x00000015

next bytes: 0x00000000 0x00000005 0x49D079E7 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000005
data:       0x49D079E7
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000000 0x00000006 0x013AF0D7 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000006
data:       0x013AF0D7
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000000 0x00000007 0x3D98FDA1 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000007
data:       0x3D98FDA1
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000003 0x00000002 0x00000000 0x00320AA8 0x00000027 
obj_type :  0x00000003
obj_index:  0x00000002
data:       0x00000000
data_ptr:   0xALLOC002 0x00000027


MAIN PTR: 1
ALLOCATED: 1 size(0x00000015)
754ECB75 3834FA8E 01C0A801 2881A543 | A314A9EF 8000000 

MAIN PTR: 1
ALLOCATED: 2 size(0x00000027)
506C6561 73652076 69736974 206F7220 | 73697465 20686572 653A2077 77772E72 
652E6F72 670A0000 



*/




/*
newblk2

"\x41\x08\x00\x00\x04\x04\x03"
"\x15\x75\x4E\xCB\x75\x38\x34\xFA\x8E\x01\xC0\xA8\x01\x28\x81\xA5"
"\x43\xA3\x14\xA9\xEF\x08\x00\x05\xE2\xF3\xC1\xCE\x04\x00\x06\xD7"
"\xE1\xEB\x09\x00\x07\x9F\xFB\xE3\xEC\x03\x03"
"\x0E\x00\x00\x0F\x00\x00\x0A\x9D\xED\xA2\x90\x04"
;


==============================================
PKT:
==============================================
Session id:  0x000013D3 (5075)
Session cmd: 0x0000006D (109)
MAIN: size(0x000000A0)
00000000 00000000 00000004 00000000 | 00000000 00000004 00000003 00000000 
00320A60 00000015 00000000 00000005 | 49D079E2 00000000 00000000 00000000 
00000006 013AF0D7 00000000 00000000 | 00000000 00000007 3D98FD9F 00000000 
00000000 00000003 0000000E 00000000 | 00320AA8 00000001 00000000 0000000F 
00000000 00000000 00000000 00000000 | 0000000A 4208B69D 00000000 00000000 

next bytes: 0x00000000 0x00000000 0x00000004 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000000
data:       0x00000004
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000004 0x00000003 0x00000000 0x00320A60 0x00000015 
obj_type :  0x00000004
obj_index:  0x00000003
data:       0x00000000
data_ptr:   0xALLOC001 0x00000015

next bytes: 0x00000000 0x00000005 0x49D079E2 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000005
data:       0x49D079E2
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000000 0x00000006 0x013AF0D7 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000006
data:       0x013AF0D7
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000000 0x00000007 0x3D98FD9F 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000007
data:       0x3D98FD9F
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000003 0x0000000E 0x00000000 0x00320AA8 0x00000001 
obj_type :  0x00000003
obj_index:  0x0000000E
data:       0x00000000
data_ptr:   0xALLOC002 0x00000001

next bytes: 0x00000000 0x0000000F 0x00000000 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x0000000F
data:       0x00000000
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000000 0x0000000A 0x4208B69D 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x0000000A
data:       0x4208B69D
data_ptr:   0x00000000 0x00000000


MAIN PTR: 1
ALLOCATED: 1 size(0x00000015)
754ECB75 3834FA8E 01C0A801 2881A543 | A314A9EF 8000000 

MAIN PTR: 1
ALLOCATED: 2 size(0x00000001)
00 


*/








/*

  newblk1 

"\x41\x08\x00\x00\x01\x04\x03"
"\x15\x75\x4E\xCB\x75\x38\x34\xFA\x8E\x01\xC0\xA8\x01\x28\x81\xA5"
"\x43\xA3\x14\xA9\xEF\x08\x00\x05\xE2\xF3\xC1\xCE\x04\x00\x06\xD7"
"\xE1\xEB\x09\x00\x07\xA0\xFB\xE3\xEC\x03\x03"
"\x01\x78\x6F\x74\x5F\x69\x61\x6D\x00\x00\x0A\xAA\xEE\xF5\x46\x00"
"\x0B\x01"
;


==============================================
PKT:
==============================================
Session id:  0x000013D3 (5075)
Session cmd: 0x0000006D (109)
MAIN: size(0x000000A0)
00000000 00000000 00000001 00000000 | 00000000 00000004 00000003 00000000 
00320A60 00000015 00000000 00000005 | 49D079E2 00000000 00000000 00000000 
00000006 013AF0D7 00000000 00000000 | 00000000 00000007 3D98FDA0 00000000 
00000000 00000003 00000001 00000000 | 00320AA8 00000008 00000000 0000000A 
08DD772A 00000000 00000000 00000000 | 0000000B 00000001 00000000 00000000 

next bytes: 0x00000000 0x00000000 0x00000001 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000000
data:       0x00000001
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000004 0x00000003 0x00000000 0x00320A60 0x00000015 
obj_type :  0x00000004
obj_index:  0x00000003
data:       0x00000000
data_ptr:   0xALLOC001 0x00000015

next bytes: 0x00000000 0x00000005 0x49D079E2 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000005
data:       0x49D079E2
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000000 0x00000006 0x013AF0D7 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000006
data:       0x013AF0D7
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000000 0x00000007 0x3D98FDA0 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000007
data:       0x3D98FDA0
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000003 0x00000001 0x00000000 0x00320AA8 0x00000008 
obj_type :  0x00000003
obj_index:  0x00000001
data:       0x00000000
data_ptr:   0xALLOC002 0x00000008

next bytes: 0x00000000 0x0000000A 0x08DD772A 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x0000000A
data:       0x08DD772A
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000000 0x0000000B 0x00000001 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x0000000B
data:       0x00000001
data_ptr:   0x00000000 0x00000000


MAIN PTR: 1
ALLOCATED: 1 size(0x00000015)
754ECB75 3834FA8E 01C0A801 2881A543 | A314A9EF 8000000 

MAIN PTR: 1
ALLOCATED: 2 size(0x00000008)
786F745F 69616D00 



*/