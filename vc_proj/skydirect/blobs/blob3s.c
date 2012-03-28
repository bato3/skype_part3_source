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


int encode41_sess3pkt1_ack(char *globalptr, char *buf, int buf_limit_len){
	uint session_id;
	uint session_cmd;
	int buf_len;


	struct global_s *global;
	global=(struct global_s *)globalptr;

	session_id=0xAE;
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



int encode41_sess3pkt2(char *globalptr, char *buf, int buf_limit_len){
	struct blob_s blob;
	uint session_id;
	uint session_cmd;
	int buf_len;

	struct global_s *global;
	global=(struct global_s *)globalptr;

	session_id=0xF0AA;
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



int encode41_sess3pkt3_ack(char *globalptr, char *buf, int buf_limit_len){
	uint session_id;
	uint session_cmd;
	int buf_len;

	struct global_s *global;
	global=(struct global_s *)globalptr;

	session_id=0xF4;
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



int encode41_sess3pkt4_recurs3(char *globalptr, char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;

	struct global_s *global;
	global=(struct global_s *)globalptr;


	memset(buf,0,sizeof(buf));
    buf_len=0;

    buf_len=make_41cmdencode_recurs(buf, buf_len, 5, 0);



	
    // hz .. blob1 
    blob.obj_type = 0;
	blob.obj_index = 0;
    blob.obj_data = 9;
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
	blob.obj_data = global->BLOB_0_2__1;
    //blob.obj_data = 0xE9C150A9;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);


    // blob4  newblk
    blob.obj_type = 4;
	blob.obj_index = 3;
    blob.obj_data = 0;
	blob.data_ptr = (int)global->NEWBLK;
	blob.data_size = global->NEWBLK_LEN;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	
    // blob5  credentials
    blob.obj_type = 4;
	blob.obj_index = 4;
    blob.obj_data = 0;
	blob.data_ptr = (int)global->CREDENTIALS;
	blob.data_size = global->CREDENTIALS_LEN;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	
	
	
	if ( buf_len > buf_limit_len ){
		if (DEBUG_LEVEL>=100) printf("buffer limit overrun\n");
		return -1;
	};

	return buf_len;
};






int encode41_sess3pkt4_recurs2(char *globalptr, char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;
    
	char intbuf[0x1000];
	int intbuf_len;

	struct global_s *global;
	global=(struct global_s *)globalptr;


	memset(buf,0,sizeof(buf));
    buf_len=0;

    buf_len=make_41cmdencode_recurs(buf, buf_len, 4, 0);



    // blob1 recursive 41
	intbuf_len=encode41_sess3pkt4_recurs3(globalptr,intbuf,sizeof(intbuf));
	if (intbuf_len == -1) {	return -1;	};
	
    // blob1 
    blob.obj_type = 5;
	blob.obj_index = 2;
    blob.obj_data = 0;
	blob.data_ptr = (int)intbuf;
	blob.data_size = intbuf_len;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);


    // hz .. blob2
    blob.obj_type = 0;
	blob.obj_index = 6;
    blob.obj_data = 1;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);
	

    // hz .. blob3
    blob.obj_type = 0;
	blob.obj_index = 7;
	blob.obj_data = global->BLOB_0_7__1;
    //blob.obj_data = 0x4208B69D;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);
	

    // hz .. blob4
    blob.obj_type = 0;
	blob.obj_index = 9;
	blob.obj_data = global->BLOB_0_9;
    //blob.obj_data = 0x013AF0D7;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);
	
	
	
	
	
	if ( buf_len > buf_limit_len ){
		if (DEBUG_LEVEL>=100) printf("buffer limit overrun\n");
		return -1;
	};

	return buf_len;
};




int encode41_sess3pkt4_recurs(char *globalptr, char *buf, int buf_limit_len){
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
    blob.obj_data = 0x2A;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);


    // blob2 recursive 41
	intbuf_len=encode41_sess3pkt4_recurs2(globalptr,intbuf,sizeof(intbuf));
	if (intbuf_len == -1) {	return -1;	};
	
    // blob2 
    blob.obj_type = 5;
	blob.obj_index = 0x18;
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






int encode41_sess3pkt4(char *globalptr, char *buf, int buf_limit_len){
	struct blob_s blob;
	uint session_id;
	uint session_cmd;
	int buf_len;

	char intbuf[0x1000];
	int intbuf_len;

	struct global_s *global;
	global=(struct global_s *)globalptr;


	session_id=0x13D3;
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
    blob.obj_data = 2;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);


    // blob3 ALLOC1 recursive 41
	intbuf_len=encode41_sess3pkt4_recurs(globalptr,intbuf,sizeof(intbuf));
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




int encode41_sess3pkt5(char *globalptr, char *buf, int buf_limit_len){
	struct blob_s blob;
	uint session_id;
	uint session_cmd;
	int buf_len;

	struct global_s *global;
	global=(struct global_s *)globalptr;

	session_id=0x36FC;
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
    blob.obj_data = 2;
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




int encode41_sess3pkt6_ack(char *globalptr, char *buf, int buf_limit_len){
	uint session_id;
	uint session_cmd;
	int buf_len;

	struct global_s *global;
	global=(struct global_s *)globalptr;

	session_id=0x013A;
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

///////////////////////////////////////////////////////////////////


int encode41_sess3pkt7_recurs21(char *globalptr, char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;
    

	struct global_s *global;
	global=(struct global_s *)globalptr;

	memset(buf,0,sizeof(buf));
    buf_len=0;

    buf_len=make_41cmdencode_recurs(buf, buf_len, 3, 0);


    // hz .. blob1
    blob.obj_type = 0;
	blob.obj_index = 9;
	blob.obj_data = global->BLOB_0_9__1;
    //blob.obj_data = 0x3D98FDA0;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);
	

    // hz .. blob2
    blob.obj_type = 0;
	blob.obj_index = 0x0A;
	blob.obj_data = global->BLOB_0_A;
    //blob.obj_data = 0x3D98FDA0;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);
	

    // hz .. blob3
    blob.obj_type = 0;
	blob.obj_index = 0x15;
	blob.obj_data = global->BLOB_0_15;
    //blob.obj_data = 0x718CDD7C;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);
	
	
	
	if ( buf_len > buf_limit_len ){
		if (DEBUG_LEVEL>=100) printf("buffer limit overrun\n");
		return -1;
	};

	return buf_len;
};



int encode41_sess3pkt7_recurs22(char *globalptr, char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;
    

	struct global_s *global;
	global=(struct global_s *)globalptr;

	memset(buf,0,sizeof(buf));
    buf_len=0;

    buf_len=make_41cmdencode_recurs(buf, buf_len, 3, 0);


    // hz .. blob1
    blob.obj_type = 0;
	blob.obj_index = 9;
	blob.obj_data = global->BLOB_0_9__2;
    //blob.obj_data = 0x3D98FDA1;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);
	

    // hz .. blob2
    blob.obj_type = 0;
	blob.obj_index = 0x0A;
	blob.obj_data = global->BLOB_0_A__1;
    //blob.obj_data = 0x3D98FDA1;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);
	

    // hz .. blob3
    blob.obj_type = 0;
	blob.obj_index = 0x15;
	blob.obj_data = global->BLOB_0_15__1;
    //blob.obj_data = 0xA29916E7;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);
	
	
	
	if ( buf_len > buf_limit_len ){
		if (DEBUG_LEVEL>=100) printf("buffer limit overrun\n");
		return -1;
	};

	return buf_len;
};





int encode41_sess3pkt7_recurs23(char *globalptr, char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;
    

	struct global_s *global;
	global=(struct global_s *)globalptr;

	memset(buf,0,sizeof(buf));
    buf_len=0;

    buf_len=make_41cmdencode_recurs(buf, buf_len, 1, 0);


    // hz .. blob1
    blob.obj_type = 0;
	blob.obj_index = 2;
    blob.obj_data = 2;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	
	
	if ( buf_len > buf_limit_len ){
		if (DEBUG_LEVEL>=100) printf("buffer limit overrun\n");
		return -1;
	};

	return buf_len;
};







int encode41_sess3pkt7_recurs(char *globalptr, char *buf, int buf_limit_len){
	struct blob_s blob;
	int buf_len;
    
	char intbuf[0x1000];
	int intbuf_len;

	struct global_s *global;
	global=(struct global_s *)globalptr;

    //u8 peers[]="xot_iam xoteg_iam";

	memset(buf,0,sizeof(buf));
    buf_len=0;

    buf_len=make_41cmdencode_recurs(buf, buf_len, 6, 0);


    // hz .. blob1
    blob.obj_type = 0;
	blob.obj_index = 1;
    blob.obj_data = 0x13;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

    // hz .. blob2
    blob.obj_type = 0;
	blob.obj_index = 0x0F;
	blob.obj_data = global->BLOB_0_F;
    //blob.obj_data = 0x3D98FDA0;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);


    // blob3 recursive 41
	intbuf_len=encode41_sess3pkt7_recurs21(globalptr,intbuf,sizeof(intbuf));
	if (intbuf_len == -1) {	return -1;	};
    
	// blob3 
    blob.obj_type = 5;
	blob.obj_index = 0x14;
    blob.obj_data = 0;
	blob.data_ptr = (int)intbuf;
	blob.data_size = intbuf_len;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);	

	
    // blob4 recursive 41
	intbuf_len=encode41_sess3pkt7_recurs22(globalptr,intbuf,sizeof(intbuf));
	if (intbuf_len == -1) {	return -1;	};
    
	// blob4 
    blob.obj_type = 5;
	blob.obj_index = 0x14;
    blob.obj_data = 0;
	blob.data_ptr = (int)intbuf;
	blob.data_size = intbuf_len;
    
	buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);	


    // hz .. blob5
    blob.obj_type = 3;
	blob.obj_index = 0x12;
    blob.obj_data = 0;
	blob.data_ptr = (int)global->CHAT_PEERS;
	blob.data_size = strlen(global->CHAT_PEERS)+1;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);

	
    // blob6 recursive 41
	intbuf_len=encode41_sess3pkt7_recurs23(globalptr,intbuf,sizeof(intbuf));
	if (intbuf_len == -1) {	return -1;	};
    
	// blob6 
    blob.obj_type = 5;
	blob.obj_index = 0x2F;
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






int encode41_sess3pkt7(char *globalptr, char *buf, int buf_limit_len){
	struct blob_s blob;
	uint session_id;
	uint session_cmd;
	int buf_len;

	char intbuf[0x1000];
	int intbuf_len;

	struct global_s *global;
	global=(struct global_s *)globalptr;


	session_id=0x5A25;
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
    blob.obj_data = 3;
	blob.data_ptr = 0;
	blob.data_size = 0;

    buf_len=make_41encode(buf,buf_len,(char *)&blob, 0);


    // blob3 ALLOC1 recursive 41
	intbuf_len=encode41_sess3pkt7_recurs(globalptr,intbuf,sizeof(intbuf));
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



/////////////////////////////////////////////



int encode41_sess3pkt8(char *globalptr, char *buf, int buf_limit_len){
	struct blob_s blob;
	uint session_id;
	uint session_cmd;
	int buf_len;

	struct global_s *global;
	global=(struct global_s *)globalptr;

	session_id=0x7D4E;
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
    blob.obj_data = 3;
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





int encode41_sess3pkt9_ack(char *globalptr, char *buf, int buf_limit_len){
	uint session_id;
	uint session_cmd;
	int buf_len;

	struct global_s *global;
	global=(struct global_s *)globalptr;

	session_id=0x0181;
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

session 3 pk 8
==============================================
PKT:
==============================================
Session id:  0x00007D4E (32078)
Session cmd: 0x0000006D (109)
MAIN: size(0x0000003C)
00000000 00000001 55819F87 00000000 | 00000000 00000000 00000003 00000003 
00000000 00000000 00000000 00000008 | 00000001 00000000 00000000 

next bytes: 0x00000000 0x00000001 0x55819F87 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000001
data:       0x55819F87
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000000 0x00000003 0x00000003 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000003
data:       0x00000003
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000000 0x00000008 0x00000001 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000008
data:       0x00000001
data_ptr:   0x00000000 0x00000000


*/



/*
sess 3 pkt 7


==============================================
PKT:
==============================================
Session id:  0x00005A25 (23077)
Session cmd: 0x0000006D (109)
MAIN: size(0x0000003C)
00000000 00000001 55819F87 00000000 | 00000000 00000000 00000003 00000003 
00000000 00000000 00000004 00000004 | 00000000 00320A60 00000059 

next bytes: 0x00000000 0x00000001 0x55819F87 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000001
data:       0x55819F87
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000000 0x00000003 0x00000003 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000003
data:       0x00000003
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000004 0x00000004 0x00000000 0x00320A60 0x00000059 
obj_type :  0x00000004
obj_index:  0x00000004
data:       0x00000000
data_ptr:   0xALLOC001 0x00000059


ALLOCATED: 1 size(0x00000059)
41060001 13000FA0 FBE3EC03 05144103 | 0009A0FB E3EC0300 0AA0FBE3 EC030015 
FCBAB38C 07051441 030009A1 FBE3EC03 | 000AA1FB E3EC0300 15E7ADE4 940A0312 
786F745F 69616D20 786F7465 675F6961 | 6D00052F 41010002 2000000 





MAIN PTR: 1
ALLOCATED: 1 size(0x00000010)
00953898 00000000 00000000 00000000 | 

MAIN PTR: 1
ALLOCATED: 2 size(0x00000010)
00953898 00000000 00000000 00000000 | 

MAIN PTR: 1
ALLOCATED: 3 size(0x00000012)
786F745F 69616D20 786F7465 675F6961 | 6D000000 

MAIN PTR: 1
ALLOCATED: 4 size(0x00000010)
00953898 00000000 00000000 00000000 | 

MAIN OTHER: 1 size(0x00000280)
next bytes: 0x00000000 0x00000001 0x00000013 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000001
data:       0x00000013
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000000 0x0000000F 0x3D98FDA0 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x0000000F
data:       0x3D98FDA0
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000005 0x00000014 0x00000000 0x00320A60 0x00000000 
obj_type :  0x00000005
obj_index:  0x00000014
data:       0x00000000
data_ptr:   0x00320A60 0x00000000

next bytes: 0x00000005 0x00000014 0x00000000 0x00323360 0x00000000 
obj_type :  0x00000005
obj_index:  0x00000014
data:       0x00000000
data_ptr:   0x00323360 0x00000000

next bytes: 0x00000003 0x00000012 0x00000000 0x00323660 0x00000012 
obj_type :  0x00000003
obj_index:  0x00000012
data:       0x00000000
data_ptr:   0x00323660 0x00000012

next bytes: 0x00000005 0x0000002F 0x00000000 0x003236A8 0x00000000 
obj_type :  0x00000005
obj_index:  0x0000002F
data:       0x00000000
data_ptr:   0x003236A8 0x00000000


MAIN OTHER: 2 size(0x00000078)
next bytes: 0x00000000 0x00000009 0x3D98FDA0 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000009
data:       0x3D98FDA0
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000000 0x0000000A 0x3D98FDA0 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x0000000A
data:       0x3D98FDA0
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000000 0x00000015 0x718CDD7C 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000015
data:       0x718CDD7C
data_ptr:   0x00000000 0x00000000


MAIN OTHER: 3 size(0x0000008C)
next bytes: 0x00000000 0x00000009 0x3D98FDA1 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000009
data:       0x3D98FDA1
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000000 0x0000000A 0x3D98FDA1 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x0000000A
data:       0x3D98FDA1
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000000 0x00000015 0xA29916E7 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000015
data:       0xA29916E7
data_ptr:   0x00000000 0x00000000


MAIN OTHER: 4 size(0x00000280)
next bytes: 0x00000000 0x00000002 0x00000002 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000002
data:       0x00000002
data_ptr:   0x00000000 0x00000000





*/







/*
  sess 3 pkt 4

==============================================
PKT:
==============================================
Session id:  0x000036FC (14076)
Session cmd: 0x0000006D (109)
MAIN: size(0x0000003C)
00000000 00000001 55819F87 00000000 | 00000000 00000000 00000003 00000002 
00000000 00000000 00000000 00000008 | 00000001 00000000 00000000 

next bytes: 0x00000000 0x00000001 0x55819F87 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000001
data:       0x55819F87
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000000 0x00000003 0x00000002 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000003
data:       0x00000002
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000000 0x00000008 0x00000001 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000008
data:       0x00000001
data_ptr:   0x00000000 0x00000000

*/







/*


MAIN PTR: 1
ALLOCATED: 1 size(0x00000010)
00953898 00000000 00000000 00000000 | 

MAIN PTR: 2
ALLOCATED: 2 size(0x00000010)
00953898 00000000 00000000 00000000 | 

MAIN PTR: 3
ALLOCATED: 3 size(0x0000008C)
580A58FB F6A21DD5 409216F6 48054420 | 662DB22A 4E0EC8D7 B9D520E2 0F4835E4 
B30500D0 503BC12C 5C66A44D E6C36C75 | 3594C039 38A2561E 8ACBAB67 016D1E70 
72FD861F FFACF5F0 8472068E 301D8E10 | 97948B4D CC5E00FE 0BD9C271 64639808 
986A69E0 F2F9F7B0 426A3C5C 20805B14 | 4C4E0D8C 2C8C97D0 7EF4CBEE BFD442A5 
0E00000F 00000A9D EDA29004 

MAIN PTR: 3
ALLOCATED: 4 size(0x00000104)
00000001 9A1247C4 422535E2 D528A73E | 8C2B3E28 26631055 3FA315DB 93D7D3A5 
C44B44EB E0AEB979 E5CF3ABE 8FA1D571 | 94D2E8E4 0E526DA3 7BDBE49E 2C9E1843 
3807F350 358E430A 7E69F03D 09267F7E | 92B3E43B 173D2480 50782D52 E4CE8185 
3EA33BEC 1532F85B 228004D3 CDFA5BC6 | 9734BEB7 67C6CD79 476A6B99 A3F6689C 
1E471AA9 43162EB9 3EA484AA CA0ACF97 | 5D660959 FAEB9C7D 6DC05B53 CF57C390 
C4A9FECA EA7584C9 0D649D14 8C33A680 | 094B865E D815BBEE A0DA4B03 470BD2A2 
97AF3229 949E71B1 8CCB276D 84447825 | 2781D0C3 A2DD9A89 4C4F9147 258349DE 
9A47D051 7F222BDB FDA5FF2C 6FFDBCC6 | 95E589A2 D0038C2C 249A2EFE CBA19F69 
64B21059 

MAIN OTHER: 1 size(0x0000003C)
next bytes: 0x00000000 0x00000001 0x0000002A 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000001
data:       0x0000002A
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000005 0x00000018 0x00000000 0x00320A60 0x00000000 
obj_type :  0x00000005
obj_index:  0x00000018
data:       0x00000000
data_ptr:   0x00320A60 0x00000000


MAIN OTHER: 2 size(0x000000A0)
next bytes: 0x00000005 0x00000002 0x00000000 0x00323360 0x00000000 
obj_type :  0x00000005
obj_index:  0x00000002
data:       0x00000000
data_ptr:   0x00323360 0x00000000

next bytes: 0x00000000 0x00000006 0x00000001 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000006
data:       0x00000001
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000000 0x00000007 0x4208B69D 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000007
data:       0x4208B69D
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000000 0x00000009 0x013AF0D7 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000009
data:       0x013AF0D7
data_ptr:   0x00000000 0x00000000


MAIN OTHER: 3 size(0x00000064)
next bytes: 0x00000000 0x00000000 0x00000009 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000000
data:       0x00000009
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000000 0x00000001 0x00000001 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000001
data:       0x00000001
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000000 0x00000002 0xE9C150A9 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000002
data:       0xE9C150A9
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000004 0x00000003 0x00000000 0x00323660 0x0000008C 
obj_type :  0x00000004
obj_index:  0x00000003
data:       0x00000000
data_ptr:   0x00323660 0x0000008C

next bytes: 0x00000004 0x00000004 0x00000000 0x00323718 0x00000104 
obj_type :  0x00000004
obj_index:  0x00000004
data:       0x00000000
data_ptr:   0x00323718 0x00000104


*/







/*

==============================================
PKT:
==============================================
Session id:  0x000013D3 (5075)
Session cmd: 0x0000006D (109)
MAIN: size(0x0000003C)
00000000 00000001 55819F87 00000000 | 00000000 00000000 00000003 00000002 
00000000 00000000 00000004 00000004 | 00000000 00320A60 000001C2 

next bytes: 0x00000000 0x00000001 0x55819F87 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000001
data:       0x55819F87
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000000 0x00000003 0x00000002 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000003
data:       0x00000002
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000004 0x00000004 0x00000000 0x00320A60 0x000001C2 
obj_type :  0x00000004
obj_index:  0x00000004
data:       0x00000000
data_ptr:   0xALLOC001 0x000001C2


MAIN PTR: 1
ALLOCATED: 1 size(0x000001C2)
41020001 2A051841 04050241 05000009 | 00010100 02A9A185 CE0E0403 8C01580A 
58FBF6A2 1DD54092 16F64805 4420662D | B22A4E0E C8D7B9D5 20E20F48 35E4B305 
00D0503B C12C5C66 A44DE6C3 6C753594 | C03938A2 561E8ACB AB67016D 1E7072FD 
861FFFAC F5F08472 068E301D 8E109794 | 8B4DCC5E 00FE0BD9 C2716463 9808986A 
69E0F2F9 F7B0426A 3C5C2080 5B144C4E | 0D8C2C8C 97D07EF4 CBEEBFD4 42A50E00 
000F0000 0A9DEDA2 90040404 84020000 | 00019A12 47C44225 35E2D528 A73E8C2B 
3E282663 10553FA3 15DB93D7 D3A5C44B | 44EBE0AE B979E5CF 3ABE8FA1 D57194D2 
E8E40E52 6DA37BDB E49E2C9E 18433807 | F350358E 430A7E69 F03D0926 7F7E92B3 
E43B173D 24805078 2D52E4CE 81853EA3 | 3BEC1532 F85B2280 04D3CDFA 5BC69734 
BEB767C6 CD79476A 6B99A3F6 689C1E47 | 1AA94316 2EB93EA4 84AACA0A CF975D66 
0959FAEB 9C7D6DC0 5B53CF57 C390C4A9 | FECAEA75 84C90D64 9D148C33 A680094B 
865ED815 BBEEA0DA 4B03470B D2A297AF | 3229949E 71B18CCB 276D8444 78252781 
D0C3A2DD 9A894C4F 91472583 49DE9A47 | D0517F22 2BDBFDA5 FF2C6FFD BCC695E5 
89A2D003 8C2C249A 2EFECBA1 9F6964B2 | 10590006 0100079D EDA29004 0009D7E1 
EB090000 

*/









/*
u8 aes_41data_sess3pkt2[]=
"\xAA\xE1\x03\x6D\x41\x03\x00\x01\x87\xBF\x86\xAC\x05\x00\x03\x01"
"\x00\x08\x01\xAA\x52"
"\x00\x00"
;
*/

/*
==============================================
PKT:
==============================================
Session id:  0x0000F0AA (61610)
Session cmd: 0x0000006D (109)
MAIN: size(0x0000003C)
00000000 00000001 55819F87 00000000 | 00000000 00000000 00000003 00000001 
00000000 00000000 00000000 00000008 | 00000001 00000000 00000000 

next bytes: 0x00000000 0x00000001 0x55819F87 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000001
data:       0x55819F87
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000000 0x00000003 0x00000001 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000003
data:       0x00000001
data_ptr:   0x00000000 0x00000000

next bytes: 0x00000000 0x00000008 0x00000001 0x00000000 0x00000000 
obj_type :  0x00000000
obj_index:  0x00000008
data:       0x00000001
data_ptr:   0x00000000 0x00000000

*/