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

int process_tcp_client_sess1_pkt5n(_MIPD_ char *globalptr, char *resp, int resp_len){
	struct global_s *global;
	global=(struct global_s *)globalptr;


	// recv pkt
	show_memory(resp, resp_len, "Result");

	process_tcp_packet4(globalptr, resp, resp_len);


	return 0;
};


