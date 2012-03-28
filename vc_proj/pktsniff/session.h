// session structure
//


#include "rc4/Expand_IV.h"


#define MAX_UDP_SESSION 1000
#define MAX_TCP_SESSION 1000

struct session_s {
	u32 src_ip;
	u16 sport;
	u32 dest_ip;
	u16 dport;

	u32 remote_udp_rnd;
	u32 public_ip;

	u32 send_count;
	u32 recv_count;

	RC4_context rc4_send;
	RC4_context rc4_recv;
};

struct session_s session_tcp[MAX_TCP_SESSION];
struct session_s session_udp[MAX_UDP_SESSION];




