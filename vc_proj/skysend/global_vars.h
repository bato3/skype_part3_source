//
// global structure
//

#include "short_types.h"

#include "rc4/Expand_IV.h"


struct global_s {

	u8 destip[0x1000];
	u16 destport;

	uint rnd;

	RC4_context rc4_send;
	RC4_context rc4_recv;

	u8 CHALLENGE_RESPONSE[0x80];
	u8 LOCAL_NONCE[0x80];


	u8 LOCAL_UIC[0x189];


	u8 AFTER_CRED_LOCAL[0x81];

	u8 REMOTE_CREDENTIALS[0x100];
	u8 REMOTE_PUBKEY[0x80];

	u8 AES_KEY[0x20];
	u32 REMOTE_SESSION_ID;
	u32 LOCAL_SESSION_ID;


	u8 INIT_UNK[0x16];

	uint BLOB_0_1;
	uint BLOB_0_2;
	uint BLOB_0_2__1;
	uint BLOB_0_5;
	uint BLOB_0_5__1;
	uint BLOB_0_6;
	uint BLOB_0_7;
	uint BLOB_0_7__1;
	uint BLOB_0_7__2;
	uint BLOB_0_7__3;
	uint BLOB_0_7__4;
	uint BLOB_0_9;
	uint BLOB_0_9__1;
	uint BLOB_0_A;
	uint BLOB_0_15;
	uint BLOB_0_9__2;
	uint BLOB_0_A__1;
	uint BLOB_0_15__1;
	uint BLOB_0_F;
	uint BLOB_0_A__2;
	uint BLOB_0_A__3;
	uint BLOB_1_9_ptr;
	uint BLOB_1_9_size;


	u32 confirm[0x100];
	u32 confirm_count;


	u8 MSG_TEXT[0x1000];

	u8 CHAT_STRING[0x100];
	u8 REMOTE_NAME[0x100];
	u8 CHAT_PEERS[0x100];
	u8 CHAT_RND_ID[0x100];


	u8 NEWBLK[0x1000];
	uint NEWBLK_LEN;

	u8 CREDENTIALS[0x105];
	uint CREDENTIALS_LEN;
	u8 CREDENTIALS_HASH[0x15];
	uint UIC_CRC;


	u8 AFTER_CRED[0x81];

	u8 CREDENTIALS188[0x189];
	uint CREDENTIALS188_LEN;

	u8 xoteg_pub[0x81];
	u8 xoteg_sec[0x81];

	u8 skype_pub[0x101];

};



