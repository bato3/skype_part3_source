/*\
|*|
|*| Skype Protocol v0.106 by Sean O'Neil.
|*| Copyright (c) 2009 by VEST Corporation.
|*| All rights reserved. Strictly Confidential!
|*|
|*| Date: 28.10.2009
|*|
\*/

#ifndef _skype_advanced_h_

#pragma warning(disable:4312)

#include "skype_basics.h"
#include "skype_supernodes.h"
#include "md5/md5.h"
#include "miracl/miracl.h"
#include "rijndael/rijndael.h"
#include "sha1/sha1.h"
#include "skype_rc4/skype_rc4.h"

struct bigtype	skype_384_bit_dh_mod = {12, skype_384_bit_dh_modulus};	// Skype 384-bit DH session key modulus
struct bigtype	skype_login_mod = {48, skype_login_rsa_key};			// Skype 1536-bit session key modulus
struct bigtype	skype_credentials_mod = {64, skype_credentials_key};	// Skype 2048-bit credentials modulus

#define attach(x,y,z) (memcpy(x,y,z),(u32)(z))

static void reverse_bytes (void *x, const u32 dwords)
{
	u32		i, j;
	
	for (i = 0; i < dwords*2; i += 4)
		j = dword(x,i), dword(x,i) = _bswap32(dword(x,dwords*4-4-i)), dword(x,dwords*4-4-i) = _bswap32(j);
}

// encodes one 32-bit dword into a 7-bit sequence, returns the number of encoded bytes

static u32 encode_dword (u8 * const to, u32 a)
{
	u32		n = 0;
	
	for (; a > 0x7F; a >>= 7, n++) to[n] = (u8) a | 0x80; to[n++] = (u8) a;
	return n;
}

// encodes a number of 32-bit dwords into a 7-bit sequence, returns the number of encoded bytes

static u32 encode32 (u8 * const to, const u32 * const from, const u32 words)
{
	u32		n = 0, i, a;
	
	for (i = 0; i < words; i++) { for (a = from[i]; a > 0x7F; a >>= 7, n++) to[n] = (u8) a | 0x80; to[n++] = (u8) a; }
	return n;
}

// decodes a 32-bit dword from a 7-bit sequence, returns the number of decoded bytes

static u32 decode32 (u32 * const to, const u8 * const from, const u32 bytes)
{
	u32		i, a;
	
	for (i = 0, a = 0; i < bytes; i++)
	{
		a |= (from[i] & 127) << (i*7);
		if (from[i] <= 127)
		{
			*to = a;	// length ok
			return i+1;
		}
	}
	*to = 0x80000000;	// really invalid length, ran out of input
	return i+1;
}

static void free_4142_list (skype_list *list)
{
	u32				i;
	
	for (i = 0; i < list->things; i++)
	{
		switch (list->thing[i].type)
		{
		case 5:
			free_4142_list ((skype_list *) list->thing[i].m);
		case 3:
		case 4:
		case 6:
			free ((void*)list->thing[i].m);
			list->thing[i].m = 0;
		}
	}
	free (list->thing);
	list->owner = list;
	list->thing = NULL;
	list->allocated_things = 0;
	list->things = 0;
}

static u32 skype_slot (const char *name)
{
	u32		slot = -1, i, j, n = __min(5,(u32)strlen(name));
	
	for (i = 0; i < n; i++) {slot ^= name[i];CRC32(slot, 0xEDB88320);}
	return slot & 0x7FF;
}

extern u32 pack_4142(u32 * list, u8 * packed_list, u32 pack_42, u32 max_bytes);
extern u32 unpack_4142(u32 *into_list, u8 **packed_blob, u32 *packed_bytes, u8 *pack_42, u32 max_depth, u32 *list_size);
extern u32 MD5_Skype_Password (const char *username, const char *password, u8 *hash128);
extern void AES_CTR (const u32 *key, u8 *pkt, const u32 bytes, const u32 IV);
extern void Generate_User_Key (_MIPD_ skype_user *user);
extern void Restore_User_Keypair (_MIPD_ skype_user *user);
extern u32 Skype_Server_Login (_MIPD_ skype_user *user, const u32 register_new, u8 *response, const u32 buffer_bytes);

#endif
