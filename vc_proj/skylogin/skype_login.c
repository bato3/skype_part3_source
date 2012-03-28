/*\
|*|
|*| Skype Login v0.105 by Sean O'Neil.
|*| Copyright (c) 2009 by VEST Corporation.
|*| All rights reserved. Strictly Confidential!
|*|
|*| Includes: Password Login, User Registration
|*|
|*| Date: 08.07.2009
|*|
\*/

//#include <stdio.h>
#include <string.h>
#include "SkypeControl/skype_basics.h"
#include "md5/md5.h"
#include "sha1/sha1.h"
#include "rijndael/rijndael.h"
#include "miracl/miracl.h"

#define SKYPE_VERSION	"4.1.0.130"

struct bigtype	skype_login_mod = {48, skype_login_rsa_key};				// Skype 1536-bit session key modulus
struct bigtype	skype_credentials_mod = {64, (u32*)skype_credentials_key};	// Skype 2048-bit credentials modulus

static u32 MD5_Skype_Password (const char *username, const char *password, u8 *hash128)
{
	MD5_state		skyper = MD5_INIT;
	
	MD5_update (&skyper, username, (u32) strlen (username));
	MD5_update (&skyper, "\nskyper\n", 8);
	MD5_update (&skyper, password, (u32) strlen (password));
	MD5_end (&skyper);
	memcpy (hash128, skyper.hash, 16);
	return 16;
}

#define reverse_bytes(x,i,j,n)	for(i=0;(i)<(n);(i)++)((j)=(x)[i],(x)[i]=_bswap32((x)[(n)-1-(i)]),(x)[(n)-1-(i)]=_bswap32(j))

static void Produce_Session_Key (_MIPD_ const u32 *rand192, u32 *key256, u32 *encrypted_key1536)
{
	SHA1_state		skyper = SHA1_INIT;
	u32				n = 0, i, j, x192[48];
	struct bigtype	x = {48, x192}, y = {48, encrypted_key1536};
	
	for (i = 0; i < 8; i++) memcpy (x192+i*6, rand192, 24);
	x192[0] &= 0xFFFFFF00;
	x192[0] |= 1;
	// Hashing it into 256-bit AES key
	SHA1_update (&skyper, &n, 4);
	SHA1_update (&skyper, x192, 192);
	SHA1_end (&skyper);
	memcpy (key256, skyper.hash, 20);
	n = 0x01000000;
	SHA1_init (&skyper);
	SHA1_update (&skyper, &n, 4);
	SHA1_update (&skyper, x192, 192);
	SHA1_end (&skyper);
	memcpy (key256+5, skyper.hash, 12);
	// Reversing byte order and RSA encrypting it for the server
	reverse_bytes (x192,i,j,48);
	power (_MIPP_ &x, 0x10001, &skype_login_mod, &y);
	reverse_bytes (encrypted_key1536,i,j,48);
}

static u8				login1[1024], login2[1024];
static u8				b[1024];

static void AES_CTR (const u32 *key, u8 *pkt, const u32 bytes, const u32 IV)
{
	u32		blk[8] = {IV, IV, 0, 0}, ks[60], i, j;
	
	aes_256_setkey (key, ks);
	for (j = 0; j+16 < bytes; j += 16)
	{
		aes_256_encrypt (blk, blk+4, ks);
		dword(pkt,j+ 0) ^= _bswap32(blk[4]);
		dword(pkt,j+ 4) ^= _bswap32(blk[5]);
		dword(pkt,j+ 8) ^= _bswap32(blk[6]);
		dword(pkt,j+12) ^= _bswap32(blk[7]);
		blk[3]++;
	}
	if (j < bytes)
	{
		aes_256_encrypt (blk, blk+4, ks);
		for (i = 0; j < bytes; j++, i++) pkt[j] ^= ((u8 *)(blk+4))[i^3];
	}
}

static u32 encode32 (u8 * const to, const u32 * const from, const u32 words)
{
	u32		n = 0, i, a;
	
	for (i = 0; i < words; i++) { for (a = from[i]; a > 0x7F; a >>= 7, n++) to[n] = (u8) a | 0x80; to[n++] = (u8) a; }
	return n;
}

#define attach(x,y,z)	(memcpy(x,y,z),(u32)z)

// Returns 0 if communication error, otherwise the number of bytes returned in 'credentials'.

u32 Skype_Password_Login (_MIPD_ const char *user_name, const char *password, const u32 *public_key, const u32 myexternalip, u8 *credentials)
{
	u32					i, n1, n2, n, rand192[6], key256[8], encrypted_key1536[48], hostid1[4], hostid2[5];
	u8					*p;
	struct sockaddr_in	sa;
	SOCKET				s;
	
	sa.sin_addr.s_addr = inet_addr("193.88.6.13"); sa.sin_port = htons (33033); sa.sin_family = AF_INET;
	// Generating 192-bit session key, should be random
	for (i = 0; i < 6; i++) srand32(), rand192[i] = rand32();
	Produce_Session_Key (_MIPP_ rand192, key256, encrypted_key1536);
	// Faking HostIDs from public_key, this is NOT how Skype does it
	SHA1_hash (public_key, 128, hostid2);	// a = public_key; b = rand192?; c = sha1(ProductId); d = sha1(HDD0 ID); e = sha1(C Volume SN);
	hostid2[3] ^= hostid2[0]; hostid2[0] = public_key[0];	// matching Skype
	hostid2[2] ^= hostid2[1]; hostid2[1] = rand192[0];		// matching Skype
	MD5_hash (hostid2, 20, hostid1);	// only the first 64 bits of it are needed actually = sha1(c,d,e)
	hostid1[0] ^= hostid1[3];
	hostid1[1] ^= hostid1[2];
	// Forming Packet 1
	p  = login1;
	p += attach (p, "\x16\x03\x01\x00\xE5\x42\xCD\xEF\xE7\x40\xD7\x2F\x1D\xC0\xC6\x87\x43\x2F\x33\x6F\xC0\x7D\x77\x75\xE0\xBE\x45", 27);
	p += attach (p, encrypted_key1536, 48*4);
	p += attach (p, "\xBA\x63\xB8\xC9\x08\xD9\x36\xAF\x94\xF5\xA2\x2B\xE0\xD1\xCE", 15);
	n1 = (u32) (p-login1);
	// Forming Packet 2
	p  = login2;
	p += attach (p, "\x17\x03\x01\x00\x00\x41\x04\x00\x00\x99\x27\x00\x02\x01\x03\x04", 16);
	p += attach (p, user_name, strlen(user_name)+1);
	p += attach (p, "\x04\x05\x10", 3);
	p += MD5_Skype_Password (user_name, password, p);
	p += attach (p, "\x41\x05\x04\x21\x80\x01", 6);
	p += attach (p, public_key, 128);
	p += attach (p, "\x01\x31", 2);
	p += attach (p, hostid1, 8);
	p += attach (p, "\x06\x33\x05", 3);
	p += encode32 (p, hostid2, 5);
	p += attach (p, "\x03\0x0D" "0/" SKYPE_VERSION "//\0\x00\x0E", 8+sizeof(SKYPE_VERSION));
	p += encode32 (p, &myexternalip, 1);	// 127.0.0.1 = 0x7F000001
	n = (u32) (p-login2-5);
	AES_CTR (key256, login2+5, n, 0);
	dword(login2+5,n) = crc8 (login2+5, n);
	n2 = (u32) (p+2-login2);
	login2[3] = (u8) ((n2-5)>>8);
	login2[4] = (u8) (n2-5);
	// Authenticating
	s = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (connect (s, (struct sockaddr*) &sa, 16)) return 0;	// WTF?
	if (send (s, "\x16\x03\x01\x00", 5, 0) != 5) return 0;	// WTF?
	n = recv (s, b, sizeof(b), 0) - 5;
	if (n > sizeof(b)-5) return 0;	// WTF?
	if (memcmp (b, "\x17\x03\x01\x00", 5)) return 0;	// WTF?
	if (send (s, login1, n1, 0) != n1) return 0;	// WTF?
	if (send (s, login2, n2, 0) != n2) return 0;	// WTF?
	n = recv (s, b, sizeof(b), 0) - 7;
	if (n > sizeof(b)-7) return 0;	// WTF?
	if (memcmp (b, "\x17\x03\x01", 3)) return 0;	// WTF?
	if (((u32)b[3]<<8)+b[4]-2 != n) return 0;	// WTF?
	if ((crc8 (b+5,n) & 0xFFFF) != word(b+5,n)) return 0;	// WTF?
	AES_CTR (key256, b+5, n, 1);
	memcpy (credentials, b+5, n);
	return n;	// 14 == incorrect password; 285 == successful login, returned credentials; otherwise some other error
}

// Returns 0 if communication error, otherwise the number of bytes returned in 'credentials'.

u32 Skype_Register (_MIPD_ const char *user_name, const char *password, const char *name, const char *email, const u32 *public_key, const u32 myexternalip, u8 *credentials)
{
	u32					i, n1, n2, n, rand192[6], key256[8], encrypted_key1536[48], hostid1[4], hostid2[5];
	u8					*p;
	struct sockaddr_in	sa;
	SOCKET				s;
	
	sa.sin_addr.s_addr = inet_addr("193.88.6.13"); sa.sin_port = htons (33033); sa.sin_family = AF_INET;
	// Generating 192-bit session key, should be random
	for (i = 0; i < 6; i++) srand32(), rand192[i] = rand32();
	Produce_Session_Key (_MIPP_ rand192, key256, encrypted_key1536);
	// Faking HostIDs from public_key, this is NOT how Skype does it
	SHA1_hash (public_key, 128, hostid2);	// a = public_key; b = rand192?; c = sha1(ProductId); d = sha1(HDD0 ID); e = sha1(C Volume SN);
	hostid2[3] ^= hostid2[0]; hostid2[0] = public_key[0];	// matching Skype
	hostid2[2] ^= hostid2[1]; hostid2[1] = rand192[0];		// matching Skype
	MD5_hash (hostid2, 20, hostid1);	// only the first 64 bits of it are needed actually = sha1(c,d,e)
	hostid1[0] ^= hostid1[3];
	hostid1[1] ^= hostid1[2];
	// Forming Packet 1
	p  = login1;
	p += attach (p, "\x16\x03\x01\x00\xE5\x42\xCD\xEF\xE7\x40\xD7\x2F\x1D\xC0\xC6\x87\x43\x2F\x33\x6F\xC0\x7D\x77\x75\xE0\xBE\x45", 27);
	p += attach (p, encrypted_key1536, 48*4);
	p += attach (p, "\xBA\x63\xB8\xC9\x08\xD9\x36\xAF\x94\xF5\xA2\x2B\xE0\xD1\xCE", 15);
	n1 = (u32) (p-login1);
	// Forming Packet 2
	p  = login2;
	p += attach (p, "\x17\x03\x01\x00\x00\x41\x04\x00\x00\x9A\x27\x00\x02\x01\x03\x04", 16);
	p += attach (p, user_name, strlen(user_name)+1);
	p += attach (p, "\x04\x05\x10", 3);
	p += MD5_Skype_Password (user_name, password, p);
	p += attach (p, "\x41\x09\x04\x21\x80\x01", 6);
	p += attach (p, public_key, 128);
	p += attach (p, "\x01\x31", 2);
	p += attach (p, hostid1, 8);
	p += attach (p, "\x06\x33\x05", 3);
	p += encode32 (p, hostid2, 5);	// a b c d e; a = public_key; b = key256?; c = sha1(ProductId); d = sha1(HDD0 ID); e = sha1(C Volume SN);
	p += attach (p, "\x03\x20", 2);
	p += attach (p, email, strlen(email)+1);
	p += attach (p, "\x00\x26\x01\x03/0/" SKYPE_VERSION "//\0\x03\x37", 11+sizeof(SKYPE_VERSION));
	p += attach (p, name, strlen(name)+1);
	p += attach (p, "\x03\x0D" "0/" SKYPE_VERSION "//\0\x00\x0E", 8+sizeof(SKYPE_VERSION));
	p += encode32 (p, &myexternalip, 1);	// 127.0.0.1 = 0x7F000001
	n = (u32) (p-login2-5);
	AES_CTR (key256, login2+5, n, 0);
	dword(login2+5,n) = crc8 (login2+5, n);
	n2 = (u32) (p+2-login2);
	login2[3] = (u8) ((n2-5)>>8);
	login2[4] = (u8) (n2-5);
	// Authenticating
	s = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (connect (s, (struct sockaddr*) &sa, 16)) return 0;	// WTF?
	if (send (s, "\x16\x03\x01\x00", 5, 0) != 5) return 0;	// WTF?
	n = recv (s, b, sizeof(b), 0) - 5;
	if (n != 5) return 0;	// WTF?
	if (memcmp (b, "\x17\x03\x01\x00", 5)) return 0;	// WTF?
	if (send (s, login1, n1, 0) != n1) return 0;	// WTF?
	if (send (s, login2, n2, 0) != n2) return 0;	// WTF?
	n = recv (s, b, sizeof(b), 0) - 7;
	if (n > sizeof(b)-7) return 0;	// WTF?
	if (memcmp (b, "\x17\x03\x01", 3)) return 0;	// WTF?
	if (((u32)b[3]<<8)+b[4]-2 != n) return 0;	// WTF?
	if ((crc8 (b+5,n) & 0xFFFF) != word(b+5,n)) return 0;	// WTF?
	AES_CTR (key256, b+5, n, 1);
	memcpy (credentials, b+5, n);
	return n;	// 285 == successful login, returned credentials; otherwise returns a small packet (~60 bytes) with a list of name suggestions
}

// calculates public_key and secret_key from secret_p and secret_q

void Restore_User_Keypair (_MIPD_ u32 *secret_p, u32 *secret_q, u32 *public_key, u32 *secret_key)
{
	u32					_w[2] = {0x10001, 0};
	struct bigtype		p = {16, secret_p}, q = {16, secret_q}, y = {32, public_key}, z = {32, secret_key}, w = {1, _w};
	
	p.w[16] = 0;
	q.w[16] = 0;
	multiply (_MIPP_ &p, &q, &y);		// p*q = public key (not exactly, it's the common RSA modulus)
	decr (_MIPP_ &p, 1, &p);			// p-1
	decr (_MIPP_ &q, 1, &q);			// q-1
	multiply (_MIPP_ &p, &q, &z);		// z = (p-1)*(q-1)
	incr (_MIPP_ &p, 1, &p);			// p restored
	incr (_MIPP_ &q, 1, &q);			// q restored
//	convert (0x10001, w);				// w = 0x10001, the public exponent (now that's the real public key)
	xgcd (_MIPP_ &w, &z, &z, &z, &z);	// z = 1/0x10001 mod (p-1)*(q-1), the secret exponent
	printf ("Public Key = "); bindump (public_key, 128);
	printf ("Secret Key = "); bindump (secret_key, 128);
}

// generates new secret_p and secret_q and calculates the public_key and the secret_key from them

void Generate_User_Key (_MIPD_ u32 *secret_p, u32 *secret_q)
{
	u32					i;
	struct bigtype		p = {16, secret_p}, q = {16, secret_q};
	
	// Generating a random 1024-bit RSA keypair
	for (i = 0; i < 16; i++) srand32(), p.w[i] = rand32 (), q.w[i] = rand32 ();
	p.w[15] |= 0x80000000, p.w[16] = 0;
	q.w[15] |= 0x80000000, q.w[16] = 0;
	nxprime (_MIPP_ &p, &p);			// p = random 512-bit prime
	nxprime (_MIPP_ &q, &q);			// q = random 512-bit prime
}

int main_int (void)
{
	// local variables in each thread:
	miracl				mip, *mr_mip=&mip;
	u32					i, j, hash[5];
	u8					response[1024], *s, credentials[256];
	u32					public_key[33], secret_p[17], secret_q[17], secret_key[33];
	struct bigtype		c = {64, (u32*)(response+19)}, y = {64, (u32*) credentials};
	
#ifdef _MSC_VER
	{
		WSADATA			wsd;
		if (WSAStartup (0x0202, &wsd)) __asm int 3;	// WTF?
	}
#endif
	// each thread:
	mirsys (_MIPP_ -256, 0); // up to 2048-bit keys, no mallocs
//	mip.PRIMES = root_mip.PRIMES;	// need it for [MUCH] faster key generation, one table for all is enough
	Generate_User_Key (_MIPP_ secret_p, secret_q);
	Restore_User_Keypair (_MIPP_ secret_p, secret_q, public_key, secret_key);
//	i = Skype_Register (_MIPP_ "john.fucking.doe", "password", "John F Doe", "john.f.doe@somewhere.online", public_key, 0x55AAF39B, response);	// 85.170.243.155
	i = Skype_Password_Login (_MIPP_ "johnfuckingdoe", "password", public_key, 0x55555555, response);	// 85.170.243.155
	printf ("Server Response = "); bindump (response, i);
	if (i < 0x113) return -1;
	printf ("User Credentials = "); bindump (response+19, 256);
	reverse_bytes (c.w,i,j,64);
	power (_MIPP_ &c, 0x10001, &skype_credentials_mod, &y);
	reverse_bytes (y.w,i,j,64);
	printf ("Decrypted Credentials = "); bindump (credentials, 256);
	s = memchr (credentials, 0x41, 80);
	if (!s) return -1;
	SHA1_hash (s, (u32)(credentials+255-20-s), hash);
	printf ("Credentials SHA-1 = "); bindump (hash, 20);
	for (i = 0; i < 5; i++) if (dword(credentials,255-20+i*4) != _bswap32(hash[i])) return -1;
	printf ("Valid Credentials!\n");
	return 0;
}
