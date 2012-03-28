// crypto.c : Defines the entry point for the console application.
//

#include <stdio.h>

#include "miracl.h"

#include "sha.h"

//extern void __fastcall SHA_hash (const void *data, unsigned long bytes, void *hash);

extern int rsa_sign(_MIPD_ char *globalptr, char *buf, int len, char *outbuf);
extern int rsa_unsign_cred(_MIPD_ char *globalptr, char *buf, int len, char *outbuf);
extern int rsa_decode(_MIPD_ char *globalptr, char *buf, int len, char *outbuf);
extern int rsa_encode(_MIPD_ char *globalptr, char *buf, int len, char *outbuf);

int _get_sha1_data(char *buf, int len, char *outbuf, int need_convert){
	unsigned int dwtmp;

	SHA_hash(buf,len,outbuf);


	if (need_convert) {
		// invert data by integer big/little endian
		memcpy(&dwtmp,outbuf,4);
		dwtmp=bswap32(dwtmp);
		memcpy(outbuf,&dwtmp,4);

		memcpy(&dwtmp,outbuf+4,4);
		dwtmp=bswap32(dwtmp);
		memcpy(outbuf+4,&dwtmp,4);

		memcpy(&dwtmp,outbuf+8,4);
		dwtmp=bswap32(dwtmp);
		memcpy(outbuf+8,&dwtmp,4);

		memcpy(&dwtmp,outbuf+12,4);
		dwtmp=bswap32(dwtmp);
		memcpy(outbuf+12,&dwtmp,4);

		memcpy(&dwtmp,outbuf+16,4);
		dwtmp=bswap32(dwtmp);
		memcpy(outbuf+16,&dwtmp,4);
	};



	return 0;
}



int _get_sign_data(_MIPD_ char *globalptr, char *buf, int len, char *outbuf){


	rsa_sign(_MIPP_ globalptr,buf,len,outbuf);




	return 0;
};

int _get_unsign_cred(_MIPD_ char *globalptr, char *buf, int len, char *outbuf){


	rsa_unsign_cred(_MIPP_ globalptr,buf,len,outbuf);


	return 0;
};

int _get_encode_data(_MIPD_ char *globalptr, char *buf, int len, char *outbuf){


	rsa_encode(_MIPP_ globalptr,buf,len,outbuf);


	return 0;

};

int _get_decode_data(_MIPD_ char *globalptr, char *buf, int len, char *outbuf){


	rsa_decode(_MIPP_ globalptr,buf,len,outbuf);


	return 0;

};


