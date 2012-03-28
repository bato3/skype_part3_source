// miramax.c : Defines the entry point for the console application.
//


#include <stdio.h>

#include "crypto/miracl.h"
#include <stdlib.h>
#include <string.h>

#include "short_types.h"


extern int show_memory_with_ascii(char *mem, int len, char *text);


u8 skype_pub[]=
"\xB8\x50\x6A\xEE\xD8\xED\x30\xFE\x1C\x0E\x67\x74\x87\x4B\x59\x20"
"\x6A\x77\x32\x90\x42\xA4\x9B\xE2\x40\x3D\xA4\x7D\x50\x05\x24\x41"
"\x06\x7F\x87\xBC\xD5\x7E\x65\x79\xB8\x3D\xF0\xBA\xDE\x2B\xEF\xF5"
"\xB5\xCD\x8D\x87\xE8\xB3\xED\xAC\x5F\x57\xFA\xBC\xCD\x49\x69\x59"
"\x74\xE2\xB5\xE5\xF0\x28\x7D\x6C\x19\xEC\xC3\x1B\x45\x04\xA9\xF8"
"\xBE\x25\xDA\x78\xFA\x4E\xF3\x45\xF9\x1D\x33\x9B\x73\xCC\x2D\x70"
"\xB3\x90\x4E\x11\xCA\x57\x0C\xE9\xB5\xDC\x4B\x08\xB3\xC4\x4B\x74"
"\xDC\x46\x35\x87\xEA\x63\x7E\xF4\x45\x6E\x61\x46\x2B\x72\x04\x2F"
"\xC2\xF4\xAD\x55\x10\xA9\x85\x0C\x06\xDC\x9A\x73\x74\x41\x2F\xCA"
"\xDD\xA9\x55\xBD\x98\x00\xF9\x75\x4C\xB3\xB8\xCC\x62\xD0\xE9\x8D"
"\x82\x82\x18\x09\x71\x05\x5B\x45\x7C\x06\xF3\x51\xE6\x11\x64\xFC"
"\x5A\x9D\xE9\xD8\x3D\x1D\x13\x78\x96\x40\x01\x38\x0B\x5B\x99\xEE"
"\x4C\x5C\x7D\x50\xAC\x24\x62\xA4\xB7\xEA\x34\xFD\x32\xD9\x0B\xD8"
"\xD4\xB4\x64\x10\x26\x36\x73\xF9\x00\xD1\xC6\x04\x70\x16\x5D\xF9"
"\xF3\xCB\x48\x01\x6A\xB8\xCA\x45\xCE\x68\x75\xA7\x1D\x97\x79\x15"
"\xCA\x82\x51\xB5\x02\x58\x74\x8D\xBC\x37\xFE\x33\x2E\xDC\x28\x55"
;


miracl *mip;

int rsa_unsign_profile(u8 *buf, int len, u8 *outbuf) {  

    big e,m,kn;
	
	mip=mirsys(100,0);

    e=mirvar(0);
    m=mirvar(0);
    kn=mirvar(0);

    bytes_to_big(0x100,buf,m);
	bytes_to_big(0x100,skype_pub,kn);

	power(m,65537,kn,e);
	
	big_to_bytes (0x100, e, outbuf, TRUE);

    return 0;
}


int rsa_unsign_profile_data(u8 *buf, int len, u8 *outbuf, u8 *pubkey) {  

    big e,m,kn;
	
	mip=mirsys(100,0);

    e=mirvar(0);
    m=mirvar(0);
    kn=mirvar(0);

    bytes_to_big(0x80,buf,m);
	bytes_to_big(0x80,pubkey,kn);

	power(m,65537,kn,e);
	
	big_to_bytes (0x80, e, outbuf, TRUE);

    return 0;
}


// in - reomte_profile
// out - pubkey, data
int decode_profile(u8 *remote_profile, u8 *pubkey, u8 *data, u8 *skypename){
	u8 tmpbuf[0x100];
	int i;
	int ret;


	// get cred
	rsa_unsign_profile(remote_profile+8,0x100,tmpbuf);
	show_memory_with_ascii(tmpbuf,0x100,"unsign cred:");

	// get pub
	for(i=0;i<0x100;i++){

		ret=memcmp(tmpbuf+i,"\x41\x05\x03\x00",4);

		if(ret==0){
			strncpy(skypename,tmpbuf+i+4,1024);
		};
	
		if((tmpbuf[i]==0x80) && (tmpbuf[i+1]==0x01)){
			memcpy(pubkey,tmpbuf+i+2,0x80);
		};

	};
	show_memory_with_ascii(pubkey,0x80,"pubkey data:");

	//get decoded data
	rsa_unsign_profile_data(remote_profile+8+0x100,0x80,data,pubkey);
	show_memory_with_ascii(data,0x80,"unsign data:");


	return 0;
};





