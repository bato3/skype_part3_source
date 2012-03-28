// miramax.c : Defines the entry point for the console application.
//

/*
 *   Program to encode text using RSA public key.
 *
 *   *** For Demonstration use only *****
 *
 *   Copyright (c) 1988-1997 Shamus Software Ltd.
 */


#include <stdio.h>

#include "miracl.h"

#include <stdlib.h>
#include <string.h>

// for global structure
#include "../global_vars.h"


extern int show_memory(char *mem, int len, char *text);


int rsa_unsign_cred(_MIPD_ char *globalptr, char *buf, int len, char *outbuf)
{  

    big e,m,kn;

	struct global_s *global;
	global=(struct global_s *)globalptr;
	


    e=mirvar(_MIPP_ 0);
    m=mirvar(_MIPP_ 0);
    kn=mirvar(_MIPP_ 0);

    bytes_to_big(_MIPP_ 0x100,buf,m);
	bytes_to_big(_MIPP_ 0x100,global->skype_pub,kn);

	power(_MIPP_ m,65537,kn,e);
	
	big_to_bytes(_MIPP_ 0x100, e, outbuf, TRUE);


	mirkill(_MIPP_ e);
	mirkill(_MIPP_ m);
	mirkill(_MIPP_ kn);

    return 0;
}





int rsa_sign(_MIPD_ char *globalptr, char *buf, int len, char *outbuf)
{  

    big e,m,kd,kn;

	struct global_s *global;
	global=(struct global_s *)globalptr;

    e=mirvar(_MIPP_ 0);
    m=mirvar(_MIPP_ 0);
    kd=mirvar(_MIPP_ 0);
    kn=mirvar(_MIPP_ 0);


    bytes_to_big(_MIPP_ 0x80,buf,m);
    bytes_to_big(_MIPP_ 0x80,global->xoteg_sec,kd);
	bytes_to_big(_MIPP_ 0x80,global->xoteg_pub,kn);

    powmod(_MIPP_ m,kd,kn,e);

	
	big_to_bytes(_MIPP_ 0x80, e, outbuf, TRUE);

    mirkill(_MIPP_ e);
    mirkill(_MIPP_ m);
    mirkill(_MIPP_ kd);
    mirkill(_MIPP_ kn);

    return 0;
}





int rsa_decode(_MIPD_ char *globalptr, char *buf, int len, char *outbuf)
{  

    big e,m,kd,kn;

	struct global_s *global;
	global=(struct global_s *)globalptr;
    
    e=mirvar(_MIPP_ 0);
    m=mirvar(_MIPP_ 0);
    kd=mirvar(_MIPP_ 0);
    kn=mirvar(_MIPP_ 0);


    bytes_to_big(_MIPP_ 0x80,buf,m);
    bytes_to_big(_MIPP_ 0x80,global->xoteg_sec,kd);
	bytes_to_big(_MIPP_ 0x80,global->xoteg_pub,kn);

    powmod(_MIPP_ m,kd,kn,e);
	
	big_to_bytes(_MIPP_ 0x80, e, outbuf, TRUE);

    mirkill(_MIPP_ e);
    mirkill(_MIPP_ m);
    mirkill(_MIPP_ kd);
    mirkill(_MIPP_ kn);


    return 0;
}


int rsa_encode(_MIPD_ char *globalptr, char *buf, int len, char *outbuf)
{
    big e,m,ke;

	struct global_s *global;
	global=(struct global_s *)globalptr;


    e=mirvar(_MIPP_ 0);
    m=mirvar(_MIPP_ 0);
    ke=mirvar(_MIPP_ 0);
 

	bytes_to_big(_MIPP_ 0x80,global->REMOTE_PUBKEY,ke);    
    bytes_to_big(_MIPP_ 0x80,buf,m);

	power(_MIPP_ m,65537,ke,e);
	
	big_to_bytes (_MIPP_ 0x80, e, outbuf, TRUE);

    mirkill(_MIPP_ e);
    mirkill(_MIPP_ m);
    mirkill(_MIPP_ ke);

    return 0;
};


