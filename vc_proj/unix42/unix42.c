// unix42.c : Defines the entry point for the console application.
//

#include <stdio.h>
#include <stdlib.h>

#include "short_types.h"


extern int main_unpack_sync();
extern int main_unpack(u8 *indata, u32 inlen);

u8 test[]=
//"\xD6\xA9\x03\x6D"
"\x41\x04\x00\x01\xB8\xC1\x8C\x8C\x09\x00\x03\x00"
"\x04\x04\x32\x41\x04\x00\x01\x0D\x03\x02\x23\x78\x6F\x74\x5F\x69"
"\x61\x6D\x2F\x24\x78\x6F\x74\x65\x67\x5F\x69\x61\x6D\x3B\x31\x36"
"\x32\x30\x64\x31\x31\x31\x62\x34\x65\x64\x32\x39\x32\x30\x00\x00"
"\x1C\x01\x00\x1D\x01\x00\x07\x05"
"\xA0\xC2"
;

u32 test_len=sizeof(test)-1;

int main(int argc, char* argv[]){



	//main_unpack_push();

	printf("Hello World 111\n");
	main_unpack(test, test_len);

	printf("Hello World 222\n");
	main_unpack_sync();

	return 0;
}

