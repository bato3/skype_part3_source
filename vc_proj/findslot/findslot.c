// findslot.c : Defines the entry point for the console application.
//

#include <stdio.h>
#include <stdlib.h>

extern int slot_find(char *str);

int main(int argc, char* argv[]) {
	char *str;

	if (argc!=2){
		printf("no enough args\n");
		exit(-1);
	};

	str=argv[1];

	slot_find(str);


	return 0;
}

