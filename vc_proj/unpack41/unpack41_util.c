//
//  utils
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include "unpack41.h"

extern int mysub_SessionManager_CMD_RECV_Process_00788E80(char *buf1, uint buflen1, char *selfptr);

//
// Utils
//

//
// free-ing allocated buffers
//
int free_structure(char *selfptr){
	uint i;
	char *buf;

	
	struct self_s *self;
	self=(struct self_s *)selfptr;

	buf=self->heap_alloc_buf;
	free(buf);
	self->heap_alloc_buf_count=0;

	for(i=0;i<self->heap_alloc_struct_count;i++){
		buf=self->heap_alloc_struct_array[i];
		free(buf);
	};
	self->heap_alloc_struct_count=0;

	return 0;

};


//
// Print one buffer, detailed line by line
//
int print_structure_one_detail(char *str, char *selfptr, int index){
	unsigned int tmp,i,j,k;
	uint tmp1,tmp2,tmp3,tmp4,tmp5;
	char *buf;
	uint size;
	uint flag_k;

	struct self_s *self;
	self=(struct self_s *)selfptr;

	if (index==-1){
		buf=self->heap_alloc_buf;
		size=self->heap_alloc_buf_count;
	}else{
		buf=self->heap_alloc_struct_array[index];
		size=self->heap_alloc_struct_array_size[index];
	};

	if (index==-1){
		//printf("%s size(0x%08X)\n",str,size);
	}else{
		//printf("%s %d size(0x%08X)\n",str,index+1,size);
	};

	j=0;
	for(i=0;i<size;i=i+4){
		tmp=0;
		if (j==0){
			printf("next bytes: ");
		};
		if ((size-i)<4) {
			memcpy(&tmp,buf,size-i);
			if ((size-i)==3){
				printf("0x%06X ",tmp&0xffffff00);
			};
			if ((size-i)==2){
				printf("0x%04X ",tmp&0xffff0000);
			};
			if ((size-i)==1){
				printf("0x%02X ",tmp&0xff000000);
			};

		}else{
			memcpy(&tmp,buf,4);
			printf("0x%08X ",tmp);		
		};
		j++;
		if (j==1){
			tmp1=tmp;
		};
		if (j==2){
			tmp2=tmp;
		};
		if (j==3){
			tmp3=tmp;
		};
		if (j==4){
			tmp4=tmp;
		};
		if (j==5){
			tmp5=tmp;
		};
		if  ((j==5)||(i+4>=size)){ 
			j=0;
			printf("\n");
			printf("obj_type :  0x%08X\n",tmp1);
			printf("obj_index:  0x%08X\n",tmp2);
			printf("data:       0x%08X\n",tmp3);
			flag_k=-1;
			for (k=0;k<self->heap_alloc_struct_count;k++){
				if ( self->heap_alloc_struct_array[k] == (char *)tmp4 ){
					flag_k=k;
				};
			};
			if (flag_k==-1){
				printf("data_ptr:   0x%08X 0x%08X\n",tmp4,tmp5);
			}else{
				printf("data_ptr:   0xALLOC00%d 0x%08X\n",flag_k+1,tmp5);
			};
			printf("\n");
		};

		buf=buf+4;
	};

	printf("\n");

	return 0;
};



//
// Print one main buffer, detailed line by line
//
int print_structure_one_detail_main(char *str, char *selfptr, int index){
	unsigned int tmp,i,j,k;
	uint tmp1,tmp2,tmp3,tmp4,tmp5;
	char *buf;
	uint size;
	uint flag_k;

	struct self_s *self;
	self=(struct self_s *)selfptr;

	if (index==-1){
		buf=self->heap_alloc_buf;
		size=self->heap_alloc_buf_count;
	}else{
		buf=self->heap_main_alloc_struct_array[index];
		size=self->heap_main_alloc_struct_array_size[index];
	};

	if (index==-1){
		//printf("%s size(0x%08X)\n",str,size);
	}else{
		printf("%s %d size(0x%08X)\n",str,index+1,size);
	};

	j=0;
	for(i=0;i<size;i=i+4){
		tmp=0;
		if (j==0){
			printf("next bytes: ");
		};
		if ((size-i)<4) {
			memcpy(&tmp,buf,size-i);
			if ((size-i)==3){
				printf("0x%06X ",tmp&0xffffff00);
			};
			if ((size-i)==2){
				printf("0x%04X ",tmp&0xffff0000);
			};
			if ((size-i)==1){
				printf("0x%02X ",tmp&0xff000000);
			};

		}else{
			memcpy(&tmp,buf,4);
			printf("0x%08X ",tmp);		
		};
		j++;
		if (j==1){
			tmp1=tmp;
		};
		if (j==2){
			tmp2=tmp;
		};
		if (j==3){
			tmp3=tmp;
		};
		if (j==4){
			tmp4=tmp;
		};
		if (j==5){
			tmp5=tmp;
		};
		if  ((j==5)||(i+4>=size)){ 
			j=0;
			printf("\n");
			printf("obj_type :  0x%08X\n",tmp1);
			printf("obj_index:  0x%08X\n",tmp2);
			printf("data:       0x%08X\n",tmp3);
			flag_k=-1;
			for (k=0;k<self->heap_main_alloc_struct_count;k++){
				if ( self->heap_main_alloc_struct_array[k] == (char *)tmp4 ){
					flag_k=k;
				};
			};
			if (flag_k==-1){
				printf("data_ptr:   0x%08X 0x%08X\n",tmp4,tmp5);
			}else{
				printf("data_ptr:   0xALLOC00%d 0x%08X\n",flag_k+1,tmp5);
			};
			printf("\n");
		};

		buf=buf+4;
	};

	printf("\n");

	return 0;
};



//
// Print one buffer
//
int print_structure_one(char *str, char *selfptr, int index){
	unsigned int tmp,i,j;
	char *buf;
	uint size;

	struct self_s *self;
	self=(struct self_s *)selfptr;

	if(index==-1){
		buf=self->heap_alloc_buf;
		size=self->heap_alloc_buf_count;
	}else{
		buf=self->heap_alloc_struct_array[index];
		size=self->heap_alloc_struct_array_size[index];
	};

	if (index==-1){
		printf("%s size(0x%08X)\n",str,size);
	}else{
		printf("%s %d size(0x%08X)\n",str,index+1,size);
	};

	j=0;
	for(i=0;i<size;i=i+4){
		tmp=0;
		if ((size-i)<4) {
			memcpy(&tmp,buf,size-i);
			if (index!=-1) tmp=bswap32(tmp);
			if ((size-i)==3){
				printf("%06X ",tmp&0xffffff00);
			};
			if ((size-i)==2){
				printf("%04X ",tmp&0xffff0000);
			};
			if ((size-i)==1){
				printf("%02X ",tmp&0xff000000);
			};

		}else{
			memcpy(&tmp,buf,4);
			if (index!=-1) tmp=bswap32(tmp);
			printf("%08X ",tmp);		
		};
		j++;
		if (j==4) { printf("| "); };
		if ((j==8)||(i+4>=size)) { 
			j=0; 
			printf("\n");
		};
		buf=buf+4;
	};

	printf("\n");

	return 0;
};


//
// Print logic
//
int print_structure(char *str, char *selfptr, int detail){
	uint i;

	
	struct self_s *self;
	self=(struct self_s *)selfptr;

	printf("==============================================\n");
	printf("%s\n",str);
	printf("==============================================\n");

	printf("Session id:  0x%08X (%d)\n",self->session_id, self->session_id);
	printf("Session cmd: 0x%08X (%d)\n",self->session_cmd, self->session_cmd);

	print_structure_one("MAIN:",selfptr,-1);

	if (detail) print_structure_one_detail("MAIN:",selfptr,-1);

	for(i=0;i<self->heap_alloc_struct_count;i++){

		printf("MAIN PTR: %d\n",self->heap_alloc_struct_array_mainptr[i]);
		print_structure_one("ALLOCATED:",selfptr,i);

	};

	for(i=0;i<self->heap_main_alloc_struct_count;i++){

		print_structure_one_detail_main("MAIN OTHER:",selfptr,i);

	};


	return 0;
};


/*
*  Krasivo vivodim soderjimae heap_alloc_buf
*/

int print_buffer(char *str,unsigned int size1, char *selfptr){
	unsigned int tmp,i,j;
	char *buf;
	uint size;

	struct self_s *self;
	self=(struct self_s *)selfptr;

	buf=self->heap_alloc_buf;
	size=self->heap_alloc_buf_count;

	printf("MAINBUF %s size(0x%08X)\n",str,size);

	j=0;
	for(i=0;i<size;i=i+4){
		memcpy(&tmp,buf,4);
		printf("%08X ",tmp);		
		j++;
		if (j==4) { printf("| "); };
		if ((j==8)||(i+4>=size)) { 
			j=0; 
			printf("\n");
		};
		buf=buf+4;
	};


	return 0;
};

int print_buffer2(char *str,unsigned int size1, char *selfptr){
	unsigned int tmp,i,j;
	char *buf;
	uint size;

	struct self_s *self;
	self=(struct self_s *)selfptr;

	if (self->heap_alloc_struct_count == 0){
			printf("no alloc struct-es");
			return 0;
	};

	//current alloc
	buf=self->heap_alloc_struct_array[ (self->heap_alloc_struct_count-1) ];

	//size
	size=self->heap_alloc_struct_array_size[ (self->heap_alloc_struct_count-1) ];

	printf("%s size(0x%08X)\n",str,size);

	j=0;
	for(i=0;i<size;i=i+4){
		tmp=0;
		if ((size-i)<4) {
			memcpy(&tmp,buf,size-i);
			tmp=bswap32(tmp);
			if ((size-i)==3){
				printf("%06X ",tmp&0xffffff00);
			};
			if ((size-i)==2){
				printf("%04X ",tmp&0xffff0000);
			};
			if ((size-i)==1){
				printf("%02X ",tmp&0xff000000);
			};

		}else{
			memcpy(&tmp,buf,4);
			tmp=bswap32(tmp);
			printf("%08X ",tmp);		
		};
		j++;
		if (j==4) { printf("| "); };
		if ((j==8)||(i+4>=size)) { 
			j=0; 
			printf("\n");
		};
		buf=buf+4;
	};


	return 0;
};


//
// Main function 
// called from external
// unpack41
//
int unpack41_structure(char *buf, uint buflen, char *selfptr){
	struct self_s *self;
	self=(struct self_s *)selfptr;

	
	self->value_02c3f818=(unsigned int)buf;
	self->value_02c3f844=buflen;
	self->heap_alloc_buf_count=0;
	self->heap_alloc_buf=0;
	mysub_SessionManager_CMD_RECV_Process_00788E80(buf,buflen,selfptr);
	

	//last 2 bytes -- crc16
	if (self->value_02c3f844!=2) {

		//not all bytes decoded
		return -1;
	};


	return 0;
}


