// example of 42 usage
//

#include "skype_basics.h"
#include "skype_rc4.h"
#pragma warning(disable:4311 4312)

extern int last_slot;

#define error printf

#define MAX_MEM		4096

static void errdump (const u8 * const mem, const u32 n)
{
	u32		i, j, m = (__min(n,MAX_MEM)+15)&~15;
	char	s[512], *z;
	
	for (i = 0, z = s, *s = '\0'; i < m; i++)
	{
		if ((i&15)==0) z += sprintf (z, "%04X:", i);
		if (i < n) z += sprintf (z, " %02X", mem[i]); else z += sprintf (z, "   ");
		if ((i&15)==15)
		{
			*z++ =0x20; *z++ ='|'; *z++ =0x20;
			for (j = 0; j < 16; j++) *z++ = (i-15+j >= n) ? 0x20 : (mem[i-15+j]<0x20)||(mem[i-15+j]>0x7E) ? '.' : mem[i-15+j];
			*z++ =0x20; *z++ ='|'; *z++ ='\n'; *z = '\0';
			error ("%s", z = s); *s = '\0';
		}
	}
	if (n >= MAX_MEM) error ("...\n");
	error ("\n");
}



static void dump_blob (const char *header, const u32 type, const u32 m, const u32 n)
{
	u32			i;
	char		*s, out[1024*100];
	
	switch (type)
	{
	case 0:	// 32-bit
		error ("%s: %02X %02X %02X %02X\n", header, m&0xFF, (m>>8)&0xFF, (m>>16)&0xFF, m>>24);
		break;
	case 1: // 64-bit
		error ("%s: %02X %02X %02X %02X %02X %02X %02X %02X\n", header, m&0xFF, (m>>8)&0xFF, (m>>16)&0xFF, m>>24, n&0xFF, (n>>8)&0xFF, (n>>16)&0xFF, n>>24);
		break;
	case 2:	// IP:port
		error ("%s: %u.%u.%u.%u:%u\n", header, m>>24, (m>>16)&0xFF, (m>>8)&0xFF, m&0xFF, n);
		break;
	case 3:	// ASCIIZ
		if (byte(m,n-1) != 0) __asm int 3;	// just in case
		error ("%s: \"%s\"\n", header, m);
		break;
	case 4:	// BINARY
		error ("%s: %d bytes\n", header, n);
		errdump ((void*)m, n);
		break;
	case 5:	// recursion, gotta handle it upstairs
		__asm int 3;
		break;
	case 6:	// 32-bit words
		s += sprintf (s = out, "%s: ", header);
		for (i = 0; i < n; i += 4) s += sprintf (s, "%02X %02X %02X %02X%s", dword(m,i)&0xFF, (dword(m,i)>>8)&0xFF, (dword(m,i)>>16)&0xFF, dword(m,i)>>24, (i+4<n)?", ":"");
		error ("%s\n", out);
		break;
	default:
		__asm int 3;
	}
}

#define report(h)	dump_blob(h,type,m,n);break

static void dump_41 (const u32 type, const u32 id, const u32 m, const u32 n)
{
	char		aid[12];
	
	switch (id)
	{
//	case 0x00:	report ("SuperNode");
//	case 0x01:	report ("Command");
//	case 0x05:	report ("My Password MD5");
//	case 0x09:	report ("My Credentials Expiry Time");
//	case 0x0D:	report ("Skype Version");
//	case 0x0E:	report ("Login/Key Time/ID?");
//	case 0x20:	report ("My Email");
//	case 0x21:	report ("My Public Key");
//	case 0x24:	report ("My Credentials");
//	case 0x31:	report ("Host ID");
//	case 0x33:	report ("Host IDs");
//	case 0x37:	report ("My Name");
	default:	sprintf (aid, "%02X-%02X", type, id); report (aid);
	}
}

typedef struct _skype_thing
{
	u32				type, id, m, n;
} skype_thing;

typedef struct _skype_list
{
	struct _skype_list	*next;
	skype_thing			*thing;
	u32					allocated_things;
	u32					things;
} skype_list;

static void dump_41_list (const skype_list *list)
{
	u32				i, l;
	
	if (!list) { error ("<empty>\n"); return; }
	if (!list->things || !list->thing) { error ("<empty>\n"); return; }
	for (i = 0, l = 0; i < list->things; i++)
	{
		if (list->thing[i].type == 5) {
			error ("05-%02X: {\n", list->thing[i].id);
			dump_41_list ((skype_list *)list->thing[i].m);
			error ("05-%02X: }\n", list->thing[i].id);
			continue;
		};

		dump_41 (list->thing[i].type, list->thing[i].id, list->thing[i].m, list->thing[i].n);
	}
}




//
// unpack all
//
int main_unpack (u8 *indata, u32 inlen) {
	u32				list_size = 0;
	u8				*blob_pos = indata;
	skype_list		new_list = {&new_list, 0, 0, 0};
	u32				packed_bytes;
	int				ret;

	packed_bytes=inlen;


	list_size = 0x50000;

	while ((packed_bytes>0) && (blob_pos[0]!=0x42)){ 			
		packed_bytes--;
		blob_pos++;
	};


	ret=1;
	while( (packed_bytes>0) && (ret==1) ){
		
		ret=unpack_4142 ((u32*)&new_list, &blob_pos, &packed_bytes, 0, 8, &list_size);

		while ((packed_bytes>0) && (blob_pos[0]!=0x42)){ 			
			packed_bytes--;
			blob_pos++;
		};

	};

	dump_41_list (&new_list);
	error ("\n");


	
	return 0;
};


//
// pack
//
int main_pack (skype_thing *mythings, int mythings_len, u8 *outdata, u32 maxlen) {
	u32				list_size = 0;
	skype_list		list = {&list, mythings, mythings_len, mythings_len};
	u32				packed_bytes;


	list_size = 0x50000;

	packed_bytes = pack_4142 ((u32*)&list, outdata, 1, list_size);
	
	return packed_bytes;
};


static void dump_41_test (const skype_list *list, u32 test_type, u32 test_id, int *testok) {
	u32				i, l;
	
	if (!list) { 
		//error ("<empty>\n"); 
		return ;
	};

	if (!list->things || !list->thing) { 
		//error ("<empty>\n"); 
		return ;
	};

	for (i = 0, l = 0; i < list->things; i++) {
		if (list->thing[i].type == 5) {
			dump_41_test ((skype_list *)list->thing[i].m, test_type, test_id, testok);
			continue;
		};
		if (list->thing[i].type == test_type) {
			if (list->thing[i].id == test_id) {
				*testok=1;
			};
		};
	}


}



//
// unpack and test for id type
//
int main_unpack_test (u8 *indata, u32 inlen, u32 test_type, u32 test_id) {
	u32				list_size = 0;
	u8				*blob_pos = indata;
	skype_list		new_list = {&new_list, 0, 0, 0};
	u32				packed_bytes;
	int				ret;

	packed_bytes=inlen;

	list_size = 0x50000;

	while ((packed_bytes>0) && (blob_pos[0]!=0x42)){ 			
		packed_bytes--;
		blob_pos++;
	};

	ret=1;
	while( (packed_bytes>0) && (ret==1) ){
		
		ret=unpack_4142 ((u32*)&new_list, &blob_pos, &packed_bytes, 0, 8, &list_size);

		while ((packed_bytes>0) && (blob_pos[0]!=0x42)){ 			
			packed_bytes--;
			blob_pos++;
		};

	};

	ret=0;
	dump_41_test (&new_list, test_type, test_id, &ret);

	
	return ret;
};





static void dump_41_saveip (const skype_list *list, FILE *fp, u32 *total) {
	u32				i, l;
	u32 m;
	u32 n;
	
	if (!list) { 
		//error ("<empty>\n"); 
		return ;
	};

	if (!list->things || !list->thing) { 
		//error ("<empty>\n"); 
		return ;
	};

	for (i = 0, l = 0; i < list->things; i++) {
		if (list->thing[i].type == 5) {
			dump_41_saveip ((skype_list *)list->thing[i].m, fp, total);
			continue;
		};

		if (list->thing[i].type == 0x02) {
			(*total)++;
			m=list->thing[i].m;
			n=list->thing[i].n;
			fprintf(fp,"%u.%u.%u.%u:%u\n",m>>24, (m>>16)&0xFF, (m>>8)&0xFF, m&0xFF, n);
		};
		if ((list->thing[i].type == 0x00) && (list->thing[i].id==0x00)) {
			m=list->thing[i].m;
			n=list->thing[i].n;
			fprintf(fp,"\nSlot: #%d 0x%08X\n",m,m);
			last_slot=m;
		};
	}


}

//
// unpack and save ip
//
int main_unpack_saveip(u8 *indata, u32 inlen) {
	u32				list_size = 0;
	u8				*blob_pos = indata;
	skype_list		new_list = {&new_list, 0, 0, 0};
	u32				packed_bytes;
	int				ret;
	u32				total;
	FILE			*fp;

	packed_bytes=inlen;

	list_size = 0x50000;

	while ((packed_bytes>0) && (blob_pos[0]!=0x42)){ 			
		packed_bytes--;
		blob_pos++;
	};

	ret=1;
	while( (packed_bytes>0) && (ret==1) ){
		
		ret=unpack_4142 ((u32*)&new_list, &blob_pos, &packed_bytes, 0, 8, &list_size);

		while ((packed_bytes>0) && (blob_pos[0]!=0x42)){ 			
			packed_bytes--;
			blob_pos++;
		};

	};
	
	total=0;
	fp=fopen("./_getnodes.txt","a");
	fprintf(fp,":: new dump ::\n");
	dump_41_saveip (&new_list, fp, &total);
	fclose(fp);

	printf("::: %d nodes saved :::\n",total);

	return total;
};

