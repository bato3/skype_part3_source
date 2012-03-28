// example of 42 usage
//


#include "skype_basics.h"
#include "skype_rc4.h"
#pragma warning(disable:4311 4312)



int show_memory(char *mem, int len, char *text){
	int zz;
	int i;

	printf("%s\n",text);
	printf("Len: 0x%08X\n",len);

	zz=0;
	for(i=0;i<len;i++){
		printf("%02X ",mem[i] & 0xff);
		zz++;if (zz == 16) { zz=0; printf("\n ");};
	};
	printf("\n");

	return 0;
};

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
	//error ("\n");
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
/*
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
*/
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

	while ((packed_bytes>0) && (blob_pos[0]!=0x41)){
		packed_bytes--;
		blob_pos++;
	};


	ret=1;
	while( (packed_bytes>0) && (ret==1) ){
		
		ret=unpack_4142 ((u32*)&new_list, &blob_pos, &packed_bytes, 0, 8, &list_size);

		while ((packed_bytes>0) && (blob_pos[0]!=0x41)){ 			
			packed_bytes--;
			blob_pos++;
		};

	};

	dump_41_list (&new_list);
	//error("\n");

	
	return 0;
};



//
// unpack exactly
//
int main_unpack_once (u8 *indata, u32 inlen) {
	u32				list_size = 0;
	u8				*blob_pos = indata;
	skype_list		new_list = {&new_list, 0, 0, 0};
	u32				packed_bytes;
	int				ret;

	packed_bytes=inlen;

	list_size = 0x50000;

	ret=unpack_4142 ((u32*)&new_list, &blob_pos, &packed_bytes, 0, 8, &list_size);

	dump_41_list (&new_list);

	
	return inlen-packed_bytes;
};







//
// pack
//
int main_pack (skype_thing *mythings, int mythings_len, u8 *outdata, u32 maxlen) {
	u32				list_size = 0;
	skype_list		list = {&list, mythings, mythings_len, mythings_len};
	u32				packed_bytes;


	list_size = 0x50000;

	packed_bytes = pack_4142 ( (u32 *)&list, outdata, 1, list_size);
	
	return packed_bytes;
};



//
// pack
//
int main_pack_into (skype_list *list, u8 *outdata, u32 maxlen) {
	u32				list_size = 2;
	u32				packed_bytes;

	list_size = 0x50000;

	packed_bytes = pack_4142 ( (u32 *)list, outdata, 0, list_size);
	
	return packed_bytes;
};




/*
////////////////////////
// udp push prepare //
////////////////////////
int main_unpack_push() {
	int ret=0;
	u8 result[0x2000];
	int result_len;
	int header_len=5;

	u8 req_user[]="xoteg_iam";


	// random
	u8 req_ipblock[]="\xAA\x21\xBB\x77\x6D\x6D\xAB\xF5\x01\xAA\xB8\xC1\x24\x87\x78\x3A\x44\xCE\x68\xF3\x14";

	u32 req_ipblock_len=sizeof(req_ipblock)-1;

	//xoteg_iam card
	u8 INIT_UNK[]="\xFF\xFF\xFF\xFF\xff\xff\xff\xff\x01\xB2\xB6\x7F\x47\xEF\x32";
	u32 INIT_UNK_len=sizeof(INIT_UNK)-1;

	u8 rnd64bit_[]="\x33\x50\x82\x48\xF9\xF9\xA4\x59";

	u32 rnd64bit_1=0x48825033;
	u32 rnd64bit_2=0x59A4F9F9;

	skype_thing	mythings3[] = {
		{00, 0x03, 0x2A7E, 0x00},
		{02, 0x08, 0x00,  0x00},
		{00, 0x10, 0x0A, 0x00}
	};
	int mythings3_len=3;
	skype_list		list3 = {-1, mythings3, mythings3_len, mythings3_len};

	skype_thing	mythings2[] = {
		{03, 0x00, (u32 )req_user, 0x00},
		{04, 0x01, (u32 )req_ipblock, req_ipblock_len},
		{00, 0x03, 0x63E0, 0x00},
		{05, 0x07, (u32 )&list3, 16},
		{01, 0x09, rnd64bit_1, rnd64bit_2},
		{00, 0x18, 0x01, 0x00},
		{00, 0x1B, 0x06, 0x00}
		};
	int mythings2_len=7;
	skype_list		list2 = {-1, mythings2, mythings2_len, mythings2_len};

	skype_thing	mythings[] = {
		{00, 0x00, 0x02, 0x00},
		{04, 0x01, (u32 )INIT_UNK, INIT_UNK_len},
		{00, 0x02, 0x43, 0x00},
		{05, 0x03, (u32 )&list2, 16},
		{00, 0x04, 0x1E, 0x00}
	};
	int mythings_len=5;

	skype_list		list = {-1, mythings, mythings_len, mythings_len};

	


	dump_41_list (&list);

	//result_len=main_pack_into(&list, result, sizeof(result)-1 );
	result_len=main_pack_into(&list, result, sizeof(result)-1 );

	if (DEBUG_LEVEL>=100) show_memory(result,result_len,"packed42:");
	if (DEBUG_LEVEL>=100) main_unpack(result,result_len);


	return 1;
};
*/







////////////////////////
// chatsync prepare   //
////////////////////////
int main_unpack_sync() {
	int ret=0;

	u8 result[0x2000];
	u32 result_len;

	u8 result2[0x2000];
	u32 result2_len;

	u8 req_chatid[]="#xot_iam/$xoteg_iam;1620d111b4ed2920";
	u32 req_chatid_len=sizeof(req_chatid);

	/*
	u8 test2[]=
"\x41\x04\x00\x01\x0D\x03\x02\x23\x78\x6F\x74\x5F\x69"
"\x61\x6D\x2F\x24\x78\x6F\x74\x65\x67\x5F\x69\x61\x6D\x3B\x31\x36"
"\x32\x30\x64\x31\x31\x31\x62\x34\x65\x64\x32\x39\x32\x30\x00\x00"
"\x1C\x01\x00\x1D\x01"
;
	u32 test2_len=sizeof(test2)-1;
	*/



	skype_thing	mythings2[] = {
		{00, 0x01, 0x0D, 0x00},
		{03, 0x02, (u32 )req_chatid, req_chatid_len},
		{00, 0x1C, 0x01, 0x00},
		{00, 0x1D, 0x01, 0x00}
		};
	int mythings2_len=4;
	skype_list		list2 = {-1, mythings2, mythings2_len, mythings2_len};



	skype_thing	mythings[] = {
		{00, 0x01, 0x918320B8, 0x00},
		{00, 0x03, 0x00, 0x00},
		{04, 0x04, 0x0F /*(u32 )&result2*/, 0x0F /*result2_len*/},
		{00, 0x07, 0x05, 0x00},
	};
	int mythings_len=4;
	skype_list		list = {-1, mythings, mythings_len, mythings_len};


	
	result2_len=main_pack_into(&list2, result2, sizeof(result2)-1 );


	mythings[2].m=(u32 )&result2;
	mythings[2].n=result2_len;


	//dump_41_list (&list);

	result_len=main_pack_into(&list, result, sizeof(result)-1 );

	show_memory(result,result_len,"packed41:");
	main_unpack(result,result_len);


	return 1;
};


