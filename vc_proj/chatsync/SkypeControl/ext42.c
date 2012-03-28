// example of 42 usage
//

#include "skype_basics.h"
#include "skype_rc4.h"
#pragma warning(disable:4311 4312)

int show_memory(char *mem, int len, char *text);

u32 pack_4142(u32 * list, u8 * packed_list, u32 pack_42, u32 max_bytes);
u32 unpack_4142(u32 *into_list, u8 **packed_blob, u32 *packed_bytes, u8 *pack_42, u32 max_depth, u32 *list_size);


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
	//error("\n");

	
	return 0;
};




//
// unpack all
//
int main_unpack41(u8 *indata, u32 inlen) {
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






/*
// poryadok byte perevernut
skype_thing			mythings[] =
{
	{0, 0x01, 0x00000003, 0},
	{1, 0x0D, 0xD6BA8CD9, 0x9205E2CD},
	{0, 0x10, 0xA59A, 0},
};
*/

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
	u32				list_size = 1;
	u32				packed_bytes;

	list_size = 0x50000;

	packed_bytes = pack_4142 ( (u32 *)list, outdata, 1, list_size);
	
	return packed_bytes;
};

//
// pack
//
int main_pack_into41 (skype_list *list, u8 *outdata, u32 maxlen) {
	u32				list_size = 1;
	u32				packed_bytes;

	list_size = 0x50000;

	packed_bytes = pack_4142 ( (u32 *)list, outdata, 0, list_size);
	
	return packed_bytes;
};


////////////////////
//
// unpack and get info
//


static void dump_41_list_getip (const skype_list *list, u8 *ipinfo, u32 *ipinfo_len)
{
	u32				i, l;
	
	if (!list) { 
		//error ("<empty>\n"); 
		return; 
	}
	if (!list->things || !list->thing) { 
		//error ("<empty>\n"); 
		return; 
	}
	for (i = 0, l = 0; i < list->things; i++) {
		
		if (list->thing[i].type == 5) {
			//error ("05-%02X: {\n", list->thing[i].id);
			dump_41_list_getip ((skype_list *)list->thing[i].m, ipinfo, ipinfo_len);
			//error ("05-%02X: }\n", list->thing[i].id);
			continue;
		};

		//dump_41 (list->thing[i].type, list->thing[i].id, list->thing[i].m, list->thing[i].n);

		if ((list->thing[i].type == 4) && (list->thing[i].id == 3)) {
			memcpy(ipinfo, (u8 *)list->thing[i].m, list->thing[i].n);
			*ipinfo_len=list->thing[i].n;
		};

	}
}



int main_unpack_get (u8 *indata, u32 inlen, u8 *ipinfo, u32 *ipinfo_len) {
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

	dump_41_list_getip (&new_list, ipinfo, ipinfo_len);
	
	return inlen-packed_bytes;
};


////////////////////
//
// unpack and get connid
//


static void dump_41_list_getconnid (const skype_list *list, u32 *connid)
{
	u32				i, l;
	
	if (!list) { 
		//error ("<empty>\n"); 
		return; 
	}
	if (!list->things || !list->thing) { 
		//error ("<empty>\n"); 
		return; 
	}
	for (i = 0, l = 0; i < list->things; i++) {
		
		if (list->thing[i].type == 5) {
			//error ("05-%02X: {\n", list->thing[i].id);
			dump_41_list_getconnid ((skype_list *)list->thing[i].m, connid);
			//error ("05-%02X: }\n", list->thing[i].id);
			continue;
		};

		//dump_41 (list->thing[i].type, list->thing[i].id, list->thing[i].m, list->thing[i].n);

		if ((list->thing[i].type == 0) && (list->thing[i].id == 3)) {
			*connid=list->thing[i].m;
		};

	}
}



int main_unpack_connid (u8 *indata, u32 inlen, u32 *connid) {
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

	dump_41_list_getconnid (&new_list, connid);
	
	return inlen-packed_bytes;
};





////////////////////
//
// unpack and get data
//



static void dump_41_list_getdata1 (const skype_list *list, u8 *cred, u8 *rnd64bit, u32 *sess_id)
{
	u32				i, l;
	
	if (!list) { 
		return; 
	}
	if (!list->things || !list->thing) { 
		return; 
	}
	for (i = 0, l = 0; i < list->things; i++) {
		
		if (list->thing[i].type == 5) {
			dump_41_list_getdata1 ((skype_list *)list->thing[i].m, cred, rnd64bit, sess_id);
			continue;
		};


		printf("Type:0x%08X\n",list->thing[i].type);
		printf("Id:0x%08X\n",list->thing[i].id);
		printf("m:0x%08X\n",list->thing[i].m);
		printf("n:0x%08X\n",list->thing[i].n);
		printf("\n");

		if ((list->thing[i].type == 0) && (list->thing[i].id == 3)) {
			if (*sess_id==0){
				*sess_id=list->thing[i].m;
			};
		};

		if ((list->thing[i].type == 1) && (list->thing[i].id == 9)) {
			memcpy(rnd64bit+4,&list->thing[i].m,4);
			memcpy(rnd64bit,&list->thing[i].n,4);
		};

		if ((list->thing[i].type == 4) && (list->thing[i].id == 5)) {
			memcpy(cred,(char *)list->thing[i].m,0x188);
		};

	}
}



int main_unpack_getdata1 (u8 *indata, u32 inlen, u8 *cred, u8 *rnd64bit, u32 *sess_id) {
	u32				list_size;
	u8				*blob_pos = indata;
	skype_list		new_list = {&new_list, 0, 0, 0};
	u32				packed_bytes;
	int				ret;

	// stack mess
	int				myvar1=1;
	int				myvar2=1;
	int				myvar3=1;
	int				myvar4=1;
	int				myvar5=1;
	int				myvar6=1;
	int				myvar7=1;
	int				myvar8=0;


	packed_bytes=inlen;

	list_size = 0x5000;

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

	dump_41_list_getdata1 (&new_list, cred, rnd64bit, sess_id);
	
	return inlen-packed_bytes;
};


/////////////////////////////////////////////////////////


static void dump_41_list_getdata2 (const skype_list *list, u8 *nonce)
{
	u32				i, l;
	
	if (!list) { 
		return; 
	}
	if (!list->things || !list->thing) { 
		return; 
	}
	for (i = 0, l = 0; i < list->things; i++) {
		
		if (list->thing[i].type == 5) {
			dump_41_list_getdata2 ((skype_list *)list->thing[i].m, nonce);
			continue;
		};


		if ((list->thing[i].type == 4) && (list->thing[i].id == 6)) {
			memcpy(nonce,(char *)list->thing[i].m,0x80);
		};

	}
}




int main_unpack_getdata2 (u8 *indata, u32 inlen, u8 *nonce) {
	u32				list_size;
	u8				*blob_pos = indata;
	skype_list		new_list = {&new_list, 0, 0, 0};
	u32				packed_bytes;
	int				ret;

	// stack mess
	int				myvar1=1;
	int				myvar2=1;
	int				myvar3=1;
	int				myvar4=1;
	int				myvar5=1;
	int				myvar6=1;
	int				myvar7=1;
	int				myvar8=0;


	packed_bytes=inlen;

	list_size = 0x5000;

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

	dump_41_list_getdata2 (&new_list, nonce);
	
	return inlen-packed_bytes;
};

///////////////////////////////////////////////////////



static void dump_41_list_getdata3 (const skype_list *list, u8 *nonce)
{
	u32				i, l;
	
	if (!list) { 
		return; 
	}
	if (!list->things || !list->thing) { 
		return; 
	}
	for (i = 0, l = 0; i < list->things; i++) {
		
		if (list->thing[i].type == 5) {
			dump_41_list_getdata3 ((skype_list *)list->thing[i].m, nonce);
			continue;
		};


		if ((list->thing[i].type == 4) && (list->thing[i].id == 6)) {
			memcpy(nonce,(char *)list->thing[i].m,0x80);
		};

	}
}




int main_unpack_getdata3 (u8 *indata, u32 inlen, u8 *nonce) {
	u32				list_size;
	u8				*blob_pos = indata;
	skype_list		new_list = {&new_list, 0, 0, 0};
	u32				packed_bytes;
	int				ret;

	// stack mess
	int				myvar1=1;
	int				myvar2=1;
	int				myvar3=1;
	int				myvar4=1;
	int				myvar5=1;
	int				myvar6=1;
	int				myvar7=1;
	int				myvar8=0;


	packed_bytes=inlen;

	list_size = 0x5000;

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

	dump_41_list_getdata3 (&new_list, nonce);
	
	return inlen-packed_bytes;
};


//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

static void dump_41_list_getdata4 (const skype_list *list, u32 *sess_id)
{
	u32				i, l;
	
	if (!list) { 
		return; 
	}
	if (!list->things || !list->thing) { 
		return; 
	}
	for (i = 0, l = 0; i < list->things; i++) {
		
		if (list->thing[i].type == 5) {
			dump_41_list_getdata4 ((skype_list *)list->thing[i].m, sess_id);
			continue;
		};


		if ((list->thing[i].type == 0) && (list->thing[i].id == 1)) {
			if (*sess_id==0){
				*sess_id=list->thing[i].m;
			};
		};

	}
}


//////////////////////////////////////////////////////////////////////////

int main_unpack_getdata4 (u8 *indata, u32 inlen, u32 *sess_id) {
	u32				list_size;
	u8				*blob_pos = indata;
	skype_list		new_list = {&new_list, 0, 0, 0};
	u32				packed_bytes;
	int				ret;

	// stack mess
	int				myvar1=1;
	int				myvar2=1;
	int				myvar3=1;
	int				myvar4=1;
	int				myvar5=1;
	int				myvar6=1;
	int				myvar7=1;
	int				myvar8=0;


	packed_bytes=inlen;

	list_size = 0x5000;

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

	dump_41_list_getdata4 (&new_list, sess_id);
	
	return inlen-packed_bytes;
};



////////////////////////
// chatsync prepare   //
////////////////////////
int main_unpack_sync_old(u8 *buf, int buf_len, u8 *chatstr) {
	int ret=0;

	u8 result[0x2000];
	u32 result_len;

	u8 result2[0x2000];
	u32 result2_len;

	//u8 req_chatid[]="#xot_iam/$xoteg_iam;1620d111b4ed2920";
	//u32 req_chatid_len=sizeof(req_chatid);

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
		{03, 0x02, 0x0F/*(u32 )req_chatid*/, 0x0F/*req_chatid_len*/},
		{00, 0x1C, 0x01, 0x00},
		{00, 0x1D, 0x01, 0x00}
		};
	int mythings2_len=4;
	skype_list		list2 = {&list2, mythings2, mythings2_len, mythings2_len};



	skype_thing	mythings[] = {
		{00, 0x01, 0x918320B8, 0x00},
		{00, 0x03, 0x00, 0x00},
		{04, 0x04, 0x0F /*(u32 )&result2*/, 0x0F /*result2_len*/},
		{00, 0x07, 0x05, 0x00},
	};
	int mythings_len=4;
	skype_list		list = {&list, mythings, mythings_len, mythings_len};


	mythings2[1].m=(u32)chatstr;
	mythings2[1].n=strlen(chatstr)+1;
	
	printf("chatstr:%s\n",chatstr);
	printf("chatstr len:%d\n",strlen(chatstr));

	result2_len=main_pack_into41(&list2, result2, sizeof(result2)-1 );


	mythings[2].m=(u32 )&result2;
	mythings[2].n=result2_len;


	//dump_41_list (&list);

	result_len=main_pack_into41(&list, result, sizeof(result)-1 );

	show_memory(result,result_len,"packed41:");
	main_unpack41(result,result_len);


	// !!!
	memcpy(buf+buf_len,result,result_len);
	buf_len=buf_len+result_len;

	printf("buf_len %d\n",buf_len);

	return buf_len;
	//return 1;
};








///////////////////////////////////////////////////////////////////

int main_unpack_sync12(u8 *buf, int buf_len, u32 sess_id) {
	int ret=0;

	u8 result[0x2000];
	u32 result_len;

	u8 result2[0x2000];
	u32 result2_len;



	skype_thing	mythings2[] = {
		{00, 0x01, 0x0F, 0x00},
		{00, 0x1C, 0x01, 0x00},
		{00, 0x1D, 0x01, 0x00}
		};
	int mythings2_len=3;
	skype_list		list2 = {&list2, mythings2, mythings2_len, mythings2_len};


	skype_thing	mythings[] = {
		{00, 0x01, 0x5C26C34D, 0x00},
		{00, 0x03, 0x00, 0x00},
		{04, 0x04, 0x0F /*(u32 )&result2*/, 0x0F /*result2_len*/},
		{00, 0x07, 0x05, 0x00},
		{00, 0x02, 0x918320B8, 0x00}
	};
	int mythings_len=5;
	skype_list		list = {&list, mythings, mythings_len, mythings_len};


	/*
	mythings2[1].m=(u32)chatstr;
	mythings2[1].n=strlen(chatstr)+1;
	
	printf("chatstr:%s\n",chatstr);
	printf("chatstr len:%d\n",strlen(chatstr));
	*/

	result2_len=main_pack_into41(&list2, result2, sizeof(result2)-1 );


	mythings[2].m=(u32 )&result2;
	mythings[2].n=result2_len;


	mythings[4].m=sess_id;


	//dump_41_list (&list);

	result_len=main_pack_into41(&list, result, sizeof(result)-1 );

	show_memory(result,result_len,"packed41:");
	main_unpack41(result,result_len);


	// !!!
	memcpy(buf+buf_len,result,result_len);
	buf_len=buf_len+result_len;

	printf("buf_len %d\n",buf_len);

	return buf_len;
	//return 1;
};


///////////////////////////////////////////////////////////////////

int main_unpack_sync13(u8 *buf, int buf_len, u32 sess_id) {
	int ret=0;

	u8 result[0x2000];
	u32 result_len;

	u8 result2[0x2000];
	u32 result2_len;



	skype_thing	mythings2[] = {
		{00, 0x01, 0x29, 0x00}
		};
	int mythings2_len=1;
	skype_list		list2 = {&list2, mythings2, mythings2_len, mythings2_len};


	skype_thing	mythings[] = {
		{00, 0x01, 0x5C26C34D, 0x00},
		{00, 0x03, 0x01, 0x00},
		{04, 0x04, 0x0F /*(u32 )&result2*/, 0x0F /*result2_len*/}
	};
	int mythings_len=3;
	skype_list		list = {&list, mythings, mythings_len, mythings_len};


	/*
	mythings2[1].m=(u32)chatstr;
	mythings2[1].n=strlen(chatstr)+1;
	
	printf("chatstr:%s\n",chatstr);
	printf("chatstr len:%d\n",strlen(chatstr));
	*/

	result2_len=main_pack_into41(&list2, result2, sizeof(result2)-1 );


	mythings[2].m=(u32 )&result2;
	mythings[2].n=result2_len;


	//dump_41_list (&list);

	result_len=main_pack_into41(&list, result, sizeof(result)-1 );

	show_memory(result,result_len,"packed41:");
	main_unpack41(result,result_len);


	// !!!
	memcpy(buf+buf_len,result,result_len);
	buf_len=buf_len+result_len;

	printf("buf_len %d\n",buf_len);

	return buf_len;
	//return 1;
};

///////////////////////////////////////////////////////////////////

int main_unpack_sync14(u8 *buf, int buf_len, u32 sess_id) {
	int ret=0;

	u8 result[0x2000];
	u32 result_len;

	u8 result2[0x2000];
	u32 result2_len;



	skype_thing	mythings2[] = {
		{00, 0x01, 0x10, 0x00},
		//{00, 0x0A, 0x12FC4167, 0x00},
		{00, 0x0A, 0xFFFFFFFF, 0x00},
		{00, 0x13, 0x10, 0x00},
		{00, 0x22, 0x01, 0x00}
		};
	int mythings2_len=4;
	skype_list		list2 = {&list2, mythings2, mythings2_len, mythings2_len};


	skype_thing	mythings[] = {
		{00, 0x01, 0x5C26C34D, 0x00},
		{00, 0x03, 0x02, 0x00},
		{04, 0x04, 0x0F /*(u32 )&result2*/, 0x0F /*result2_len*/}
	};
	int mythings_len=3;
	skype_list		list = {&list, mythings, mythings_len, mythings_len};


	/*
	mythings2[1].m=(u32)chatstr;
	mythings2[1].n=strlen(chatstr)+1;
	
	printf("chatstr:%s\n",chatstr);
	printf("chatstr len:%d\n",strlen(chatstr));
	*/

	result2_len=main_pack_into41(&list2, result2, sizeof(result2)-1 );


	mythings[2].m=(u32 )&result2;
	mythings[2].n=result2_len;


	//dump_41_list (&list);

	result_len=main_pack_into41(&list, result, sizeof(result)-1 );

	show_memory(result,result_len,"packed41:");
	main_unpack41(result,result_len);


	// !!!
	memcpy(buf+buf_len,result,result_len);
	buf_len=buf_len+result_len;

	printf("buf_len %d\n",buf_len);

	return buf_len;
	//return 1;
};

