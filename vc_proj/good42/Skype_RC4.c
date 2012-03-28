#include "skype_basics.h"
#include "skype_rc4/skype_rc4.h"
//#include "md5/md5.h"
//#include "sha1/sha.h"
#include "rijndael/rijndael.h"
#pragma warning(disable:4311 4312)


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
	char		*s, out[1024];
	
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
		error ("%s\n", s);
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
		if (list->thing[i].type == 5)
		{
			dump_41_list ((skype_list *)list->thing[i].m);
			continue;
		}
		dump_41 (list->thing[i].type, list->thing[i].id, list->thing[i].m, list->thing[i].n);
	}
}

skype_thing			things[] =
{
	{1, 0x0D, 0x6042341A, 0xC26F4A39},
	{0, 0x10, 0x2553, 0},
	{0, 0x01, 0xDE, 0},
	{0, 0x23, 0, 0}
};


//"\x42\xB1\x26\x04\x5B\x71\x78\x53\xD7\xC9\x67\x47\x0E\x73\x8F\x27\x2C\x2A\x3D\x25\x4E\xDE\x3A\x58\xEC\xDC\x07\x59"
//"\x42\xB0\x9F\x68\x98\x3D\xA7\x1E\xF9\x02"
//"\x42\xF6\x43\x86\x85\x75\x52\x8D\x7A\xED\xEB\x3B\xEB\xEF\x4D\x2D\x95\x66\x2E\x6B\xB8\x68\xBF\xB8\xC4\x17\x84\x89\x06\x02"

u8	packed_blob[] = 
"\x42\xB1\x26\x04\x5B\x71\x78\x53\xD7\xC9\x67\x47\x0E\x73\x8F\x27\x2C\x2A\x3D\x25\x4E\xDE\x3A\x58\xEC\xDC\x07\x59"
;

/*
"\x41\x0B\x00\x03\xD8\x4C\x04\x01\x15\xBA\xA1\x97\x19\xA6"
"\xC4\xF0\xC6\x01\xC0\xA8\x01\x1C\xB3\x39\x43\xA2\xAD\x8F\x7D\x48"
"\x01\x09\xF4\x5C\xA4\xFF\x4C\x91\x20\x3A\x00\x1B\x06\x05\x07\x41"
"\x03\x02\x08\x4E\x74\x8A\x5F\xDA\x25\x00\x03\xDC\xAC\x01\x00\x10"
"\x0A\x00\x16\x01\x00\x1A\x01\x00\x02\x80\xE1\x94\xF1\x04\x04\x05"
"\x88\x03\x00\x00\x01\x04\x00\x00\x00\x01\x6E\x54\x2A\x45\x96\x97"
"\x37\xEE\x72\x76\x83\xB1\x4A\xE4\x7F\xAE\x86\x6D\xD9\x54\x65\xF4"
"\x64\x5A\xB5\x57\xCC\x88\x1A\x04\x59\x14\x88\xEB\x9C\xCA\x15\x89"
"\x23\x26\xC9\x29\x41\x6F\x4C\x6D\x70\x9D\x5F\x42\x04\xEF\xF3\xD8"
"\xF5\xCB\xBB\xF7\x92\xBA\x78\x2B\xF9\x89\x4B\x5A\x81\x72\x5D\x38"
"\x28\xC0\x2A\x03\x36\xA0\xB3\x95\x91\x8E\x58\x74\xC6\xBE\xA5\x97"
"\xDA\xA5\xF4\xBA\x0D\x75\x9B\x2F\x05\xA8\x76\x28\x34\xAA\xF2\x86"
"\x43\x2A\xBF\x9E\x12\x79\xDA\x47\x6C\x7E\xAC\xDF\x54\x36\x27\x1B"
"\xAC\x32\x81\x2A\xB5\x20\x06\xD1\xCD\xF4\xBB\x72\x89\x0C\x61\x3D"
"\x0D\xE7\x60\x3C\xD5\x14\x70\xA8\x4E\xC0\x17\x45\xC0\x96\xA1\x3A"
"\x82\x21\x29\x77\x60\x66\xB5\xD0\xCD\xEB\x89\x27\xE1\x6D\x63\xEC"
"\x52\x11\x13\x61\xF4\x65\xE8\xB6\x84\x57\x30\xD4\x55\x4C\x16\x12"
"\x3E\x73\x30\xEF\x4E\x77\x41\xF5\xC8\x6A\xE5\x0F\xB0\xE6\x73\x67"
"\x3B\x49\x3F\x4F\xD5\xDB\x20\xAF\x3C\x96\x43\x4F\xA8\xC6\xAE\xC0"
"\x4F\x41\x2F\xBA\xF9\x86\x36\x4D\x8A\x86\xDD\xF7\x12\xAD\xF0\x2C"
"\xA0\x58\xFF\xC7\xCA\x74\x01\x3F\x47\x2A\x6D\x4B\x37\x9E\x76\x50"
"\x7C\xE5\xAD\xE0\x30\x7F\xCD\x51\x6B\xB4\x66\xB9\xFD\x82\x3F\x93"
"\x5E\x43\x33\x79\x16\x94\xA7\x53\x0A\xFA\x3F\x25\xE1\xD0\x6A\x07"
"\x68\xDD\x1F\x0D\xDE\x90\x63\xA3\xE2\xDB\x1D\x4F\x8C\x94\x33\xF0"
"\x19\x0B\x89\x94\x51\x03\x7C\x65\x3D\xA2\x1C\x6B\x99\xBD\xDA\x40"
"\x65\x1A\x35\x23\x6A\xAB\x7B\xFC\x22\xFF\x8D\xFA\xC6\x5F\xAF\xA4"
"\x1D\x4B\x8C\x55\xF6\x47\xAC\x74\x53\x83\xF1\xB8\x12\xA7\xBA\xB4"
"\x86\x65\xB2\x85\xBE\xDD\x99\x7A\xFB\x99\x6A\xA8\x51\x9C\x18\x00"
"\xE5\xAA\x69\x7A\x58\x12\x19\x72\x7F\xC1\x63\xB8\x5A\x40\x5E\xBB"
"\x25\x2A\xF2\x1C\x72\x99\x1A\x56\x05\x96\x00\x0D\x02\x04\x0A\x80"
"\x01\x6E\x24\x81\x25\xC1\xC5\xE8\xB2\xC4\xE8\x79\x69\xA6\x06\xC6"
"\x29\x12\x25\x63\xBC\xAB\xB5\x3E\x21\x2C\xF2\x73\x8F\x4C\xA8\xFF"
"\xBE\xBA\xA3\x91\x51\x51\x52\xCB\xC8\x43\x2C\x12\xF4\x87\x12\xD9"
"\xB8\x05\x9B\xC8\xD9\xCA\xF9\x9E\x25\xF1\x02\x51\x91\x03\xB5\xED"
"\x8F\xA5\x90\xDD\x02\x76\xBB\x42\x01\x38\xE1\x88\xB7\xAA\x32\x5B"
"\xF1\xE7\x6A\x66\xE8\x99\x25\xAF\xF5\x67\xDB\x44\xE2\x05\xB5\x12"
"\x06\x30\x29\x3B\x2E\x28\xF1\x7E\xE1\x34\xBD\x2E\xFA\x5F\x1B\xE6"
"\x91\xD1\x2C\xA1\xC8\xBD\x67\x93\x31\x32\x36\x4C\x37\x1D\x95\x71"
"\x18\x94\xAC\xB3\x34"
;
*/

//"\x42\xB1\x26\x04\x5B\x71\x78\x53\xD7\xC9\x67\x47\x0E\x73\x8F\x27\x2C\x2A\x3D\x25\x4E\xDE\x3A\x58\xEC\xDC\x07\x59"


/*
"\x42\xB0\x9F\x68\x98\x3D\xA7\x1E\xF9\x02"
"\x42\xF6\x43\x86\x85\x75\x52\x8D\x7A\xED\xEB\x3B\xEB\xEF\x4D\x2D\x95\x66\x2E\x6B\xB8\x68\xBF\xB8\xC4\x17\x84\x89\x06\x02"
;*/
;

/*
"\x42\x57\x4A\x5B\xF7\xD3\x73\xC6\xA6\x22\x7D\x1A\x34\x42\x60\x39\x4A\x6F\xC2"
;
*/


/*
u8					packed_blob[] =
{
 0x42,0x57,0x4A,0x5B,0xF7,0xD3,0x73,0xC6,0xA6,0x22,0x7D,0x1A,0x34,0x42,0x60,0x39,0x4A,0x6F,0xC2
};
*/

u32				packed_bytes = sizeof (packed_blob)-1;


int main (void)
{
	u8				blob[] = {0};
	int readed;
	u32				list_size = 0;
	u8				*blob_pos = packed_blob;
	skype_list		new_list = {&new_list, 0, 0, 0}, list = {&list, things, 4, 4};
	int ok=0;

	list_size = 0x50000;
	printf("before packed_bytes=%d\n",packed_bytes);
	readed=unpack_4142 ((u32*)&new_list, &blob_pos, &packed_bytes, 0, 8000, &list_size);
	printf("readed=%x\n",readed);
	printf("after packed_bytes=%d\n",packed_bytes);

	dump_41_list (&new_list);
	error ("\n");

	exit(1);

	blob_pos=blob_pos+5;
	packed_bytes-=5;
	printf("before packed_bytes=%d\n",packed_bytes);
	readed=unpack_4142 ((u32*)&new_list, &blob_pos, &packed_bytes, 0, 8, &list_size);
	printf("readed=%x\n",readed);
	printf("after packed_bytes=%d\n",packed_bytes);

	//dump_41_list (&new_list);
	//error ("\n");

	//exit(1);

	blob_pos=blob_pos+3;
	packed_bytes-=3;
	printf("before packed_bytes=%d\n",packed_bytes);
	readed=unpack_4142 ((u32*)&new_list, &blob_pos, &packed_bytes, 0, 8, &list_size);
	printf("after readed=%x\n",readed);

	dump_41_list (&new_list);
	error ("\n");


	/*
	packed_bytes = pack_4142 ((u32*)&new_list, packed_blob, 1, list_size);
	
	list_size = 0x50000;
	unpack_4142 ((u32*)&new_list, &blob_pos, &packed_bytes, 0, 8, &list_size);
	dump_41_list (&new_list);
	error ("\n");
	packed_bytes = pack_4142 ((u32*)&new_list, packed_blob, 1, list_size);

  */


	return 0;
}
