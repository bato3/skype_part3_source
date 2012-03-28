#ifndef _skype_dump_h_
#define _skype_dump_h_

#include "skype_basics.h"
#include <stdio.h>

#define error printf

#define MAX_MEM		4096

static void errdump (const u8 * const mem, const u32 n)
{
	u32		i, j, m = (__min(n,MAX_MEM)+15)&~15;
	char	s[80], *z;
	
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
		#if defined(_DEBUG) && defined(_MSC_VER)
			if (byte(m,n-1) != 0) __asm int 3;	// just in case
		#endif
		error ("%s: \"%s\"\n", header, m);
		break;
	case 4:	// BINARY
		error ("%s: %d bytes\n", header, n);
		errdump ((void*)m, n);
		break;
	case 5:	// recursion, gotta handle it upstairs
		#if defined(_DEBUG) && defined(_MSC_VER)
			__asm int 3;
		#endif
		break;
	case 6:	// 32-bit words
		s += sprintf (s = out, "%s: ", header);
		for (i = 0; i < n; i += 4) s += sprintf (s, "%02X %02X %02X %02X%s", dword(m,i)&0xFF, (dword(m,i)>>8)&0xFF, (dword(m,i)>>16)&0xFF, dword(m,i)>>24, (i+4<n)?", ":"");
		error ("%s\n", out);
		break;
	default:;
		#if defined(_DEBUG) && defined(_MSC_VER)
			__asm int 3;
		#endif
	}
}

static void dump_4142 (const u32 type, const u32 id, const u32 m, const u32 n)
{
	char		aid[12];
	
	sprintf (aid, "%02X-%02X", type, id);
	dump_blob (aid, type, m, n);
}

static void dump_4142_list (const skype_list *list)
{
	u32				i, l;
	
	if (!list) { error ("<empty>\n"); return; }
	if (!list->things || !list->thing) { error ("<empty>\n"); return; }
	for (i = 0, l = 0; i < list->things; i++)
	{
		if (list->thing[i].type == 5)
		{
			error ("05-%02X: {\n", list->thing[i].id);
			dump_4142_list ((skype_list *)list->thing[i].m);
			error ("05-%02X: }\n", list->thing[i].id);
			continue;
		}
		dump_4142 (list->thing[i].type, list->thing[i].id, list->thing[i].m, list->thing[i].n);
	}
}

#endif
