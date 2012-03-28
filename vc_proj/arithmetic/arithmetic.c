#include <stdio.h>
#include <stdlib.h>


//functions used in decode process
int next_byte();
int mysub_call_eax_5008509F8_mysub_rabota_s_pkt_recv_no_call_DECRYPT();
int mysub_some_math_get_next_byte_cikl();
void flush_decode();
void copy_memory(unsigned int param1, unsigned int param2, unsigned int len);
int mysub_attribute_container_encoder(unsigned int p1);
int jmp_tbl_attr_encoder(unsigned int par1, unsigned int par2);
unsigned int mysub_some_math_call_edx_0_get_next_byte_cikl_wrap(unsigned int table_ptr, unsigned int sdvig);
int mysub_some_math_41_get_next_byte(unsigned int table_ptr, unsigned int hz);
int mysub_some_math_42(unsigned int ebx);
int mygen_no_call_00850F30(unsigned int off);


//init function
int init_arithmetic();

//nice print help internal function 
void print_big(int exit_now);

//global variables
static char *buf;
static unsigned int *outbuf;
static unsigned int outlen;

// 0 - debug msg off
// 1 - debug msg on
static unsigned int DEBUG = 0;




//internal data

//test case 8
//static char buf[]=
//"\x42\xb0\x9f\x48\x6f\xf4\xb0"
//;
//INTEGER:00A837AC
//INTEGER:11024300

//test case 7
//static char buf[]="\x42\xb0\x9f\x66\x87\x5d\xea";
//INTEGER:00A5D4DC
//INTEGER:10867932

//test case 6
//1e after network stat with 0x42
//static char buf[]=
//"\x42\xF6\x43\x86\x86\x4D\x23\xB8\xB4\xED\xEB\x3B\xF5\xCB\x7B\x72\xB1"
//"\x66\x2C\xE6\x97\x9A\xA0\xB8\xC4\x17\x84\x87\xBB\xD7\x56"
//;
//I:0x00000002 D:2
//I:0x0CABA34F D:212575055
//I:0x00000100 D:256
//I:0x01348C89 D:20221065
//I:0x00000003 D:3
//I:0x0C3BA9E3 D:205236707
//I:0x00000004 D:4
//I:0x00000002 D:2
//I:0x00000005 D:5
//I:0x00000018 D:24

//test case 5
//static char buf[]=
//"\x42\xF6\x43\x86\x86\x4D\x23\xB8\xB4\xED\xEB\x3B"
//"\xFF\xE1\x81\x6A\xB1\x66\x2C\xE6\x97\x9A\xA0\xB8\xC4\x17\x84\x87\xE2\x32"
//;

//I:0x00000002 D:2
//I:0x0CABA34F D:212575055
//I:0x00000100 D:256
//I:0x0134B8D5 D:20232405
//I:0x00000003 D:3
//I:0x0C3BA9E3 D:205236707
//I:0x00000004 D:4
//I:0x00000002 D:2
//I:0x00000005 D:5
//I:0x00000019 D:25

//test case 4
//static char buf[]=
//"\x42\x3D\xA4\x27"
//;
//I:0x00000001 D:1
//I:0x0000003F D:63

//test case 3
//static char buf[]=
//"\x42\xB1\xFC\x83\x09\x5F\x57\x1F\xE1\x5E\x8D\xF3\xD2\xEA\xE5\x7E\x75\xFA"
//;
//failed
//I:0x00000001 D:1
//I:0x00000004 D:4
//I:0x0000000D D:13
//should be
//11:45:50 I:0x00000001 D:1 
//11:45:50 I:0x00000004 D:4 
//11:45:50 I:0x0002D548 D:185672 

//test case 2
//static char buf[]=
//"\x42\xB1\x25\xF2\x82\x8A\xB3\xAC\xC0\xCC\xAF\x29\x4A\x73\x90\x92\xBD\x0D\x2E"
//"\x5D\xFB\xFE\xD5\x72\xE4\xBA\xC2\x7A\x0D"
//;
//I:0x0000002C D:44
//I:0x2FCDB925 D:802011429
//I:0x0000BE46 D:48710
// 11 bytes left ???????

//test case 1
//static char buf[]=
//"\x42\xB0\x9F\x4F\x43\xF1\xAA"
//;
//I:0x009A5B57 D:10115927



//
//arithmetic decode table
//needed for arithmetic algo
//
static char table1[]=
"\x00\x00\xA3\x02\x7C\x03\x7C\x06\xA3\x06\xAE\x06\x84\x0A\x74\x0B"
"\xAD\x0D\x5D\x0F\xB2\x0F\xD4\x0F\xFF\x0F\x00\x10\x00\x00\x23\x01"
"\x66\x02\xB4\x02\xA2\x08\xF5\x09\xFC\x0C\x70\x0F\xFF\x0F\x00\x10"
"\x00\x00\x4D\x01\x4C\x03\x2B\x04\xA3\x04\xCA\x06\x53\x09\xC6\x09"
"\x6C\x0A\xBB\x0A\xAE\x0B\x43\x0C\x9B\x0C\xDD\x0C\x31\x0D\x93\x0D"
"\xB5\x0D\x00\x10\x00\x00\x00\x00\x07\x00\x00\x00\x02\x00\x00\x00"
"\x01\x00\x00\x00\x74\x82\x9A\x00\x10\x00\x00\x00\x01\x00\x00\x00"
"\x00\x00\x00\x00\x88\x82\x9A\x00\x80\xFF\x84\x00\x10\xD1\x78\x00"
"\xC0\xFA\x84\x00\x90\x53\x87\x00\xC0\x09\x85\x00\xA0\x09\x85\x00"
"\x03\x00\x00\x00\xF0\x48\x81\x00\xF0\x48\x81\x00\x90\x53\x87\x00"
"\x90\x53\x87\x00\xE0\x4A\x7D\x00\x90\x53\x87\x00\x90\x53\x87\x00"
"\x90\x53\x87\x00\xE0\x4A\x7D\x00\xF0\x48\x81\x00\xF0\x48\x81\x00"
"\xF0\x48\x81\x00\xF0\x48\x81\x00\x90\x53\x87\x00\xF0\x48\x81\x00"
"\x90\x53\x87\x00\x90\x53\x87\x00\x90\x53\x87\x00\x30\xB9\x80\x00"
"\xF0\x48\x81\x00\xE0\x4A\x7D\x00\xE0\x4A\x7D\x00\xA0\x78\x7B\x00"
"\xA0\x78\x7B\x00\xF0\x48\x81\x00\x90\x8A\x72\x00\x30\xB9\x80\x00"
;
//         ^^^^^^ tolko li do suda realno nujno..
//         v 0x58 + 0xc ptr \x74\x82\x9A\x00



// big unexplored structure

struct _big_struct {
        unsigned int off_0;
        unsigned int off_4;     // schitanniy byte / 2
        unsigned int off_8;     // 0x80..itd, flag or counter or mask or smth..     
        unsigned int off_c;     // schitanniy iz buffera byte
        unsigned int off_12;    

		//unsigned int off_ae;	//eax+9c
		//unsigned int off_12;	//eax
		unsigned int off_16;	//eax+4
		unsigned int off_1a;	//eax+8
		unsigned int off_1e;	//eax+c
		unsigned int off_22;	//eax+10
		unsigned int off_26;	//eax+14
		unsigned int off_2a; //=1 //eax+18
		
		unsigned int off_36; //
		unsigned int off_3a; //

		unsigned int off_3e;
		unsigned int off_42;
		unsigned int off_de;
		unsigned int off_e2;

		unsigned int off_14e;	//eax+9c
		unsigned int off_b2;	//eax
		unsigned int off_b6;	//eax+4
		unsigned int off_ba;	//eax+8
		unsigned int off_be;	//eax+c
		unsigned int off_c2;	//eax+10
		unsigned int off_c6;	//eax+14
		unsigned int off_ca; //=1 //eax+18
		unsigned int off_ce; //=1 //eax+18

		unsigned int off_d2; //=1 //eax+18

		unsigned int off_d6; //=1 //eax+18
		unsigned int off_da; //=1 //eax+18

		unsigned int off_1ee;	//eax+9c
		unsigned int off_152;	//eax
		unsigned int off_156;	//eax+4
		unsigned int off_15a;	//eax+8
		unsigned int off_15e;	//eax+c
		unsigned int off_162;	//eax+10
		unsigned int off_166;	//eax+14
		unsigned int off_16a; //=1 //eax+18

        
		unsigned int off_2e;
        unsigned int off_32;
        unsigned int off_ae;
        unsigned int off_ea;
        unsigned int off_1f2;   //??
        char *off_1f6;          //current byte in buf ptr
        unsigned int off_1fa;   //bytes to left
        unsigned int off_1fe;   //some counter
        unsigned int off_202;   //exit indicator
        unsigned int off_206;
        unsigned int off_20a;
        unsigned int off_20e;
        unsigned int off_212;
        unsigned int off_216;
		unsigned int off_316;
		unsigned int off_31a;
		unsigned int off_31e;
		unsigned int off_322;
		unsigned int off_522;
		unsigned int off_526;

};

struct _big_struct big;

//podschitivaem skolko raz funckiya zapuskalas
unsigned int count41;
unsigned int count_wrap;
unsigned int count42;
unsigned int count_get_next_byte_cikl;
unsigned int count_next_byte;
unsigned int count_jmp_tbl;

//uchitivaem kol-vo rekursiy
unsigned int rekurs=1;

/*
*  Initialize structure, and call decode
*/

unsigned long unpack (void *inptr, unsigned long inlength, void *outptr){


	buf=inptr;
	big.off_1fa = inlength;

	outlen=0;
	outbuf=outptr;
	
	init_arithmetic();


	return outlen;
};


int init_arithmetic(){
        //int i;

		unsigned int len;

		//len=sizeof(buf)-1;

		len = big.off_1fa;
		
		if (DEBUG) {
			printf("len:%d\n",len);
		};

        big.off_0   = 0x009a82dc;
        big.off_4   = 0x0; // schitanniy byte / 2
        big.off_8   = 0x0; // 0x80..itd, flag or counter or mask or smth..
        big.off_c   = 0x0; // schitanniy iz buffera byte
        big.off_12  = 0x0;

		big.off_ae=0;	//eax+9c
		big.off_12=0;	//eax
		big.off_16=0;	//eax+4
		big.off_1a=0;	//eax+8
		big.off_1e=0;	//eax+c
		big.off_22=0;	//eax+10
		big.off_26=0;	//eax+14
		big.off_2a=0; //=1 //eax+18

		big.off_14e=0;	//eax+9c
		big.off_b2=0;	//eax
		big.off_b6=0;	//eax+4
		big.off_ba=0;	//eax+8
		big.off_be=0;	//eax+c
		big.off_c2=0;	//eax+10
		big.off_c6=0;	//eax+14
		big.off_ca=0; //=1 //eax+18

		big.off_1ee=0;	//eax+9c
		big.off_152=0;	//eax
		big.off_156=0;	//eax+4
		big.off_15a=0;	//eax+8
		big.off_15e=0;	//eax+c
		big.off_162=0;	//eax+10
		big.off_166=0;	//eax+14
		big.off_16a=0; //=1 //eax+18


        big.off_2e  = 0xb6865014;
        big.off_32  = 0x00007c91;
        big.off_ae  = 0x0;
        big.off_ea  = 0xffff0000;
        big.off_1f2 = 0x00000008;   //??
        big.off_1f6 = buf; // curr byte in buf ptr
        //big.off_1fa = len; // left_bytes
        big.off_1fe = 0x0; // some counter
        big.off_202 = 0x0; // exit indicator
        big.off_206 = 0x0;
        big.off_20a = 0x0;
        big.off_20e = 0x0004b000;//0x02c3f740;
        big.off_212 = 0x02C3F3FA;
        big.off_216 = 0x02C3F3FA;
		big.off_316 = 0x0;
		big.off_31a = 0x0;
		big.off_31e = 0x02C3F506;
		big.off_322 = 0x02C3F506;
		big.off_522 = 0x0;
		big.off_526 = 0x0;


		//printf("sizeof buf:0x%x\n",sizeof(buf)-2);
		//exit(0);

		//init 
		count41=0;
		count_wrap=0;
		count42=0;
		count_get_next_byte_cikl=0;
		count_next_byte=0;
		count_jmp_tbl=0;
		
		if (DEBUG){
			printf("Run: flush_decode\n");
		};

        flush_decode();

		if (DEBUG){
			printf("End: flush_decode\n");
		};


        return 0;
}

/*
*    Next_byte()
*    Schitivaem sleduushiy byte
*    Count_next_byte==5 unexplored
*    esli ne ostalos byte, uvelichivaem some counter,
*    esli some counter > 3, vihod iz 0x42 decrypt
*    t.e. posle 4 neudachnogo zahoda suda, kogda ne ostalos byte 
*    esli byte ostalis, schitivaem ego i vozvrashaem znachenie,
*    pri etom uvelichivaem buf ptr, i umenchaem bytes left 
*
*/

int next_byte(){
        int left_cnt;
        char *bufptr;
        unsigned int buf_byte;
        unsigned int some_cnt;

		count_next_byte++;
	
		if (DEBUG){
			printf("Run: next_byte: %d\n",count_next_byte);
		};

        left_cnt=big.off_1fa;

		//printf("BYTES LEFT:%d\n",left_cnt);

		if (count_next_byte==5){

			//
		};

        if (left_cnt == 0){

                some_cnt=big.off_1fe;
                some_cnt++;

                big.off_1fe=some_cnt;

                if (some_cnt > 3) {
                        big.off_202=1;
                };

				if (DEBUG){
					printf("End: next_byte\n");
				};

                return 0;
        };

        left_cnt--;
        big.off_1fa=left_cnt;



        bufptr=big.off_1f6;
        buf_byte=bufptr[0];
        bufptr++;
        big.off_1f6=bufptr;

		if (DEBUG) {
			printf("GET BYTE:0x%02X\n",buf_byte & 0xff);
			printf("BYTES LEFT:%d 0x%02X\n",left_cnt,left_cnt);

			printf("End: next_byte\n");
		};

        return buf_byte;
}



/*
* 
*  mysub_call_eax_5008509F8_mysub_rabota_s_pkt_recv_no_call_DECRYPT
*
*  Schitivaem byte 
*  inizializiruem structuru, 
*  off_4 -- byte / 2 
*  off_8 -- 0x80 mask ?
*  off_c -- byte
*
*/

int mysub_call_eax_5008509F8_mysub_rabota_s_pkt_recv_no_call_DECRYPT (){
			unsigned int eax;

			if (DEBUG) {
				printf("Run: mysub_call_eax_5008509F8_mysub_rabota_s_pkt_recv_no_call_DECRYPT\n");
			};

			eax=next_byte(); //schitivaem byte


            big.off_c=eax;  //schitanniy byte

            eax=eax & 0xff; //ostavlaem tolko odin byte prochitanniy
            eax=eax >> 1;   //delenie na 2, eax = eax / 2

            big.off_4=eax;  //schitanniy byte / 2
			big.off_8=0x80; //flag or counter or mask or smth

			if (DEBUG) {
				printf("End: mysub_call_eax_5008509F8_mysub_rabota_s_pkt_recv_no_call_DECRYPT\n");
			};

			return 0;

};


/*
*  poluchaetsya chto nabiraem 4 byte int, hitrim obrazom, i schitivaem 4 byte, 1 do i 3 v cikle 
*
*  reading new byte, 
*  kol-vo cikov zavisit ot sosotoyani mask big.off_c
*  off_4 eto obichnoy /2 , no s predidushim, no slojeniem ne polnim a *0x80 vmesto *0x100 , 
*  t.e. samiy perviy starhiy bit proyabivaetsya ?
*
*/

//int func_bef_get_next_byte()
int mysub_some_math_get_next_byte_cikl(){
        unsigned int eax;
        unsigned int ecx,edx;

		count_get_next_byte_cikl++;

		if (DEBUG) {
			printf("Run: mysub_some_math_get_next_byte_cikl: %d\n",count_get_next_byte_cikl);
		};




        if (big.off_8 > 0x00800000) { // 3-iy cikl.. counter > 3 

				if (DEBUG) {
					printf("End: mysub_some_math_get_next_byte_cikl\n");
				};

                return 0;
        };


        do {



                eax=big.off_c;   // orig byte
                ecx=big.off_4;   // shr-ed byte (byte/2)
                //edx=big.off_0; // for what ?

                eax=eax & 0x1;   //ostaetsya posledniy znacheshiy bit u orig byte

                ecx=ecx << 1;    // ecx=(all bytes/2)*2 , pri etom posledniy bit vsegda 0
                eax=eax | ecx;   // slivaem vmeste orig i shr-ed byte, t.e. esli nechetnoe znach orig byte, to sdes +1
                eax=eax << 7;    // shred, shifted , * 0x80(128) 2 v 7 stepeni
                big.off_4=eax;   // sohranyaem

				//print_big(0);
                eax=next_byte(); // new byte

                edx=big.off_4;   // prev byte * 0x80
                ecx=big.off_8;   // mask cnt
                big.off_c=eax;   // new byte, orig

				/*
				if (count_get_next_byte_cikl==4){
					print_big(1);
				};
				*/

                eax=eax & 0xff; // new byte, only one !
                eax=eax >> 1;   // new byte / 2

                ecx=ecx << 8;   // mask sdvig na 1 byte . ecx=ecx * 0x100(256)
                edx=edx | eax;  // pred byte * 0x80 + new byte / 2

                eax=ecx;

                big.off_4=edx;  //nakopitel.. pred byte * 0x80 + new byte / 2
                big.off_8=ecx;  //mask, *0x100
				
				print_big(0);

				if (DEBUG) {
					printf("EAX(mask off_8):%08x\n",eax);
				};

        } while (eax <= 0x00800000);  // cikl do 3-h vmeste s pervim bytom == 4 pervih byte read
									  // no s uchetom pred sostoyania mask

		if (DEBUG) {
			printf("End: mysub_some_math_get_next_byte_cikl\n");
		};

		return 0;
}


/*
* interlnal print helper func
*/

void print_big(int exit_now){

		if (DEBUG) {

			printf("big.off_4=%08X\n",big.off_4);
			printf("big.off_8=%08X\n",big.off_8);
			printf("big.off_c=%08X\n",big.off_c);
		};

		if (exit_now){

			exit(0);
		};
};

/*
*  mojet bit init vector kakont.. 
*
*  Initialize some buf structure
*  tri strukturi zabiti kakimi to strannimi dannimi
*  odna +9c, i ot 0x0 do 0x18
*
*/

void mysub_cikl_do_a0() {
		unsigned int ecx,edx;
		
		//eax=eax+0x12 eax=big+0x12;

		ecx=3;
		edx=1;

		

		//eax=big+0x12
		//do {
			big.off_ae=0;	//eax+9c
			big.off_12=0;	//eax
			big.off_16=4;	//eax+4
			big.off_1a=3;	//eax+8
			big.off_1e=5;	//eax+c
			big.off_22=2;	//eax+10
			big.off_26=6;	//eax+14
			big.off_2a=edx; //=1 //eax+18

			//			eax=eax+a0; // big.off_b2

		//	ecx--;

			big.off_14e=0;	//eax+9c
			big.off_b2=0;	//eax
			big.off_b6=4;	//eax+4
			big.off_ba=3;	//eax+8
			big.off_be=5;	//eax+c
			big.off_c2=2;	//eax+10
			big.off_c6=6;	//eax+14
			big.off_ca=edx; //=1 //eax+18

			//			eax=eax+a0; // big.off_b2

		//	ecx--;

			big.off_1ee=0;	//eax+9c
			big.off_152=0;	//eax
			big.off_156=4;	//eax+4
			big.off_15a=3;	//eax+8
			big.off_15e=5;	//eax+c
			big.off_162=2;	//eax+10
			big.off_166=6;	//eax+14
			big.off_16a=edx; //=1 //eax+18

		//}while(ecx);



};

/*
*
*  Inicializiruet sostoyanie dlya dekodinga rekursivnogo
*  proveryaet tip encodinga 
*  schitivaem perviy byte, chtobi inicializirovatt vsu big strukturu pravilno
*  hmm decode_context inicializiruetsya..
*
*  Vizivaem iz main, v kotorom toka inicializciruem nek-ptr v big structure
*  Inicializiruem nemnogo v big struct eshe
*  schitivaem perviy byte, esli on ne 0x42, vihodim
*  vizivaem mysub_cikl_do_a0 , kot-raya eshe inicializiruem big struct 
*  vizivaem mysub_call_eax_5008509F8_mysub_rabota_s_pkt_recv_no_call_DECRYPT
*      kotoraya schitivaet perviy byte i inicializiruet strukturu
*			off_c, orig schitanniy byte
*			off_8, mask
*			off_4,  byte /2
*
*  vizivaem jmp_tbl_attr_encoder() , v kotoroy i proishodit ves dekoding
*  s parametrom var1 takim je kak v flush_decode, i var2 = 0 , 
*  t.e. perviy vizov bez rekursiiy, ili kol-vo rekursiy poka = 0
*
*/


//Flush_Decode_850F60_mysub_attr_encoder_flush_decoder_returned_invalid_postprocess_attr_type
//param1=esi=02C3F78C
//param2=eax=02C3F740
// push eax
// push esi
// call flush_decode
void flush_decode() {
        int big2=0x02a9f78c;
		int ret;
        unsigned int param1=0x02C3F78c;
        unsigned int param2=0x02C3F740;
		unsigned int ecx,eax,ebx,edx,edi,esi,ebp;
		unsigned int esp_15c;

		//sub esp,148
		ebx=0;
		esi=0; // disable annoing warnings of unused parameters
		edx=0;

		//mov esi, ecx //big struct
		

		//mov ecx,[esp+15c]
		esp_15c=param2;
		ecx=esp_15c;

		
		// push edi

		edi=0;
	
		//LEA EAX,DWORD PTR DS:[ESI+20A]            ; EAX=02C3F3EE
		//eax=big.off_20a;

		//cmp ecx, edi

		big.off_206=edi; //edi=0
		big.off_202=edi;
		big.off_1fe=edi;

		big.off_20a=-1;
		

		if (ecx != edi) { //esli var2 ptr !=0
				eax=ecx;  //eax= var2 ptr
		};
		

		big.off_20e=eax; //param2

		eax=big.off_0;

		//CALL DWORD PTR DS:[EAX+4]
		//mysub_rabota_s_pkt_recv_no_call_008509C0_get_next_data_byte
		eax=next_byte(); //schitivaem perviy byte

		//printf("eax=%x\n",eax);
		//exit(0);

		if (eax!=0x42) {

				//...
				printf("This is not 0x42 encode yet\n");
				
				exit(0);
				//return -1;
		};



		eax=big.off_31e; //0x02C3F506
		ebp=big.off_322; //0x02C3F506

		if (eax!=ebp) {
			printf("unexplored hz1\n");
			exit(1);
			//hz...
			//exit
		};


		big.off_522=edi; //edi=0;
		big.off_526=0x200;

		eax=big.off_212;  //02C3F3FA
		ebp=big.off_216;  //02C3F3FA


		if (eax != ebp){
			if (DEBUG) {
				printf("unexplored hz2\n");
			};
			//hz...
			//exit
		};


		//	ecx=esi;  big struct

		big.off_316=edi; //edi=0
		big.off_31a=0x20;

		//call mysub_cikl_do_a0

		mysub_cikl_do_a0();

		mysub_call_eax_5008509F8_mysub_rabota_s_pkt_recv_no_call_DECRYPT();

        /*
		printf("big.off_4=%08X\n",big.off_4);
		printf("big.off_8=%08X\n",big.off_8);
		printf("big.off_c=%08X\n",big.off_c);
		exit(0);
		*/
		
		//print_big(1);

		//func_bef_get_next_byte
		//mysub_rabota_s_pkt_recv_no_call_008509C0_get_next_data_byte

        //mysub_some_math_get_next_byte_cikl();



		//mov ecx,esp_15c;
		esp_15c=param1;  // iz za kalla / pusha ?
		ecx=esp_15c;

        //push edi(0)
        //push ecx
        //ecx=big

		//param1=esi=02C3F78C
		//ret=jmp_tbl_attr_encoder(ecx, 0); //ecx==02C3F78C
        ret=jmp_tbl_attr_encoder(param1,0);
        //call jmp_tbl_attr_encoder ( big_struct, big2, 0)
        //..

}


/*
* not finished.. 
*
*
*/

void copy_memory(unsigned int param1, unsigned int param2, unsigned int len){
			unsigned int eax,ebx,ecx,edx,edi,esi,ebp;
			unsigned int esp;

			if (DEBUG) {
				printf("Run: copy_memory");
			};

			esp=0;
			ebx=0;
			ebp=0;

			//push ebp
			//mov ebp,esp
			//push edi
			//push esi


			edi=param1;
			esi=param2;
			ecx=len;

			eax=ecx;
			edx=ecx;

			eax=eax+esi;

			if (edi <= esi) {
					printf("End: copy_memory");
					printf("not done yet\n");
					exit(1);
			}

			if (edi >= eax) {
					printf("End: copy_memory");
					printf("not done yet2\n");
					exit(1);
			};

			 //LEA ESI,DWORD PTR DS:[ECX+ESI-4]          ; ESI=02C3F1FE
			esi=ecx+esi-4;

			//LEA EDI,DWORD PTR DS:[ECX+EDI-4]          ; EDI=02C3F202
			edi=ecx+edi-4;

			if (edi == 3) {
					printf("End: copy_memory");
					printf("not done yet3\n");
					exit(1);
			};


			eax=edi;
			edx=3;

			if (ecx < 4){
					printf("End: copy_memory");
					printf("not done yet4\n");
					exit(1);
			};

			eax=eax & 0x03; //eax=2
			ecx=ecx-eax;

			//switch ?
			//JMP DWORD PTR DS:[EAX*4+9271E8]

			if (eax!=2){
					//hz

			};

			//big=02C3F1E4
			//mov al, [esi+3] //02C3F201 // =1d
			eax=big.off_1e; // off_1d  //1e =3?
			eax=0;
			//eax=0;
			//???

			edx=edx & ecx;
			
			//big=02C3F1E4
			//EDI=02C3F202 02C3F205
			//MOV BYTE PTR DS:[EDI+3],AL
			//big.off_21..
			big.off_1e=eax;

			
			//big=02C3F1E4
			//mov al, [esi+2] //02C3F200 // =1c
			eax=big.off_1e;
			
			ecx=ecx >> 2;


			//big=02C3F1E4
			//EDI=02C3F202 02C3F204
			//MOV BYTE PTR DS:[EDI+2],AL
			//big.off_20..
			big.off_1e=eax;
		
			esi=esi-2;
			edi=edi-2;

			if (ecx >= 8){
					printf("End: copy_memory");
					printf("not done yet5\n");
					exit(1);
			};

			//neg ecx
			//ecx=-ecx;

			//JMP DWORD PTR DS:[ECX*4+927290]
			ecx=0xFFFFFFFE;
			if (ecx != 0xFFFFFFFE) {
					printf("End: copy_memory");
					printf("not done yet6\n");
					exit(1);
			};

			//MOV EAX,DWORD PTR DS:[ESI+ECX*4+8]
			//...



};

/*
*  strange function.. unfinished?
*
*/

int mysub_attribute_container_encoder(unsigned int p1){
	unsigned int esp_140;
	unsigned int esi,ecx,eax;

	if (DEBUG) {
		printf("Run: mysub_attribute_container_encoder\n");
	};


	//SUB ESP,134

	//edi=ecx=big+ b2

	esi=0;

	esp_140=p1;
	ecx=esp_140;

	
	if (big.off_b2!=ecx) {
			printf("hz not done\n");
			exit(0);			
	};

	if (esi!=0){
			printf("hz not done2\n");
			exit(0);			
	};

	eax=esi;

	if (DEBUG) {
		printf("End: mysub_attribute_container_encoder\n");
	};

	return eax;
};





/*
*  Nesovsem yasno, vrode nichego ne delaet.. potomu chto, count = 0..
*/ 

/*
//push edx -- 0  //0
//push ecx -- ecx = alloc buf
//push eax -- alloc buf + 0x14
int copy_memory1(unsigned int var1,unsigned int var2,unsigned int var3){

		unsigned int esi,ecx,eax,edx,edi;
		unsigned int ebp_8;

	printf("ENTER copy_memory1\n");

	//push ebp
	//mov ebp,esp

	//push edi
	//push esi

	//mov esi,[ebp+c]
	//--esi=02e32ee8 alloc buf
	esi=var2;

	//mov ecx,[ebp+10]
	//--ecx=0
	ecx=var3;
	
	
	//mov edi,[ebp+8]
	//--edi=02e32efc alloc+14
	edi=var1;


	//mov eax,ecx -- eax =0
	eax=ecx;

	//mov edx,ecx -- edx=0
	edx=ecx;

	//add eax,esi
	//--eax=alloc buf
	eax=eax+esi;
	
	//cmp edi,esi --edi=alloc+14, esi=alloc
	//if edi <= esi jmp..

	if (edi<=esi) {
		printf("ptr var1 menshe ptr var2.. hz 10\n");
		exit(1);
	};
	//ne prigaem


	//cmp edi,eax --edi=alloc+14, eax=alloc
	//if edi < eax jmp ..
	//ne prigaem
	if (edi<=eax) { 	//negative ptr
			printf("ptr var1 menshe ptr var2 with offset.., hz 11\n");
			exit(1);
	};
	
	//test edi,3
	//if edi !=3  jmp
	//ne prigaem
	if (edi == 3){
		printf("ptr1==3 ? , hz 12\n");
		exit(1);
	};

	//shr ecx,2 --ecx=0
	ecx=ecx >> 2;

	//and edx, 3 --edx=0
	//--edx=0
	edx=edx & 3;

	//cmp ecx, 8
	//jb ..
	//if ecx < 8 jmp
	//prigaem
	//ecx=0
	if (ecx >= 8){
		printf("ecx>8 , hz 13\n");
		exit(1);
	};

	//jmp [ecx*4+009270dc]  // jmp 0092713f

	//jmp [edx*4+00927148]  // jmp 00927158

	//{dd 5e08458b}
	//{
	//mov eax,[ebp+8] //eax=02e32f10


	//ebp_8=0x02e32f10 //alloc+28 ...
	ebp_8=var1+(var1-var2);
	eax=ebp_8;
	//printf("eax=%X\n",eax);
	//neponyatno...nevajno ???


	//pop esi
	//}

	
	//pop edi
	//leave
	//retn
	printf("LEAVE copy_memory1\n");

	return 0;
};

*/

/*
//push 14
//push ecx // 02c3ed70
//push edx //alloc buf
//copy_memory2(edx,ecx,0x14);
int copy_memory2(unsigned int var1,unsigned int var2,unsigned int var3){

	unsigned int ebp_8,ebp_c,ebp_10;
	unsigned int esi,ecx,edi,eax,edx;

	printf("ENTER copy_memory2\n");

	//push ebp
	//mov ebp,esp
	
	//push edi
	//push esi

	//mov esi,[ebp+c]
	//--esi=02c3ed70 
	ebp_c=var2;
	esi=ebp_c;
	//esi=value_02c3ed70;

	//mov ecx,[ebp+10]
	//--ecx=14
	ebp_10=var3;
	ecx=ebp_10;

	//mov edi,[ebp+8]
	//--edi=02e32ee8 alloc
	ebp_8=var1;
	edi=ebp_8;
	//edi=value_02c3f7fc;

	//mov eax,ecx -- eax=14
	eax=ecx;

	//mov edx,ecx -- edx=14
	edx=ecx;

	//add eax,esi
	//--eax=02c3ed70+14=02c3ed84
	eax=eax+esi;

	//cmp edi,esi --edi=alloc, esi=02c3ed70
	//jbe jmp..
	//if edi <= esi jmp..
	//ne prigaem
     //printf("edi=%X,esi=%X,eax=%X\n",edi,esi,eax);

	//sravnenie static ptr 0x02c3ed70 and dynamicaly allocated buf ptr.. bred kakoyta, nahuy eto
	//if (edi <= esi){
	//	printf("hz 15\n");
	//	exit(1);
	//};

	//eax=02c3ed84
	//cmp edi,eax --edi=alloc

	//sravnenie static ptr 0x02c3ed70+0x14 and dynamicaly allocated buf ptr.. bred kakoyta, nahuy eto
	//if edi < eax jmp ..
	//ne prigaem
	//if (edi<eax){
	//	printf("hz 15\n");
	//	exit(1);
	//};

	
	//edi=value_02c3f7fc;
	//test edi,3
	//if edi !=3  jmp
	//ne prigaem
	if (edi==3){
		printf("allocated ptr on buffer = 3, error, hz 16\n");
		exit(1);
	};


	//ecx=14
	//shr ecx,2 
	//-- ecx=5
	//ecx=31
	//-- ecx=0xc
	ecx=ecx >> 2;

	//edx=14
	//and edx, 3 
	//--edx=0
	edx=edx & 3;

	//cmp ecx, 8
	//jb ..
	//if ecx < 8 jmp
	//prigaem
	if (ecx >=8){
		//0x31 ecx >> 2 = 0xc

		///REP MOVS DWORD PTR ES:[EDI],DWORD PTR DS:[ESI]; 
		//ECX=00000000,ESI=02C3F42B, EDI=02E2D468
		memcpy((char *)edi,(char *)esi,var3); // some hacks... 
		
		//printf("ecx posle sdviga >8, drugaya shnyaga,some unexplored copy\n");
		//exit(1);


		printf("LEAVE copy_memory2\n");
		return 0;
	};

	//ecx=0//ecx=5
	//jmp [ecx*4+009270dc]  // jmp 0092710c


	//copiruem byte iz odnogo v drugoe
	//0x14=20 byte copy
	//heap_alloc_buf=(char *)value_02c3f7fc;

	//esi=02c3ed70
	//ecx=5
	//mov eax,[esi+ecx*4-14] //[]=02c3ed70
	//eax=0
	//edi=02e32ee8=alloc
	//(filled with 0df0adba)
	//ecx=5
	//mov [edi+ecx*4-14],eax
	//00 00 00 00 0d f0 ad ba ...
	//eax=esi+ecx*4-0x14;
	//heap_alloc_buf[0]=eax;
	//printf("%X %X %X %X\n",heap_alloc_buf[0],heap_alloc_buf[1],heap_alloc_buf[2],heap_alloc_buf[3]);
	eax=value_02c3ed70;
	memcpy((char *)edi,&eax,4);

	//mov eax,[esi+ecx*4-10] //[]=02c3ed74 //eax=0
	//eax=esi+ecx*4-0x10;
	//mov [edi+ecx*4-10],eax //[]=02e32eec //eax=0
    eax=value_02c3ed74;
	memcpy((char *)edi+0x4,&eax,4);	
	
	//mov eax,[esi+ecx*4-c] 
	//eax=esi+ecx*4-0x0c;
	//mov [edi+ecx*4-c],eax 
    eax=value_02c3ed78;
	memcpy((char *)edi+0x8,&eax,4);

	//mov eax,[esi+ecx*4-8] 
	//eax=esi+ecx*4-8;
	//mov [edi+ecx*4-8],eax 
    eax=value_02c3ed7c;
	memcpy((char *)edi+0xc,&eax,4);

	//mov eax,[esi+ecx*4-4] 
	//mov [edi+ecx*4-4],eax 
	//eax=esi+ecx*4-4;
    eax=value_02c3ed80;
	memcpy((char *)edi+0x10,&eax,4);



	//podgotovka k eshe onomu ciklu copy 0x14 no on ne ispolzuetsya..

	//lea eax, [ecx*4] //ecx=5
	//eax=14

	eax=ecx*4;

	//esi=02c3ed70
	//add esi,eax
	//esi=ed70+14
	esi=esi+eax;

	//edi=02e32ee8
	//add edi,eax
	//edi=alloc+14
	edi=edi+eax;

	//edx=0
	//jmp [edx*4+00927148]  //00927158

//dd 5e08458b {
//pop esi
//}
//pop edi
//leave
//retn

//retn
	printf("LEAVE copy_memory2\n");

	return 0;
};

*/


/*
* Rekursivnaya
* Vizivaetsya iz flush_decode
* proveryaets vtoroy parametr - kol-vo/glubina rekursiy
* esli max chislo vlojennih rekursiy(vtoroy parametr) >= 8
* to big.off_202=1 i vozvrashaem 0
* esli vtoroy parametr > 2 //tekushaya rekursiya = 2 // maksimum 2 vlojenih rekursii ?
* eax ot 0 do 2 , potom 0, 5, 10
* potom eax * 0x20(32)//0,160,320
* cikl kounter esp_18=0
*     
*
* podgotavlivautsya strukturi kotoriy v mycikl_do_a0
*
* v zavisimosti ot rekursii ot 0 do 2, smeshenie v big.off,
* ebx=esi+12+0,160(0xa0),320(0x140) // ebx=0//na pervom zahode !
* to chto v cikle do a0 inicializirovali konstantami
* seychas 0
* ebx(0) sohraneno v esp_24
*
* esli nomer rekursii ne 0 i
* b2+9c=14e != 0 dlya 1 rekursii 
* ili 152+9c=1ee !=0 dlya 2 rekusii
* to 
*     ....
*     menyaetsya esp_18//cikl kounter?
*     ....
*
* v big.off_ae,big.off_14e,big.off_1ee zapisivaem 0, t.e. inicializiruem 0, prejnee znachenie v esp_24
* takje esp_14 = 0
*
* esli big.off_202 != 0 
* to vihodim vozvrashaem 0
*
* cikl
*     esli (cikl kounter) esp_18 !=0 to
*          ....
*          ....
*          ....
*     inache(esli perviy cikl, cikl kounter eax = esp_18 = 0)
*          zapusaketsya mysub_some_math_call_edx_0_get_next_byte_cikl_wrap 
*          kot-ya vozvrashet granich index
*          esli granichniy index = 0 , 
*              vihodim,  veroyatnee vsego iz rekursii, vozvrashaem 0,
*          esli granichniy index > 6
*              vizivaem funkciuy mysub_some_math_41_get_next_byte, kotoraya vozvrashaet 
*              1-cu sdvinutuyu vlevo na granichniy index2(s vichetami) t.e. *2^ecx 
*              + ostatok ot deleniya  big.off_4 / (big.off_8 >> granichniy index2)
*              esli (granichniy index - 6) != 0
*                   smeshenie v zavisimosti ot nomera rekursii, 0x12,0xb2,0x152
*                   eax=(granichniy index - 6) * 4 ,dla sluchaya ebp=3//eax=0x0c 
*                   smeshenie + 4
*                   ebp=big.off_1e;//5//znacheni iz inicializacii a0//zavisit ot (granichnogo indexa-6), ebp
*                   copy_memory(smeshenie+4,smeshenie ot nomera rekursii,(granichniy index - 6) * 4);
*                   copy_memory(big.off_16,bif.off_12,0x0c);
*                   big.off_12=ebp;
*          inache
*              esli (granichniy index <= 6)
*                  esli (granichni index < 6), to
*                         edi=granichniy index - 1
*                  inache (granichniy index = 6)
*				          vizivaem funkciuy mysub_some_math_41_get_next_byte
*				          vozvrashaet ??? a tochno ?
*				            //1-cu sdvinutuyu vlevo na granichniy index2(s vichetami) t.e. *2^ecx 
*				            // + ostatok ot deleniya  big.off_4 / (big.off_8 >> granichniy index2)
*					      edi=eax;
*				 	      edi=edi+5;
*
*
*          eax=big.off_12;//eax=big.off_b2//eax=big.off_152;
*          esp_10=eax;
*
*/

int jmp_tbl_attr_encoder(unsigned int par1, unsigned int par2) {
        unsigned int big3=0x02a9f04c;
        unsigned int ecx,eax,ebx,edx,edi,ebp;
		unsigned int esp_10,esp_14,esp_18,esp_24,esp_d8,esp_d4;
		unsigned int while_cikl=0;		
		// sub esp,b4

		count_jmp_tbl++;

		if (DEBUG) {
			printf("Run: jmp_tbl_attr_encoder: %d\n",count_jmp_tbl);
		};



		//mov ecx,esp_d4;
		esp_d4=par2; // second parameter, 1 - rekursiya
        ecx=esp_d4; 



		//esp_d8=par1;

        //push edi()//=0
		// esp_d4 == esp_d8 ili esp_d0 ??

		//max chislo vlojennih rekursiy - 8
        if ( ecx >= big.off_1f2 ){
                big.off_202=1;
                //mov ecx,[esp+0d0h+var_c]

				if (DEBUG) {
					printf("End: jmp_tbl_attr_encoder\n");
					printf("previsheno max chislo rekursiy, Unexpected\n");
				};

                return 0;
        };

		//eax - nomer tekushiey rekursii

        eax=ecx;

        if (ecx > 2) {
                eax=2;  //max nomer = 2 // maksimum 2 vlojenih rekursii ?
        };

		

        
		//eax ot 0 do 2

		//LEA EAX,DWORD PTR DS:[EAX+EAX*4]
		eax=eax+eax*4;//0, 5, 10, ..


		// xor edi,edi
        edi=0;

        eax=eax << 5; //eax * 0x20(32)//0,160,320


        //[esp+18],edi
		esp_18=edi;//edi=0

		//LEA EBX,DWORD PTR DS:[EAX+ESI+12]
		//ESI=02C3F1E4
		//EBX=02C3F296
		//eax=a0

		//ebx=esi+12+0,160(0xa0),320(0x140)
		//to chto v cikle do a0 inicializirovali konstantami

		if (par2==0) {
			//ebx=0
			ebx=big.off_12;
		};
		
		if (par2==1) {
			ebx=big.off_b2;
		};

		if (par2==2) {
			ebx=big.off_152;
		};

		//ebx=&big.off_b2; v rekursii
		// ebx=big+12..//cikl do a0 ? ;0
		//ebx=big+b2

        //mov [esp+24],ebx
		esp_24=ebx;


		//poka ne yasno, kakayato proverka
		//ne 0-ya rekursiya

		//edi=0 doljen
        if (ecx != edi) {  
			
			/*
			if (par2==0) {
				if (big.off_ae != edi) {
					//push edi//0
					//push 009A82B0
					eax=mysub_some_math_41_get_next_byte((unsigned int)table1+0x58,0);
					ecx=big.off_ae;
					esp_18=eax;

					if (eax > ecx) {
						printf("End: jmp_tbl_attr_encoder\n");
						big.off_202=1;
						return 0;
					};
				};
			};
			*/

			if (par2==1) {
				//b2+9c=14e
				//printf("%x\n",big.off_14e);
				if (big.off_14e != edi) {
					//push edi//0
					//push 009A82B0
					eax=mysub_some_math_41_get_next_byte((unsigned int)table1+0x58,0);
					ecx=big.off_14e;
					esp_18=eax;

					if (eax > ecx) {
						if (DEBUG) {
							printf("End: jmp_tbl_attr_encoder\n");
						};
						big.off_202=1;
						return 0;
					};
				};
			};

			if (par2==2) {
				//152+9c=1ee
				//printf("%x\n",big.off_1ee);
				if (big.off_1ee != edi) {
					//push edi//0
					//push 009A82B0
					eax=mysub_some_math_41_get_next_byte((unsigned int)table1+0x58,0);
					ecx=big.off_1ee;
					esp_18=eax;

					if (eax > ecx) {
						if (DEBUG) {
							printf("End: jmp_tbl_attr_encoder\n");
						};
						big.off_202=1;
						return 0;
					};
				};
			};


        };


		//prodoljaem


		if (par2==0) {
		        big.off_ae=edi;
		};

		if (par2==1) {
				big.off_14e=edi;
		};

		if (par2==2) {
				big.off_1ee=edi;
		};

        eax=big.off_202;


        //mov [esp+14],edi
		esp_14=edi;//edi=0

        if (eax!=edi){
				if (DEBUG) {
					printf("End: jmp_tbl_attr_encoder\n");
					printf("big.off_202!=0, vihodim,not done2\n");
				};
				//exit(0);
                return 0;
        };


//maybe_cikl_loc_85135D:

do {


     //mov eax, [esp+18]
	
	 eax=esp_18; //eax=0//cikl kounter?



	 if (eax!=0){
            
				ecx=eax;
				
				if (par2==0) {
				        eax=big.off_ae;
				};

				if (par2==1) {
						eax=big.off_14e;
				};

				ecx--;



				//mov     edi, [ebx+eax*8+20h]
				///MOV EDI,DWORD PTR DS:[EBX+EAX*8+20]
				//=0
				//12 + eax*8 +20
				if (par2==0) {

					if (eax==0){
						edi=big.off_32;
					};
					if (eax==1){
						edi=big.off_3a;
					};
					if (eax>1){
						printf("not done5\n");
						exit(0);
					};

				};				
				//mov     edi, [ebx+eax*8+20h]
				///MOV EDI,DWORD PTR DS:[EBX+EAX*8+20]
				//=0
				//b2 + eax*8 +20
				if (par2==1) {

					if (eax==0){
						edi=big.off_d2;
					};
					if (eax==1){
						edi=big.off_da;
					};
					if (eax>1){
						printf("not done4\n");
						exit(0);
					};

				};

				esp_18=ecx;

				//MOV ECX,DWORD PTR DS:[EBX+EAX*8+1C]       ; ECX=00000000
				//12 + eax*8 +1c				
				if (par2==0) {
					if (eax==0){
						ecx=big.off_2e;
					};
					if (eax==1){
						ecx=big.off_36;
					};
					if (eax>1){
						printf("not done7\n");
						exit(0);
					};
				};			
				//MOV ECX,DWORD PTR DS:[EBX+EAX*8+1C]       ; ECX=00000000
				//b2 + eax*8 +1c				
				if (par2==1) {
					if (eax==0){
						ecx=big.off_ce;
					};
					if (eax==1){
						ecx=big.off_d6;
					};
					if (eax>1){
						printf("not done6\n");
						exit(0);
					};
				};



				//push edi//=0

				esp_14=ecx; //  uje ne 18 iz za pusha //esp_14


				ecx=ebx;
				esp_10=edi; //uje ne 14, a 10


				eax=mysub_attribute_container_encoder(edi);



				//goto loc_851408;

				//printf("End: jmp_tbl_attr_encoder\n");
				//printf("not done container encode\n");
				//exit(0);
	 }else{



        //push 0x0c
        //push 0x009a8258
		//ecx=big
		//print_big(0);
		//exit(1);


		//struktura big/context initialize, posle etogo zapusakem etu funkciu
		//vozvrashet granichniy index v tablice
        eax=mysub_some_math_call_edx_0_get_next_byte_cikl_wrap((unsigned int)table1, 0x0c);
		if (DEBUG) {
			printf("EAX after wrap = 0x%0x\n",eax);	
		};

        //eax=6
		//eax=9 !
		//eax=2 // 0 ?
		//eax=0
		//eax=1

		//printf("eax=%08x\n",eax);
		//print_big(1);

		//printf("eax=%08x\n",eax);
		//exit(0);


		//granichniy index = 0 , vihodim, veroyatnee vsego iz rekursii
        if (eax==0) {
				if (DEBUG) {
					printf("End: jmp_tbl_attr_encoder\n");
				};
				return 0;
				//printf("End: jmp_tbl_attr_encoder\n");
				//printf("not done4\n");\
				//exit(0);
        };

		//granichniy index > 6
        if (eax > 6){
				
				//push 0
                //PUSH Skype14.009A82B0
                //lea ebp,[eax-6]

				//ebp - granichniy index - 6

				ebp=eax-6;

				//vizivaem funkciuy mysub_some_math_41_get_next_byte

				eax=mysub_some_math_41_get_next_byte((unsigned int )table1+0x58,0);

				//vozvrashaet
				//1-cu sdvinutuyu vlevo na granichniy index2(s vichetami) t.e. *2^ecx 
				//+ ostatok ot deleniya  big.off_4 / (big.off_8 >> granichniy index2)

				edi=eax;

				//printf("%x\n",ebp);
				//exit(0);

				// esli (granichniy index - 6) != 0
				if (ebp != 0) {


					//smeshenie v zavisimosti ot rekursii

					//ebx=big+0x12;
					if (par2==0){
						ebx=0x12;
					};

					if (par2==1){
						ebx=0xb2;
					};

					if (par2==2){
						ebx=0x152;
					};


					//eax=(granichniy index - 6) * 4 
					//dla sluchaya ebp=3//eax=0x0c 

					//LEA EAX,DWORD PTR DS:[EBP*4]
					eax=ebp*4; //eax=0x0c 
					

					//smeshenie + 4


					//LEA EDX,DWORD PTR DS:[EBX+4]
					edx=ebx+4; //edx=big+0x16

					// push eax //0x0c
					// push ebx // big+0x12

					//znacheni iz inicializacii a0
					//mogut bit raznie v zavisimosti ot ebp..
				
					//MOV EBP,DWORD PTR DS:[EAX+EBX]            ; EBP=00000005
					// 0x0c+big+0x12

//					ebp=big.off_1e; //ebp=5   
//IZMENENIE
					//ne rovno byte ! vliyat doljen na chto.. a v dannom sluchae etogo net, 
					//tak kak otdelno obyavlenno int-om
					if (par2==0){
						ebp=big.off_1e;
					};

					if (par2==1){
						ebp=big.off_be;
					};

					if (par2==2){
						ebp=big.off_15e;
					};

					// push edx // big+0x16

					//CALL Skype14.00927000 copy_memory
					//copy_memory(big.off_16,bif.off_12,0x0c);
					//copy_memory(edx,ebx,eax); // edx, ebx, otkuda kuda ? eax -- skolko
					// ??? dodelat !!!!!!!
					//vrode kak napo polnostu copy_memory perevodit
					//tak kak ebp mojet bit ot 0 do 10? * 4 ..
//DODELAT !	

					//exit(1);
					if (par2==0){
						big.off_12=ebp;
					};
					if (par2==1){
						big.off_b2=ebp;
					};
					if (par2==2){
						big.off_152=ebp;
					};


				};

		//granichniy index <= 6
		} else {
		
		
		    //granichni index < 6
			if (eax != 6) {
				//mimo
				//lea edi,[eax-1]
				edi=eax-1;

			//	goto loc_8513F4;

			}else{
				//if (eax==6){
				//};

				//granichniy index = 6
				if (eax==6){
					//suda
					//push 0
					//push 009a82b0
					eax=mysub_some_math_41_get_next_byte((unsigned int )table1+0x58,0);
					edi=eax;
					edi=edi+5;

				//	goto loc_8513F4;

					//jmp case 12345
				};

			};


		};


//if (1){ //case 12345
//};


        
// sdes prodoljaem ..

//loc_8513F4:

		if (par2==0){
			eax=big.off_12;
		};
		if (par2==1){
			eax=big.off_b2;
		};
		if (par2==2){
			eax=big.off_152;
		};

		//mov [esp+10],eax

        //sohranaem v esp_10 znachenie big.off_12

		esp_10=eax;


		//kakoeto znachenie 

        //mov eax,[esp+14]//0
		eax=esp_14;


		//exit(0); 
		
		//printf("eax=%x\n",eax);
		//exit(0);

		//eax=0
		//edi - vozvrashaet
		//1-cu sdvinutuyu vlevo na granichniy index2(s vichetami) t.e. *2^ecx 
		//+ ostatok ot deleniya  big.off_4 / (big.off_8 >> granichniy index2)

        eax=eax+edi;


		//printf("edi=%x\n",edi);
		//exit(0);

		//znachenie big.off_12
        
		//mov edi,[esp+10]
		edi=esp_10;


		//printf("edi=%x\n",edi);
		//exit(0);

		//sohranili, nakaplivaem

		esp_14=eax;
        //mov [esp+14],eax

//perviy if else zakoncilsya

	};

//loc_851408:



		if (par2==0){
			eax=big.off_ae;
		};

		if (par2==1){
	        eax=big.off_14e;
		};

		if (par2==2){
	        eax=big.off_1ee;
		};


		//printf("eax=%x\n",eax);
		//exit(0);

		ebp=esp_14;
        //mov ebp,[esp+14];

		//printf("\teax=%x\n",eax);
		//exit(0);



        if (eax < 10) {


				if (par2==0){
					//[EBX+EAX*8+1C]
					//[EBX+9C]
					//[EBX+ECX*8+20]
	
					if (eax==0){
						big.off_2e=ebp;
					};
					if (eax==1){
						big.off_36=ebp;
					};
					if (eax==2){
						big.off_3e=ebp;
					};
					if (eax > 2){
						if (DEBUG) {
							printf("not done1\n");
						};
						//exit(0);
					};

	                ecx=big.off_ae;

					if (ecx==0){
						big.off_32=edi;
					};
					if (ecx==1){
						big.off_3a=edi;
					};
					if (ecx==2){
						big.off_42=edi;
					};
					if (ecx > 2){
						if (DEBUG) {
							printf("not done11\n");
						};
						//exit(0);
					};

	                eax=big.off_ae;
	                eax++;
					big.off_ae=eax;
				};
				
				if (par2==1){


					//[EBX+EAX*8+1C],EBP
					//b2+1c
					//big.off_ce=ebp; !!! ce na samomo dele !
					if (eax==0){
						big.off_ce=ebp;
					};
					if (eax==1){
						big.off_d6=ebp;
					};
					if (eax==2){
						big.off_de=ebp;
					};
					if (eax > 2){
						if (DEBUG) {
							printf("not done2 eax=0x%x\n",eax);
						};
						//exit(0);
					};

	                ecx=big.off_14e;

					//[EBX+ECX*8+20],EDI
					if (ecx==0){
						big.off_d2=edi;
					};
					if (ecx==1){
						big.off_da=edi;
					};
					if (ecx==2){
						big.off_e2=edi;
					};
					if (ecx > 2){
						if (DEBUG) {
							printf("not done3 ecx=0x%x\n",ecx);
						};
						//exit(0);
					};

	                eax=big.off_14e;
	                eax++;
	                big.off_14e=eax;
				};

				
				if (par2==2){
					printf("kopi paste i pereschitat, not done\n");
					exit(1);
				}

        };

        //push 14
	

        eax=mygen_no_call_00850F30(0x14);


		//printf("eax=%x\n",eax);
		//exit(0);

        if (eax==0) {
				//printf("End: jmp_tbl_attr_encoder\n");
				//printf("not done6\n");
				//exit(0);
				if (DEBUG) {
					printf("End: jmp_tbl_attr_encoder\n");
				};
                return 0;
        };
		//edi=0;



		//cmp edi,6 // switch 7 cases



        //switch 7 cases
        //switch edi
        //jmp [edi*4+8518cc]

		
		if (DEBUG) {
			printf("jmp_tbl switch2 edi=%x\n",edi);
		};

		


		switch (edi){


			case 0: 
						//edi ?
				        //ot predidushego case 12345,6,..
				        //if (eax==0){
						//push 0
						//push 0x009a82c0

						eax=mysub_some_math_41_get_next_byte((unsigned int )table1+0x68,0);
						//posle etogo call, v eax - nujniy integer
						// ZDES!!! nujniy integer
						if (DEBUG) {
							printf("INTEGER:0x%08X (%d)\n",eax,eax);
						};
						//printf("INTEGER:%08d\n",eax);
						ecx=esp_d4;				

						/*
						{
							FILE *f;
							f=fopen("./aaa.txt","a");
							fprintf(f,"I:0x%08X D:%d\n",eax,eax);
							fclose(f);

						};
						*/

						{
							outbuf[outlen]=eax;
							outlen++;
							if (outlen > 8192) {
								printf("output buffer overflow\n");
								exit(0);
							};
						};

						//push eax//2 //0CABA34F//100
						//push ebp//0 //1//0

						
						//call mysub_copy_mem_realloc_0(ebp,eax)
						//};

//byteov snachala 6 , potom 3 pered vivodom. , 2 i eshe 2 , eshe 4,

				;

				break;

			case 1: 
						//push 0
						//push 009A82C0
						eax=mysub_some_math_41_get_next_byte((unsigned int )table1+0x68,0);
						///posle etogo call, v eax - nujniy integer
						// ZDES!!! nujniy integer
						if (DEBUG) {
							printf("INTEGER1:%08X\n",eax);
							printf("INTEGER1:%08d\n",eax);
						};

						ebp=eax;
						if (ebp > 8){
							big.off_202=1;
						};
						if (ebp <= 0x0FFFFFFFF){
							// case 4 part..
								printf("End: jmp_tbl_attr_encoder\n");
								printf("not done yet, case2 4_2\n");
								exit(0);
								//..
						};
				;

				break;

			case 2: 
				// net dannih
				ebp=6;

				// goto case 4 part after cmp ebp
					printf("End: jmp_tbl_attr_encoder\n");
					printf("not done yet, case2 4_3\n");
					exit(0);
				;

				break;

			case 3: 
				// net dannih ne islledovana
				// raspokovka bolshaya
				printf("End: jmp_tbl_attr_encoder\n");
				printf("not done yet, case2 3\n");
				exit(0);


				;

				break;

			case 4: 
						//push 0
						//push 009A82C0
						eax=mysub_some_math_41_get_next_byte((unsigned int )table1+0x68,0);
						///posle etogo call, v eax - nujniy integer
						// ZDES!!! nujniy integer
						if (DEBUG) {
							printf("INTEGER4:%08X\n",eax);
							printf("INTEGER4:%08d\n",eax);
						};

						ebp=eax;
						//ecx=esi;
						// push ebp
						//call    mygen_no_call_00850F30
						if (ebp <= 0x0FFFFFFFF){
								//net dannih
								printf("End: jmp_tbl_attr_encoder\n");
								printf("not done yet, case2 4\n");
								exit(0);
								//..
						};
				;

				break;

			case 5: 

				//edi ?
				// new case
				//if (edi==1) {
					//mov edx,[esp+0xd8];
					esp_d8=par2;
					edx=esp_d8; // = 0

					//mov ecx,[esp+0xd4];
					esp_d4=par1;
					ecx=esp_d4;//ECX=02C3F78C

					edx++;

					//printf("ecx=%x\n",ecx);
					//exit(0);

					//push edx //= 1
					//push ebp //=1 ?

					//call mysub_copy_memory_00723060(ebp//1?,edx//1);

					//!!! REKURSIYA !!! AAA !!!
					//!!! REKURSIYA !!! AAA !!!
					//!!! REKURSIYA !!! AAA !!!

					// push eax == new malloc block ? // new alloc heap ? //EAX=00177D00//00206818
					//call mysub_jmp_tbl_attr_encoder


					if (DEBUG) {
						printf("REKURSIYA !!!: %d\n",rekurs);
					};
					//exit(0);


					

					eax=jmp_tbl_attr_encoder(eax,1);

					if ((rekurs==3) && (while_cikl==2)) {
						if (DEBUG) {
							printf("rekurs 3 end eax=%x\n",eax);
						};
						//exit(0);
					};

					//if ((rekurs==3) && (while_cikl==2) && (count_jmp_tbl==4)) {
					//	printf("eax=%x\n",eax);
					//	printf("ecx=%x\n",ecx);
					//	exit(0);
					//};
					if (DEBUG) {
						printf("REKURSIYA END: %d\n",rekurs);
					};
					//exit(0);					

					rekurs++;


					//};
				
				;

				break;

			case 6: 
						//push 0
						//push 009A82C0
						eax=mysub_some_math_41_get_next_byte((unsigned int )table1+0x68,0);
						///posle etogo call, v eax - nujniy integer
						// ZDES!!! nujniy integer
						//printf("INTEGER:%08X\n",eax);
						//printf("INTEGER:%08d\n",eax);
						edi=eax;
						if (edi>0x3FFFFFFF){
							big.off_202=1;
						}else{
							// net dannih
							// ne isssledovana..


							//..
							printf("End: jmp_tbl_attr_encoder\n");
							printf("not done yet, case2 6\n");
							exit(0);
						};

				;

				break;

			default:
				;
				break;

		};


		//if (edi>6) {
		//case default
				//printf("End: jmp_tbl_attr_encoder\n");
				//printf("not done7\n");
				//exit(0);

				
		eax=big.off_202;

while_cikl++;
}while(eax==0);

//goto maybe_cikl_loc_85135D; //na samiy verh v cikl


		if (DEBUG) {
			printf("End: jmp_tbl_attr_encoder\n");
		};

        return 0;

}


/*
*  Zapuskaetsya iz jmp_tbl_attr_encoder, na pervom cikle, context init with first byte.
*  zapuskaet mysub_some_math_get_next_byte_cikl kotoraya schitivaet ostalnie 3 byte
*
*  sdvigaem mask-u polucheniu posle schitivanie eshe 3-h byte na sdvig 0xc
*  elim big.off_4 / mask so sdvigom , i operiruem s celim ostakom
*  nahodim granichnie byte v tablice 
*  umnojaem perviy granichniy na sdvinutuu mask. i eto znachenie vichitaem iz big.off_4
*  esli znacheni celogo ostatka ot deleniya(2 oy granichniy byte) > 0x1000, to 
*  i iz maski vichitaem umnojenie pervogo granichnogo na sdvinutuu mask
*  esli net to, nahodim raznicu 2 granichnogo byte - 1 granichniy byte i umnojaem ee 
*  na sdvinutuu mask, i sohranem v big.off_8 (mask)
* 
*  funkciya operiruet big.off_4, big.off_8
*  vozvrashet eax - granichniy index v tabl
* 
*/

unsigned int mysub_some_math_call_edx_0_get_next_byte_cikl_wrap(unsigned int table_ptr, unsigned int sdvig) {
        unsigned int ecx,eax,edx,edi,ebp,tmp;
        unsigned int esi;
        unsigned int esp_1c,esp_10;
        //unsigned int esp_18;

        unsigned char * esp_table;

		count_wrap++;

		if (DEBUG) {
			printf("Run: mysub_some_math_call_edx_0_get_next_byte_cikl_wrap: %d\n",count_wrap);
		};



	    //if (count_wrap==4){
		//	printf("aga\n");
		//	exit(0);
		//};

		//push
        //mov ebx,ecx//big_struct

		// schitali pervie 4 byte
        mysub_some_math_get_next_byte_cikl();

        //if (count_wrap==3){
			//print_big(1);
		//};



        //mov esi,[ebx+8]
        esi=big.off_8;//mask==0x80000000

        //mov ecx,[esp+1c]
		
		//esp_1c=0x0c;
		esp_1c=sdvig;
        ecx=esp_1c;

        ebp=big.off_4;//byte/2 s predidushimi byte

        //mov [esp+10],esi
		esp_10=esi;//orig mask

        esi=esi >> ecx; //mask sdvig 0x0c
		//esi=0x00080000

        eax=ebp;//byte/2 s predidushimi byte

        edx=0;

/*
        if (count_wrap==3){
			printf("ecx=%x\n",ecx);
			exit(1);
		};
*/

		/// vse chto nakopili razdelil na masku sdvinutuu

        //eax=0x01abafda;
        //esi=0x00005b17;

        tmp=eax / esi;//celoe
        edx=eax % esi;//ostatok ot deleniya
		eax=tmp;//celoe ostavsheesya ot deleniya
        //eax=0x04b1;
        //edx=0x58f3;

        //if (count_wrap==3){
		//printf("eax=%08x\n",eax);
		//printf("edx=%08x\n",edx);
		//exit(0);
		//};

        //mov [esp+0x1c],esi
		esp_1c=esi;//mask sdvinutaya

        edx=eax;//ostatok ot deleniya ushel nahuy ..
				//edx - celoe ostvsheesya posle deleniya

        eax=eax >> ecx;//sdvig 0xc
		//esli chislo > 0x0FFF t.e. 0x1000 naprimer to

        if (eax!=0){
                edx=1;
                edx=edx << ecx; //edx=0x1000,
                edx--;//edx=0x0FFF
        };

        //mov esi,[esp+18]
		//esp_18=(unsigned int)table1;
		//esi=esp_18;
		esi=table_ptr;

        //if (count_wrap==3){
			//printf("edx=%08x\n",edx);
			//printf("indx=%08x\n",esi-(unsigned int)table1);
			//exit(0);
		//};

        edi=0;

        esi=esi+2; //tbl_ptr+2

        eax=1;
		//edx libo celoe ostavhseesya ot deleniya, libo esli eto celoe > 0x0FFF , edx=0x0FFF
        //itogo ostatok ot deleniya ne bolshe chem 0x0FFF
		

		//edi - perviy byte(esli s +2 to vtoroy) iz tbl_ptr

        //mov di,[esi]
		esp_table=(unsigned char *)esi;
		edi=esp_table[1]*256+esp_table[0];

		//printf("edx=%08x\n",edx);
		//printf("edi=%08x\n",edi);
		//exit(0);

		//edx  -  to chto poluchilos celoe posle deleniya
		//edi tablica kakayato.. vtoroy byte iz nee

		//esli byte iz tablici <= celoe posle deleniya, to
		//schitivaem sled byte iz tablici, uvelichivaem index
        if (edi <= edx){
                do {
                        esi=esi+2;
                        edi=0;
                        eax++;//index v tablice

                        //mov di,[esi]
						esp_table=(unsigned char *)esi;
						edi=esp_table[1]*256+esp_table[0];

						//printf ("while1\n");
						//printf("edx=%08x\n",edx);
						//printf("edi=%08x\n",edi);
						//exit(0);

                } while(edi<=edx);
        };
		
		//esli edi > edx , t.e. esli byte schitanniy iz tablici strogo bolshe , ostatka ot deleniya
		//vihodim i zapominaem eax -- index na byte v tbl


		// eax index v tablice na blijaushoe posle deleniya chislo
		

		//printf("eax=%08x\n",eax);
		//printf("edx=%08x\n",edx);
		//printf("edi=%08x\n",edi);
		//exit(0);

        //if (count_wrap==3){
			//printf("eax=%08x\n",eax);
			//printf("indx=%08x\n",esi-(unsigned int)table1);
			//exit(0);
		//};

        
		//edi=esp_18; // table1 ptr ?
		edi=table_ptr;
        //mov edi,[esp+18]


		// znacheniya iz tablici iz kotoroy vishli i znachenie -2
		esp_table=(unsigned char *)edi;
		edx=esp_table[eax*2+1]*256+esp_table[eax*2];
		//znachenie > celogo ostatka ot deleniya

		esp_table=(unsigned char *)edi;
		esi=esp_table[eax*2+1-2]*256+esp_table[eax*2-2];
		//znachenie na 1 byte do etogo t.e. <= celogo ostatka ot deleniya

        //mov dx,[edi+eax*2]
        //mov si,[edi+eax*2-2]

		//printf("edx=%08x\n",edx);
		//printf("esi=%08x\n",esi);
		//exit(0);

		// iz index-a -1 , t.e. ukazivaet na byte nujniy on do chisla > celogo ostatka ot deleniya
		// ego fozvrashaet funkciya !
        eax--;

        edi=esi;//znachenie na 1 byte do etogo t.e. <= celogo ostatka ot deleniya

        //esp_1c=0x00080000; // esi sdvinutoe/maska
        //imul edi,[esp+1c]
        edi=edi*esp_1c;
		//znachenie na 1 byte do etogo . umnojaem ego na mask > 0xc t.e. na 0x00080000;

		//printf("after imul edi=%08x\n",edi);
		//exit(0);

        //ebp data iz buffera v nakopitele sdvinutaya itd
		//originalniya byte/2 s predidushimi byte  ...
		//vichitaem edi - znachenie na 1 byte do etogo * (mask(0x80000000) >> 0xc)
        ebp=ebp-edi;

        big.off_4=ebp;  //sohranyaem..

        ebp=edx;//znachenie > celogo ostatka ot deleniya

        ebp=ebp >> ecx; //znachenie > celogo ostatka ot deleniya >> 0x0c
		//0x1000 >> 0xc == 0x1

		//if znachenie > celogo ostatka ot deleniya, >=0x1000, to
        if (ebp != 0){

				// ne testil
                //na 5-om byte suda
                //mov ecx,[esp+10]
				ecx=esp_10; //orig mask

                ecx=ecx-edi; //mask = mask - znachenie na 1 byte do etogo * (mask(0x80000000) >> 0xc)
                //pop edi
                //pop esi

                big.off_8=ecx; //mask sohranyaem
                //pop

				//if (count_wrap==3){
				//	print_big(0);
				//	printf("ebp=%08x\n",ebp);
				//	exit(0);
				//};

				if (DEBUG) {
					printf("End: mysub_some_math_call_edx_0_get_next_byte_cikl_wrap\n");
				}

                return eax;
        };
		//esli < 0x1000 to


		//edx = znachenie > celogo ostatka ot deleniya
		//esi = znachenie na 1 byte do etogo t.e. <= celogo ostatka ot deleniya
        edx=edx-esi;
		//raznica mejdu 2 byte v tablice granichnimi dlya nashego ostatka ot deleniya

		//printf("edx=%08x\n",edx);
		//exit(0);

        //pop edi


		//raznica mejdu byte v tablice granichnimi * na sdvinutuu mask

        //esp_18=0x00000800;
        //imul edx,[esp+18]
		// iz za pop-a esp_18=esp_1c
        edx=edx*esp_1c;//sdvinut mask
		//printf("edx=%08x\n",edx);
		//exit(0);

        //pop esi
		
		//sohranyem to chto poluchilos kak mask, vozvrashem index iz tablici

        big.off_8=edx;
        //pop

		if (DEBUG) {
			printf("End: mysub_some_math_call_edx_0_get_next_byte_cikl_wrap\n");
		};

        return eax;
};


/*
* Rekursivnaya !
* table_ptr+0x58
* 
* bez novoy inicializacii big.off_4,big.off_8
* schitivaet znachenie ptr iz tablici 0x58 +0xc
* vichitaet iz nego static ptr 0x009a8258
* poluchaet +1c indexi 2, 
* vizivaet mysub_some_math_call_edx_0_get_next_byte_cikl_wrap s etim novim indexom
* kotoraya vozvrashaet granichniy index iz index2 
* schitivaem 0x02 iz 0x58+4. 
* esli 1<<2(4) < eax(granichniy index iz index2) , to vihodim
* inache schitivaem sled byte 0x58+8 , on raven 1 ,
* iz granichnogo index2, vichitaem 1
* schitivaem iz tablici table_ptr+0x58 eto 0x07
* if granichniy index2 - 1 < 0x07(table_ptr+0x58) to
*    iz granichniy index2 eshe vichitaem 1
*    1-cu sdvigaem vlevo na granichniy index2(s vichetami) t.e. *2^ecx 
*    1<<ecx
*    esli granichniy index2 stal <=0 vihodim vozvrashaem  0x07(table_ptr+0x58)
*    cikl 
*       iz granichniy index2 vichitaem nul(na pervom shage)
*       esli granichniy index2 > 0x10, to granichniy index2 = 0x10
*       vizivaem mysub_some_math_42 s parametrom granichniy index2
*       ona vozvrashaet eax -- ostatok ot deleniya big.off_4 / (big.off_8 >> granichniy index2) , tolko celoe
*		tolko 2 byte iz nih berem
*       sdvig ostatka ot deleniya na nul pri pervom cikle
*       cikl kounter= cikl kounter + granichniy index2(-2)
*       ebp=1-cu sdvinutaya vlevlo + ostatok ot deleniya
*       poka cikl kounter < granichniy index2, t.e. odin cikl obichno
*    eax=ebp
*	 vihodim, vozvrashaem 
*    1-cu sdvinutuyu vlevo na granichniy index2(s vichetami) t.e. *2^ecx 
*    + ostatok ot deleniya  big.off_4 / (big.off_8 >> granichniy index2)
* inache
*
*
*
*
*/

// sdes est rekursiya, na tret'em zahode
int mysub_some_math_41_get_next_byte(unsigned int table_ptr, unsigned int hz) {
        unsigned int esp_18,esp_1c;
        unsigned int ecx,eax,edx,ebx,edi,ebp;
        unsigned int esi;
		unsigned int tmp;
		unsigned char *esp_table;
        // push ..

		count41++;

		if (DEBUG) {
			printf("Run: mysub_some_math_41_get_next_byte: %d\n",count41);
		};


        if (count41==3){
			if (DEBUG) {
				printf("ogo rekursiya\n");
			};
			//exit(1);
		};

        esp_18=table_ptr; //0x009a82b0 ; //0x009a82c0
        edi=esp_18;
        //push 0x0c;
        //esp_14=big;
        //addr

		//tabler_ptr+0x58 + 0x0c
		//ptr iz tablici vichest` ptr0
		//table + raznica
		//\x74\x82\x9A\x00
		//74-58=1c
		// s 1c smesheniya +2 nachinautsya vtorie indexi, index2
		tmp=edi+0x0c;
		esp_table=(unsigned char *)tmp;
		eax=esp_table[3]*256*256*256+esp_table[2]*256*256+esp_table[1]*256+esp_table[0];
        
		tmp=eax-0x009a8258;
		eax=(unsigned int )table1+tmp;
		//eax=table_ptr+0x1c; // == 0x009a82b0 
        //eax=0x009a8274 //0x009a8288

		//if (count41==2){
		//	printf("41 table tmp=%x\n",tmp);
		//	exit(1);
		//};


		//granichniy index iz indexov 2(table_ptr+0x1c)

        //push eax;
		//print_big(0);
		//eax - index1 index2.. s raznimi smesheniyami +1c..
		//mask and big.off_4 inicializirovanni uje
		//schitivaem stoka byte skolko do maski 0x80000000
        eax=mysub_some_math_call_edx_0_get_next_byte_cikl_wrap(eax,0x0c);
		//eax=1
		//print_big(1);
		if (DEBUG) {
			printf("[debug] eax after wrap = 0x%0x\n",eax);
		};


        //if (count41==3){
			//printf("eax=%x\n",eax);
			//print_big(0);
			//printf("ogo rekursiya\n");
			//exit(1);
		//};


		//if (count41==2){
		//	printf("eax=%x\n",eax);
		//	exit(1);
		//};
		

        //edi = 009a82b0
        //ecx = 07800000
        //edi = 009a82c0
        //ecx = 27ba0000
        //edi = 009a82c0
        //ecx = 05b177e0

		//edi=table_ptr+0x58
		//tmp=edi+4

		//schitali iz tablici 0x02(posle 0x07)
		tmp=edi+4;
		esp_table=(unsigned char *)tmp;
		ecx=esp_table[3]*256*256*256+esp_table[2]*256*256+esp_table[1]*256+esp_table[0];
        //ecx=(unsigned int)tmp[0]; //mov ecx, [edi+4]

		
		//printf("ecx=%x\n",ecx);
		//exit(0);
        //ecx=2 // ecx=1

        ebp=1;

        edx=ebp;


		//sdcvinuli 1 << 2
		//edx=4
        edx=edx << ecx;

		//printf("edx=%x\n",edx);
		//printf("eax=%x\n",eax);
		//exit(1);

        //eax=04//10//4

		//eax=1
		//edx=4
		//vihodim,,
        if (eax < edx) {
				if (DEBUG) {
					printf("End: mysub_some_math_41_get_next_byte\n");
				};
                return eax;
        };



        //eax=4
        //edi=009a82b0 edi+8=009a82b8 (01 00 00 00)
        //eax=10
        //edi=009a82c0 edi+8=009a82c8 (00 00 00 00)
        //                              00 00


		//schitivaem sled byte , 0x01

		tmp=edi+8;
		esp_table=(unsigned char *)tmp;
		tmp=esp_table[3]*256*256*256+esp_table[2]*256*256+esp_table[1]*256+esp_table[0];
        
		//iz granichnogo index2, vichitaem 1		
		eax=eax - tmp; //sub eax, [edi+8]

		

		//printf("tmp=%x\n",tmp);
		//printf("eax=%x\n",eax);
		//exit(1);

        //eax=3
        //eax=10
        //eax=4


        esi=eax;
        //esi=3
        //esi=10
        //esi=4

		//schitivaem iz 0x58
		//eto 0x07

        //edi=009a82b0
        //edi=009a82c0
        //edi=009a82c0
        //eax=edi;//mov eax,[edi]
		tmp=edi;
		esp_table=(unsigned char *)tmp;
		eax=esp_table[3]*256*256*256+esp_table[2]*256*256+esp_table[1]*256+esp_table[0];

		//printf("eax=%x\n",eax);
		//exit(1);

        //eax=0x07
        //eax=0x10
        //eax=0x10

        if (count41==3){
			//printf("eax=%x\n",eax);
			//printf("esi=%x\n",esi);
			//print_big(0);
			//printf("ogo rekursiya\n");
			//exit(1);
		};



		//if granichniy index2 - 1 < 0x07(table_ptr+0x58)
		//0<7

        if (esi < eax) {

				//iz granichniy index2 eshe vichitaem 1
                esi--;
                //esi=2//3

				//printf("esi=%x\n",esi);
				//exit(0);

                edi=0;

                ecx=esi;
                //ecx=2//3

				//1-cu sdvigaem vlevo na granichniy index2(s vichetami) t.e. *2^ecx 
				//1<<ecx

                ebp=ebp << ecx; //ecx=2//ebp=1
                //ebp=4//8

				//printf("ebp=%x\n",ebp);
				//exit(0);

				//esli granichniy index2 stal <=0 vihodim vozvrashaem
				//0x07(table_ptr+0x58)

                if (esi<=0) {

						if (DEBUG) {
							printf("End: mysub_some_math_41_get_next_byte\n");
						};

                        return eax;
                };


				//cikl

                do {

                        //ebx=big

                        //esi=2//3
                        ebx=esi;
                        //ebx=2//3

                        //edi=0;

						//iz granichniy index2 vichitaem nul

                        ebx=ebx-edi;
                        //2//3

						//esli granichniy index2 > 0x10, to granichniy index2 = 0x10

                        if (ebx > 0x10) {
                                ebx=0x10;
                        };

                        //ecx=esp_10; //ecx==big

                        //ebx=2//3

						//printf("ebx=%x\n",ebx);
						//exit(0);

                        //push ebx
				        //if (count41==3){
						//	printf("ebx=%x\n",ebx);
						//	exit(0);
						//};

						//parametr granichniy index2

                        eax=mysub_some_math_42(ebx);

						//eax -- ostatok ot deleniya
						//big.off_4 / (big.off_8 >> granichniy index2) , tolko celoe

						//printf("eax=%x\n",eax);
						//exit(0);

						//tolko 2 byte

                        //eax=0
                        eax=eax & 0x0ffff;
                        //eax=0

                        //edi=0
                        ecx=edi;
                        //ecx=0

						//sdvig ostatka ot deleniya na nul pri pervom cikle

                        eax=eax << ecx;


						//cikl kounter= cikl kounter + granichniy index2(-2)

                        //edi=0
                        //ebx=2
                        edi=edi+ebx;
                        //edi=2


						//1-cu sdvinutaya vlevlo + ostatok ot deleniya
						
                        //ebp=4
                        //eax=0
                        ebp=ebp+eax;
                        //ebp=4
						//if (count41==3){
						//	printf("ebp=%x\n",ebp);
						//	exit(0);
						//};

						//poka cikl kounter < granichniy index2, t.e. odin cikl obichno

						//printf("edi=%x\n",edi);
						//printf("esi=%x\n",esi);
						//exit(0);
                }while( edi < esi );

				//vihodim, vozvrashaem 
				//1-cu sdvigaem vlevo na granichniy index2(s vichetami) t.e. *2^ecx 
				//1-cu sdvinutaya vlevlo + ostatok ot deleniya:
				//big.off_4 / (big.off_8 >> granichniy index2) , tolko celoe

                //ebp=4
                //ebp=8
                eax=ebp;
                //eax=4
                //eax=8

                //pop ..

				//printf("eax=%x\n",eax);
				//exit(0);

				if (DEBUG) {
					printf("End: mysub_some_math_41_get_next_byte\n");
				};

                return eax;
        }else{

                //mov eax, esp_1c;
				//esp_1c=0; // ??
				esp_1c=hz;
                eax=esp_1c;
                //eax=0;

                if (eax==0) {


                        // push ebp //ebp=1
                        // push edi //009a82c0

                        //ecx=ebx; ecx=big;

                        // !!! REKURSIYA !!!
                        //mysub_some_math_41_get_next_byte(ebp,edi);
				        //if (count_wrap==3){
						//	printf("edi=%08x\n",edi);
						//	printf("ebp=%08x\n",ebp);
						//	exit(0);
						//};

					
					    if (count41==2){
							print_big(0);
							if (DEBUG) {
								printf("BEF recusrion\n");
								printf("edi=%08x\n",edi);
								printf("ebp=%08x\n",ebp);
							};
						};


						eax=mysub_some_math_41_get_next_byte(edi,ebp);


				        if (count41==3){
							if (DEBUG) {
								printf("AFT recusrion\n");
							};
							print_big(0);
							//printf("edi=%08x\n",edi);
							//printf("ebp=%08x\n",ebp);
							//exit(0);
						};


                        //mov edi, [edi]
                        //edi=edi;//0x10;
						tmp=edi;
						esp_table=(unsigned char *)tmp;
						edi=esp_table[3]*256*256*256+esp_table[2]*256*256+esp_table[1]*256+esp_table[0];


                        //esi=10
                        //eax=8
                        esi=eax;
                        //esi=8

                        eax=0x20;

                        eax=eax-edi;
                        //eax=0x10;

                        //esi=8
                        //eax=10

                        if ( esi > eax ) {
                                // pop edi
                                big.off_202=ebp;
                                // pop
                                eax=0;
								if (DEBUG) {
									printf("End: mysub_some_math_41_get_next_byte\n");
								};

                                return eax;
                        };

				        //if (count41==3){
						//	printf("esi=%08x\n",esi);
						//	printf("edi=%08x\n",edi);
						//	exit(0);
						//};

                        //esi=8
                        //edi=10
                        esi=esi+edi;
                        //esi=18

                        esi--;
                        //esi=17

                        edi=0;

                        ecx=esi;
                        //ecx=17;


                        //ebp=1
                        ebp=ebp << ecx; //ecx=17
                        //ebp=0;

				        //if (count41==3){
						//	printf("ebp=%08x\n",ebp);
						//	exit(0);
						//};

                        if (esi > 0) {

                                do {

                                        //vtoroy cikl
                                        //ebx=big

                                        //esi=17//17
                                        ebx=esi;

                                        //edi=0//10
                                        ebx=ebx-edi;
                                        //ebx=17//7


                                        if (ebx > 0x10){

                                                ebx=0x10;
                                        };


										//if (count41==3){
										//	printf("ebx=%08x\n",ebx);
										//	exit(1);
										//};


										//esp_10=0; //??? big
                                        //ecx=esp_10; //esp=02a9ef54
										
                                        //ecx=big

                                        //ebx=10
                                        //ebx=7
                                        //push ebx

                                        eax=mysub_some_math_42(ebx);

										//if (count41==3){
										//	printf("eax=%08x\n",eax);
										//	exit(1);
										//};

                                        //eax=0x37ac
                                        //eax=28
                                        eax=eax & 0x0ffff;
                                        //eax=0x37ac
                                        //eax=28

                                        //ecx=10
                                        //edi=0
                                        //edi=10
                                        //mov ecx, edi
                                        ecx=edi;
                                        //ecx=0
                                        //ecx=10

                                        eax=eax << ecx; //ecx=0//10
                                        //eax=37ac
                                        //eax=00280000

                                        //edi = 0
                                        //ebx=10
                                        //edi=10
                                        //ebx=7
                                        edi=edi+ebx;
                                        //edi = 10
                                        //edi = 17

                                        //ebp=0
                                        //eax=0x000037ac
                                        //ebp=0x000037ac
                                                 //? 0x008037ac
                                        //eax=0x00280000
                                        ebp=ebp+eax;

										if (count41==3){
											//printf("ebp=%08x\n",ebp);
										//	exit(1);
										};

                                        //ebp=0x37ac
                                        //ebp=0x00a837ac
                        //AAAAGGGGAAAA !!AAAA!!!!!!!!!!!!!!!!!!!AAAAAAAA ZDES!
										//printf("zdes ? ebp=%x\n",ebp);
										

                                        //esi=17
                                        //edi=10
										if (count41==3){
											//printf("edi=%08x\n",edi);
											//printf("esi=%08x\n",esi);
											//exit(1);
										};

                                } while( edi < esi );  //dva raza

                                //eax=00a837ac
                                eax=ebp;
                                //pop

								if (DEBUG) {
									printf("End: mysub_some_math_41_get_next_byte\n");
								};

                                return eax;

                        };

                        eax=ebp;
                        //pop

						if (DEBUG) {
							printf("End: mysub_some_math_41_get_next_byte\n");
						};

						return eax;


                }else {
                        //pop edi
                        //
                        big.off_202=1;
                        //pop
                        eax=0;

						if (DEBUG) {
							printf("End: mysub_some_math_41_get_next_byte\n");
						};

                        return eax;

                };

        };

		if (DEBUG) {
			printf("End: mysub_some_math_41_get_next_byte\n");
		};

		return eax;
};

/*
* na vhod granichniy index2(no uje s -2)
* vizivaem mysub_some_math_get_next_byte_cikl
* no tak kak big.off_8 > 0x00800000, srazu vihodim byti ne schitivaem , vsegda li ?
* masku sdvigaem vpravo na granichniy index (/2^..) , 
* big.off_8 >> granichniy index2
* shifrovanniy byte delim na to chto poluchilos posle sdviga vpravo big.off_8 na granichniy index
* big.off_4 / (big.off_8 >> granichniy index2) , tolko celoe
* v edx ostatok ot deleniya 
* ops, proebli ostatok ot deleniya, dalshe ne ispolzuetsya
* celoe poluchivsheesya posle deleniya sdvigaem vpravo(/2^gran index2) na granichniy index2
* esli posle sdviga ostatok ne 0, to
*    (1<<granich index2) - 1
*    i celoe poluchivsheesya posle deleniya = (1<<granich index2) - 1
*    t.e. eto max znachenie bolshe nego nizzya
* celoe poluchivsheesya posle deleniya, s proverkoy na max
* celoe s proverkoy na max * (big.off_8 >> granichniy index2)
*
* iz big.off_4 vichitam celoe posle umnojeniya
* big.off_4 = big.off_4 - (celoe s proverkoy na max * (big.off_8 >> granichniy index2))
* sohranyem v big.off_4
*
* esli ((ostatok ot deleniya bez sdvigov + 1) >> granichniy index2) ==0 , 
* to      big.off_8=big.off_8 >> granichniy index2
* inache  big.off_8=big.off_8 - celoe posle umnojeniya(toje chto i vichli iz big.off_4)
*
* vozvrashaet eax -- ostatok ot deleniya bez sdvigov
*
*/

int mysub_some_math_42(unsigned int ebx1) {
        unsigned int ecx,eax,edx,ebx,edi,ebp;
		unsigned int tmp;      
        unsigned int esp_14;

		
		
		count42++;

		if (DEBUG) {
			printf("Run: mysub_some_math_42: %d\n",count42);
		};

		

        // push ..

        //ecx=big
        //esi=ecx;

        mysub_some_math_get_next_byte_cikl();
             //pochti srazu vihodim

		//print_big(1);

        ebp=big.off_8;
        //ebp=009ee800
        //ebp=00c40e81
        //ebp=1881d000
        //ebp=18810000

        //esp=02a9ef3c, esp+14=02a9ef50
        //mov ecx,[esp+14]
		esp_14=ebx1;
        ecx=esp_14;
        
        //ecx=2
        //ecx=3
        //ecx=10
        //ecx=7

        //mov ebx,[esi+4]
        ebx=big.off_4;
        //ebx=0023b437
        //ebx=00055435
        //ebx=05543558
        //ebx=07ac0000

        edi=ebp;
        //edi=009ee800
        //edi=00c40e81
        //edi=1881d000
        //edi=18810000
	

		//edi -- big.off_8 //The Mask
		//ecx -- granichniy index2(no uje s -2)

		
		//sdvigaem vpravo na granichniy index /2
		//big.off_8 >> granichniy index2

        edi = edi >> ecx; //cl=2 //cl=3 //cl=10 //cl=7

        //eax=07
        eax=ebx;
        //eax=0023b437
        //eax=00055435
        //eax=05543558
        //eax=07ac0000

        edx=0;

        //eax=0023b437
        //edi=0027ba00
        //eax=00055435
        //edi=001881d0
        //eax=05543558
        //edi=00001881
        //eax=07ac0000
        //edi=00310200

        // dx:ax delitsya na esi , chastnoe sohranaetsya v ax, ostatok v dx

		//shifrovanniy byte delim na to chto poluchilos posle sdviga vpravo big.off_8 na granichniy index
		//big.off_4 / (big.off_8 >> granichniy index2), tolko celoe
		//v edx ostatok ot deleniya

        tmp=eax / edi;
        edx=eax % edi;
		eax=tmp;
        //div edi
        //eax=0
        //edx=0023b437
        //eax=0
        //edx=00055435
        //eax=37ac
        //edx=07ac
        //eax=0028
        //edx=0003b000

		//printf("eax=%x\n",eax);
		//printf("edx=%x\n",edx);
		//exit(0);

		//ops, proebli ostatok ot deleniya, dalshe ne ispolzuetsya

        edx=eax;
        //edx=0
        //edx=37ac
        //edx=0028


		//celoe poluchivsheesya posle deleniya sdvigaem vpravo(/2^gran index2) na granichniy index2

        edx=edx >> ecx; ////cl=2 //cl=10 //cl=7
        //edx=0;

		//esli posle sdviga ostatok ne 0, to

        if (edx != 0){
                eax=1;
                eax=eax << ecx;
                eax--;
        };


		//celoe poluchivsheesya posle deleniya, s proverkoy na max

        edx=eax;
        // edx=0
        // edx=000037ac
        //edx=28



		//granichniy index2

        //esp=02a9ef3c esp+14=02a9ef50
        //esp=02a9ef3c
        //esp=02a9ef3c
        //mov ecx,[esp+14]
        ecx=esp_14;
        //ecx=2
        //ecx=3
        //ecx=10
        //ecx=7


		//celoe s proverkoy na max * (big.off_8 >> granichniy index2)

        //edx=0 , edi=0027ba00
        //edx=0 edi=0x001881d0
        //edx=000037ac edi=00001881
        //edx=28,      edi=00310200
        // imul -- signed multiply
        edx=edx * edi;
        //edx=eax * edi; //ili eto ??
        //imul edx,edi
        //edx=0
        //edx=0
        //edx=05542dac
        //edx=07a85000


		//iz big.off_4 vichitam celoe posle umnojeniya
		//big.off_4 = big.off_4 - (celoe s proverkoy na max * (big.off_8 >> granichniy index2))
		//sohranyem v big.off_4

        //ebx=0023b437
        //ebx=05542dac
        //sub ebx,edx
        ebx=ebx-edx;
        //ebx=0023b437
        //ebx=000007ac
        //ebx=0003b000

        //esi == big_struct==02a9f1e4
        //mov [esi+4], ebx
        big.off_4=ebx;
        //0023b437
        //00055435
        //000007ac
        //0003b000


		//esli ((ostatok ot deleniya bez sdvigov + 1) >> granichniy index2) ==0 , 
		//to      big.off_8=big.off_8 >> granichniy index2
		//inache  big.off_8=big.off_8 - celoe posle umnojeniya(toje chto i vichli iz big.off_4)


        //eax=0
        //lea ebx,[eax+1]
        ebx=eax+1;
        //ebx=1
        //ebx=37ad
        //ebx=29

        ebx=ebx >> ecx; //cl=2 //cl=3 //cl=7
        //ebx=0;

        if (ebx==0) {
                //esi=big_struct

                //edi=0027ba00
                //edi=001881d0
                //edi=00310200
                //mov [esi+8],edi
                big.off_8=edi;
                //pop ..
        }else {
           ;
          //..
			ebp=ebp-edx;
			big.off_8=ebp;
        };



		if (DEBUG) {
			printf("End: mysub_some_math_42\n");
		};

		//ostatok ot deleniya bez sdvigov

		return eax;
};


int mygen_no_call_00850F30(unsigned int off) {
        unsigned int eax,edx;
        unsigned int esi;
        unsigned int esp_8;


		if (DEBUG) {
			printf("Run: mygen_no_call_00850F30\n");
		};

        // ecx=big_struct

        //mov edx,[ecx+20e]
        edx=big.off_20e;
        //edx=02a9f740

        //push esi
        //esp = 02a9ef68

        //mov esi,[esp+8]  //esp=02a9ef68
		esp_8=off;
        esi=esp_8;
        //esi=0x14

        //edx=02a9f740
        //mov eax,[edx]
		eax=edx;//from init 0x0004b000;
        //eax=0004b000

        //esi=0x14
        //cmp eax,esi
        if (eax>=esi) {

                //eax=0x04b000
                //esi=14
                //sub eax,esi
                //eax=0x0004afec
                eax=eax-esi;

				//printf("eax=%x\n",eax);
				//exit(0);
				
                // pop esi;

                //edx=02a9f740
                //mov [edx],eax
                //edx=eax;
				big.off_20e=eax;

                //mov eax,1
                eax=1;

        }else{

                //ecx=big_struct
                //mov [ecx+202],1
                big.off_202=1;
                //eax=0;
                //pop esi

        };

		if (DEBUG) {
			printf("End: mygen_no_call_00850F30\n");
		};

	    return eax;
};



