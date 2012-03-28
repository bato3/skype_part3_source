// pktsniff.c : Defines the entry point for the console application.
//


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <winsock2.h>

#include "pcap.h"
#include "short_types.h"


extern int process_tcp_recv(FILE *fp, char *pkt, int pkt_len, u32 srcip, u16 sport, u32 destip, u16 dport);
extern int process_tcp_send(FILE *fp, char *pkt, int pkt_len, u32 srcip, u16 sport, u32 destip, u16 dport);

extern int process_udp_recv(FILE *fp, char *pkt, int pkt_len, u32 srcip, u16 sport, u32 destip, u16 dport);
extern int process_udp_send(FILE *fp, char *pkt, int pkt_len, u32 srcip, u16 sport, u32 destip, u16 dport);

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

int session_udp_count=0;
int session_tcp_count=0;
int DEBUG=1;

//#define FILTER_STRING "ip"
//#define FILTER_PORT 33864

#define FILTER_STRING "udp port 33864"
#define FILTER_PORT 33864

//#define FILTER_STRING "udp port 33999"
//#define FILTER_PORT 33999


//#define FILTER_STRING "host 165.230.143.72"



// my external ip
u8 MY_ADDR[0x100]="95.52.192.106";


#define TCP_PROTO 6
#define UDP_PROTO 17


/* IPv4 header */
typedef struct ip_header{
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service 
    u_short tlen;           // Total length 
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    u_int   saddr;      // Source address
    u_int   daddr;      // Destination address
    u_int   op_pad;         // Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header{
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_short len;            // Datagram length
    u_short crc;            // Checksum
}udp_header;

/* TCP header */
#define TH_OFF(th)	(((th)->offx2 & 0xf0) >> 4)
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)

typedef struct tcp_header {
		u_short sport;	/* source port */
		u_short dport;	/* destination port */
		u_int   seq;	/* sequence number */
		u_int   ack;	/* acknowledgement number */

		u_char  offx2;	/* data offset, rsvd */
		u_char  flags;

		u_short win;	/* window */
		u_short sum;	/* checksum */
		u_short urg;	/* urgent pointer */
}tcp_header;


/*
#if BYTE_ORDER == LITTLE_ENDIAN
    u_int th_x2:4,    // (unused)
    th_off:4;         // data offset
#endif
#if BYTE_ORDER == BIG_ENDIAN
    u_int th_off:4,   // data offset
    th_x2:4;          //(unused)
#endif
*/



//
// show memory with ascii
//
int show_memory_withascii(FILE *fp, char *mem, int len, char *text){
	int zz;
	int i;
	int k;
	char b[16+1];
	int t;

	//if(DEBUG_LEVEL>=100) {
		fprintf(fp,"%s\n",text);
		fprintf(fp,"Len: 0x%08X\n",len);
		fprintf(fp," ");
		zz=0;
		k=0;
		b[16]=0;
		for(i=0;i<len;i++){
			fprintf(fp,"%02X ",mem[i] & 0xff);
			t=mem[i] & 0xff;
			if ((t>=0x20) && (t<=0x7f)){
				memcpy(b+k,mem+i,1);
			}else{
				memcpy(b+k,"\x20",1);
			};
			zz++;
			k++;
			if (zz == 16) { 
				zz=0;
				k=0;
				fprintf(fp," ; %s",b);
				fprintf(fp,"\n ");
			};
		};

		if (zz<16) {
			b[zz]=0;
			for (i=zz;i<16;i++){
				fprintf(fp,"   ");
			};
			fprintf(fp," ; %s",b);
		};

		fprintf(fp,"\n");
	//};

	return 0;
};

//
//
//
int flags_to_string(u_char flags, char *str_flags){

		strcpy(str_flags,"");

		if (flags & TH_FIN) {
			strcat(str_flags,"FIN|");
		};
		if (flags & TH_SYN) {
			strcat(str_flags,"SYN|");
		};
		if (flags & TH_RST) {
			strcat(str_flags,"RST|");
		};
		if (flags & TH_PUSH) {
			strcat(str_flags,"PUSH|");
		};
		if (flags & TH_ACK) {
			strcat(str_flags,"ACK|");
		};
		if (flags & TH_URG) {
			strcat(str_flags,"URG|");
		};
		if (flags & TH_ECE) {
			strcat(str_flags,"ECE|");
		};
		if (flags & TH_CWR) {
			strcat(str_flags,"CWR|");
		};

		strcat(str_flags,"");


	return 0;
};



//
// Setup handler
//
int setup_dump_handler(char *card_vendor){
	pcap_if_t *alldevs;
	pcap_if_t *d;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fcode;
	bpf_u_int32 netmask;

	int found;

	
	if(pcap_findalldevs(&alldevs, errbuf) == -1) {
		printf("Error in pcap_findalldevs: %s\n", errbuf);
		return -1;
	}
	
	found=0;
	for(d=alldevs; d; d=d->next) {	
		if (strstr(d->description, card_vendor) != NULL) {
			found=1;
			break;
		};
	}

	if (!found){
		printf("Error, network card by vendor - %s - not found\n", card_vendor);
		return -1;
	};
	
	
	if ((adhandle= pcap_open_live(d->name,	// name of the device
							 65536,			// portion of the packet to capture. 
											// 65536 grants that the whole packet will be captured on all the MACs.
							 1,				// promiscuous mode (nonzero means promiscuous)
							 1000,			// read timeout
							 errbuf			// error buffer
							 )) == NULL) {

		printf("Unable to open the adapter. %s is not supported by WinPcap\n", d->name);

		pcap_freealldevs(alldevs);
		return -1;
	}
	

	if (d->addresses != NULL)
        netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        netmask=0xffffff; 


    if (pcap_compile(adhandle, &fcode, FILTER_STRING, 1, netmask) < 0){
	//if (pcap_compile(adhandle, &fcode, "tcp port 80", 1, netmask) < 0){
	
		printf("Unable to compile the packet filter. Check the syntax.\n");

        pcap_freealldevs(alldevs);
        return -1;
    }
    
    if (pcap_setfilter(adhandle, &fcode) < 0) {

        printf("Error setting the filter.\n");
        
		pcap_freealldevs(alldevs);
        return -1;
    }

	printf("Listening on interface:\n");
	printf("%s\n", d->description);

	pcap_freealldevs(alldevs);

	pcap_loop(adhandle, 0, packet_handler, NULL);

	pcap_close(adhandle);



	return 0;
}


//
// Handler callback from pcap
//
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
	struct tm *ltime;
	char timestr[16];
	time_t local_tv_sec;
	
	ip_header *iph;
    udp_header *udph;
    tcp_header *tcph;
    u_int ip_len;
    u_int tcp_len;
    u_int udp_len;
    u_int payload_len;
	u_int full_pkt_len;
	u_int eth_trail_len;
    u_short sport,dport;
	char *payload;
	char str_flags[1024];
	char str_srcip[1024];
	char str_destip[1024];
	struct in_addr src_addr;
	struct in_addr dest_addr;

	FILE *fp;


	fp=fopen("_logs.txt","a");

	local_tv_sec = header->ts.tv_sec;
	ltime=localtime(&local_tv_sec);
	strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
	
	fprintf(fp,"%s,%.6d len:%d (0x%08X)\n", timestr, header->ts.tv_usec, header->len, header->len);
	fprintf(stdout,"%s,%.6d len:%d (0x%08X)\n", timestr, header->ts.tv_usec, header->len, header->len);

	if (header->len != header->caplen) {
		fprintf(fp,"len != caplen\n");
		fprintf(stdout,"len != caplen\n");
		return ;
	};


	// 14 - ethernet header frame
    iph = (ip_header *) (pkt_data + 14);

	if ((iph->proto!=UDP_PROTO) && (iph->proto!=TCP_PROTO)){
		fprintf(fp,"Unknown protocol: %d\n",iph->proto);
		fprintf(stdout,"Unknown protocol: %d\n",iph->proto);
		return ;
	};


	if (iph->proto==UDP_PROTO) {

		ip_len = (iph->ver_ihl & 0xf) * 4;
		udph = (udp_header *) ((u_char*)iph + ip_len);

		udp_len = ntohs(udph->len);
		if (udp_len < 8) {
			fprintf(fp,"Invalid UDP header length: %u bytes\n", udp_len);
			fprintf(stdout,"Invalid UDP header length: %u bytes\n", udp_len);
			return;
		}
	
	
		payload = (u_char *)(pkt_data + 14 + ip_len + 8);
		payload_len = ntohs(iph->tlen) - (ip_len + 8);

		if (payload_len != (udp_len - 8)) {
			fprintf(fp,"Invalid len calculations, payload len %d, udp_len %d\n", payload_len, udp_len);
			fprintf(stdout,"Invalid len calculations, payload len %d, udp_len %d\n", payload_len, udp_len);
			return;
		};

		//fprintf(fp,"ptr bef: 0x%08X ptr aft: 0x%08X diff: 0x%08X\n", pkt_data, payload, payload-pkt_data );
		//fprintf(stdout,"ptr bef: 0x%08X ptr aft: 0x%08X diff: 0x%08X\n", pkt_data, payload, payload-pkt_data );
	
		fprintf(fp,"Payload %d (0x%08X) bytes:\n", payload_len, payload_len);
		fprintf(stdout,"Payload %d (0x%08X) bytes:\n", payload_len, payload_len);
		

		sport = ntohs( udph->sport );
		dport = ntohs( udph->dport );


		src_addr.s_addr=iph->saddr;
		dest_addr.s_addr=iph->daddr;

		strcpy(str_srcip,  inet_ntoa(src_addr)  );
		strcpy(str_destip, inet_ntoa(dest_addr) );

		fprintf(fp,"UDP: %s:%d -> %s:%d\n", str_srcip, sport, str_destip, dport);
		fprintf(stdout,"UDP: %s:%d -> %s:%d\n", str_srcip,	sport, str_destip, dport);


		if (payload_len != 0) {
			show_memory_withascii(fp,payload,payload_len,"Data:");
			show_memory_withascii(stdout,payload,payload_len,"Data:");			

			if (strncmp(str_srcip,"192.168.1.20",12)==0){
				process_udp_send(fp,payload,payload_len,iph->saddr,sport,iph->daddr,dport);
			}else{
				process_udp_recv(fp,payload,payload_len,iph->saddr,sport,iph->daddr,dport);
			};

			//if (dport==FILTER_PORT) {
				//fprintf(fp,"src port=%d\n",sport);
				//fprintf(stdout,"src port=%d\n",sport);
				//process_udp_recv(fp,payload,payload_len,iph->saddr,sport,iph->daddr,dport);
			//};

			//if (sport==FILTER_PORT) {
				//fprintf(fp,"dest port=%d\n",dport);
				//fprintf(stdout,"dest port=%d\n",dport);
				//process_udp_send(fp,payload,payload_len,iph->saddr,sport,iph->daddr,dport);
			//};


		};


		full_pkt_len=14 + ip_len + 8 + payload_len;

		if (full_pkt_len != header->len){

			if (header->len > full_pkt_len) {
				eth_trail_len = header->len - full_pkt_len;
				fprintf(fp,"Ethernet trailer: %d (0x%08X) bytes\n",eth_trail_len,eth_trail_len);
				fprintf(stdout,"Ethernet trailer: %d (0x%08X) bytes\n",eth_trail_len,eth_trail_len);
			}else {
				eth_trail_len = full_pkt_len - header->len;
				fprintf(fp,"!!! Not all data in this pkt !!! Not found %d (0x%08X) bytes\n",eth_trail_len,eth_trail_len);
				fprintf(stdout,"!!! Not all data in this pkt !!! Not found %d (0x%08X) bytes\n",eth_trail_len,eth_trail_len);
			};

		}

		fprintf(fp,"::::::::::::::::::::::::::::::::\n");
		fprintf(stdout,"::::::::::::::::::::::::::::::::\n");


	};



	if (iph->proto==TCP_PROTO) {

		ip_len = (iph->ver_ihl & 0xf) * 4;
		tcph = (tcp_header *) ((u_char*)iph + ip_len);

		tcp_len = TH_OFF(tcph)*4;
		if (tcp_len < 20) {
			fprintf(fp,"Invalid TCP header length: %u bytes\n", tcp_len);
			fprintf(stdout,"Invalid TCP header length: %u bytes\n", tcp_len);
			return;
		}
	
	
		payload = (u_char *)(pkt_data + 14 + ip_len + tcp_len);
		payload_len = ntohs(iph->tlen) - (ip_len + tcp_len);


		//fprintf(fp,"ptr bef: 0x%08X ptr aft: 0x%08X diff: 0x%08X\n", pkt_data, payload, payload-pkt_data );
		//fprintf(stdout,"ptr bef: 0x%08X ptr aft: 0x%08X diff: 0x%08X\n", pkt_data, payload, payload-pkt_data );
	
		fprintf(fp,"Payload %d (0x%08X) bytes:\n", payload_len, payload_len);
		fprintf(stdout,"Payload %d (0x%08X) bytes:\n", payload_len, payload_len);
		

		sport = ntohs( tcph->sport );
		dport = ntohs( tcph->dport );


		flags_to_string(tcph->flags, (char *)&str_flags);


		if (strlen((char *)str_flags)>0){
			fprintf(fp,"%s\n",str_flags);
			fprintf(stdout,"%s\n",str_flags);
		};


		src_addr.s_addr=iph->saddr;
		dest_addr.s_addr=iph->daddr;

		strcpy(str_srcip,  inet_ntoa(src_addr)  );
		strcpy(str_destip, inet_ntoa(dest_addr) );

		fprintf(fp,"TCP: %s:%d -> %s:%d\n", str_srcip, sport, str_destip, dport);
		fprintf(stdout,"TCP: %s:%d -> %s:%d\n", str_srcip,	sport, str_destip, dport);


		if (payload_len != 0) {
			show_memory_withascii(fp,payload,payload_len,"Data:");
			show_memory_withascii(stdout,payload,payload_len,"Data:");


			if (strncmp(str_srcip,"192.168.1.20",12)==0){
				process_tcp_send(fp,payload,payload_len,iph->saddr,sport,iph->daddr,dport);
			}else{
				process_tcp_recv(fp,payload,payload_len,iph->saddr,sport,iph->daddr,dport);
			};


			//process_tcp(payload,payload_len);
			//if (dport==FILTER_PORT) {
				//fprintf(fp,"src port=%d\n",sport);
				//fprintf(stdout,"src port=%d\n",sport);
				//process_tcp_recv(fp,payload,payload_len,iph->saddr,sport,iph->daddr,dport);
			//};

			//if (sport==FILTER_PORT) {
				//fprintf(fp,"dest port=%d\n",dport);
				//fprintf(stdout,"dest port=%d\n",dport);

				//process_tcp_send(fp,payload,payload_len,iph->saddr,sport,iph->daddr,dport);
			//};

		};


		full_pkt_len=14 + ip_len + tcp_len + payload_len;

		if (full_pkt_len != header->len){

			if (header->len > full_pkt_len) {
				eth_trail_len = header->len - full_pkt_len;
				fprintf(fp,"Ethernet trailer: %d (0x%08X) bytes\n",eth_trail_len,eth_trail_len);
				fprintf(stdout,"Ethernet trailer: %d (0x%08X) bytes\n",eth_trail_len,eth_trail_len);
			}else {
				eth_trail_len = full_pkt_len - header->len;
				fprintf(fp,"!!! Not all data in this pkt !!! Not found %d (0x%08X) bytes\n",eth_trail_len,eth_trail_len);
				fprintf(stdout,"!!! Not all data in this pkt !!! Not found %d (0x%08X) bytes\n",eth_trail_len,eth_trail_len);
			};

		}

		fprintf(fp,"::::::::::::::::::::::::::::::::\n");
		fprintf(stdout,"::::::::::::::::::::::::::::::::\n");

	};

	fclose(fp);


	return ;
	
}



int main(int argc, char* argv[]) {
	int ret;
	FILE *fp;

	fp=fopen("_logs.txt","w");
	fprintf(fp,"\n");
	fclose(fp);
	
	// upper-lowercase sensitive !!!
	ret = setup_dump_handler("Realtek");
	if (ret!=0){
		printf("Handler setup error\n");
	};

	
	return 0;
}

