//
// tcp1socket communication
//

#include <stdio.h>
#include <stdlib.h>

#include <winsock.h>  
#include "short_types.h"


#define BUF_SIZE 0x2000


extern unsigned int DEBUG_LEVEL;



/////////////////////////////////////////////////////////////////////////////////
//
// udpn 
//
/////////////////////////////////////////////////////////////////////////////////
int udpn_talk(char *remoteip, unsigned short remoteport, char *buf, int buf_len, char *result, int result_len){
	int s, ret, addrlen;
	struct sockaddr_in addr;
	fd_set rfds;
	struct timeval tv;

	tv.tv_sec=5;
	tv.tv_usec=0;


	s=socket(PF_INET,SOCK_DGRAM,IPPROTO_UDP);
	if (s==-1) {
		if (DEBUG_LEVEL>=100) printf("UDP Socket creation error\n");
		return -1;
	};
	if (DEBUG_LEVEL>=100) printf("udp socket: 0x%08X\n",s);


	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr=inet_addr(remoteip);
	addr.sin_port=htons(remoteport);
	addrlen=sizeof(addr);
		
	ret=sendto(s, buf, buf_len, 0, (struct sockaddr*)&addr, addrlen);
	if (ret < 0) {
		if (DEBUG_LEVEL>=100) printf("Sendto error\n");
		shutdown(s,2);
		closesocket(s);
		return -1;
	};

	memset(result,0,result_len);

    FD_ZERO(&rfds);
	FD_SET(s, &rfds);
	
	select(s+1, &rfds, NULL, NULL, &tv);

    if(FD_ISSET(s, &rfds)){
	 	ret=recvfrom(s, result, result_len, 0, (struct sockaddr*)&addr, &addrlen);
		if (ret<0){			
			if (DEBUG_LEVEL>=100) printf("Recvfrom error\n");
			//10054 - Connection reset by peer
			if (DEBUG_LEVEL>=100) printf("Error: recvfrom, Error code %d\n",WSAGetLastError());
			shutdown(s,2);
			closesocket(s);
			return -1;
		};
	}else{ 
			//timeout
			return 0;
	};



	shutdown(s,2);
	closesocket(s);
	

	return ret;
};



/////////////////////////////////////////////////////////////////////////////////
//
// tcpn
//
/////////////////////////////////////////////////////////////////////////////////

int tcpn_talk_init(int *getsock, char *remoteip, unsigned short remoteport) {
	int s, ret;
	WSADATA wsaDATA;
	struct sockaddr_in addr;
	unsigned int iMode;
	int nError;

	s=-1;
	if (DEBUG_LEVEL>=100) printf("tcpn_talk_init called\n");

	if (1) {

		if (WSAStartup(MAKEWORD(2,0),&wsaDATA)!=0){
			if (DEBUG_LEVEL>=100) printf("WSAStartup error. Error: %d\n",WSAGetLastError());
			return -1;
		};

		s=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
		if (s==-1) {
			if (DEBUG_LEVEL>=100) printf("Socket creation error\n");
			return -1;
		};

		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr=inet_addr(remoteip);
		addr.sin_port=htons(remoteport);

		iMode=1;//non block enable
		ioctlsocket(s, FIONBIO, &iMode);

		ret=connect(s, (struct sockaddr*)&addr, sizeof(addr));

		Sleep(1000);

		nError=WSAGetLastError();
		
		if ( (nError!=WSAEWOULDBLOCK) && (nError!=0) ){
			//printf("Connect failed\n");
			//printf("ret=0x%08X\n",ret);
			//printf("nError=0x%08X\n",nError);
			shutdown(s,2);
			closesocket(s);
			return 0;
		};

		iMode=0;//non block enable
		ioctlsocket(s, FIONBIO, &iMode);

	};

	*getsock=s;

	return 1;
};

int tcpn_talk_deinit(int *getsock) {
	int s;

	s=*getsock;

	if (DEBUG_LEVEL>=100) printf("tcpn_talk_deinit called\n");

	shutdown(s,2);
	closesocket(s);

	*getsock=-1;

	return 0;
};

//
// tcpn_talk
//
int tcpn_talk(int *getsock,char *remoteip,u16 remoteport,char *buf,int buf_len,char *result,int result_len){
	int s, ret, ret2;
	char tmpbuf[BUF_SIZE];
	fd_set rfds;
	struct timeval tv;

	tv.tv_sec=5;
	tv.tv_usec=0;

	s=*getsock;

	

	if (DEBUG_LEVEL>=100) printf("tcpn_talk s: 0x%08X\n",s);

	ret=send(s, buf, buf_len, 0);
	if (ret < 0) {
		//printf("Send error\n");
		//printf("conn timeout\n");
		//shutdown(s,2);
		//closesocket(s);
		return -2;
	};

    
	FD_ZERO(&rfds);
	FD_SET(s, &rfds);

	ret=0;
	ret2=0;
	do {
		select(s+1, &rfds, NULL, NULL, &tv);
		if(FD_ISSET(s, &rfds)){
			memset(tmpbuf,0,sizeof(tmpbuf)-1);
			ret2=recv(s, tmpbuf, sizeof(tmpbuf)-1, 0);

			if (DEBUG_LEVEL>=100) printf("ret2: %d\n",ret2);

			if (ret2<0){
				if (DEBUG_LEVEL>=100) printf("Recv error\n");
				//shutdown(s,2);
				//closesocket(s);
				return -1;
			};

			if ( (ret+ret2) < result_len) {
				memcpy(result+ret,tmpbuf,ret2);
				ret=ret+ret2;
			}else{
				//buffer overflow
				ret2=0;
			};
		}else{
			//recv timeout
			ret2=0;
		};

	}while(ret2>0);

	if (ret==0){
		//timeout
		return -2;
	};
	
	*getsock=s;

	return ret;
};





//
// tcpn_talk_recv
//
int tcpn_talk_recv(int *getsock, char *result, int result_len) {
	int s, ret, ret2;
	char tmpbuf[BUF_SIZE];
	fd_set rfds;
	struct timeval tv;

	tv.tv_sec=2;
	tv.tv_usec=0;

	s=*getsock;

	

	if (DEBUG_LEVEL>=100) printf("tcpn_talk_recv: 0x%08X\n",s);

    
	FD_ZERO(&rfds);
	FD_SET(s, &rfds);

	ret=0;
	ret2=0;
	do {
		select(s+1, &rfds, NULL, NULL, &tv);
		if(FD_ISSET(s, &rfds)){
			memset(tmpbuf,0,sizeof(tmpbuf)-1);
			ret2=recv(s, tmpbuf, sizeof(tmpbuf)-1, 0);

			if (DEBUG_LEVEL>=100) printf("ret2: %d\n",ret2);

			if (ret2<0){
				if (DEBUG_LEVEL>=100) printf("Recv error\n");
				//shutdown(s,2);
				//closesocket(s);
				return -1;
			};

			if ( (ret+ret2) < result_len) {
				memcpy(result+ret,tmpbuf,ret2);
				ret=ret+ret2;
			}else{
				//buffer overflow
				ret2=0;
			};
		}else{
			//recv timeout
			ret2=0;
		};

	// hack
	if (ret2==11){
		ret2=0;
	};

	}while(ret2>0);

	if (ret==0){
		//timeout
		return -2;
	};
	
	*getsock=s;

	return ret;
};

//
// tcpn_talk_recv2
//
int tcpn_talk_recv2(int *getsock, char *result, int result_len) {
	int s, ret, ret2;
	char tmpbuf[BUF_SIZE];

	s=*getsock;

	if (DEBUG_LEVEL>=100) printf("tcpn_talk_recv2: 0x%08X\n",s);
    
	memset(tmpbuf,0,sizeof(tmpbuf));
	ret=recv(s, tmpbuf, sizeof(tmpbuf), 0);
	if (ret<0){
		printf("Recv error: %d\n",ret);
		printf("Error: recv, Error code %d\n",WSAGetLastError());
		return -1;
	};

	memcpy(result,tmpbuf,ret);


	ret2=0;
	if (ret<=5){
		memset(tmpbuf,0,sizeof(tmpbuf));
		ret2=recv(s, tmpbuf, sizeof(tmpbuf), 0);
		memcpy(result+ret,tmpbuf,ret2);
		ret=ret+ret2;
	};


	if (ret2<0){
		if (DEBUG_LEVEL>=100) printf("Recv error\n");
		//shutdown(s,2);
		//closesocket(s);
		return -1;
	};

	if (ret==0){
		//timeout
		return -2;
	};
	
	*getsock=s;

	return ret;
};


//
// tcpn_talk_send
//
int tcpn_talk_send(int *getsock, char *confirm, unsigned int confirm_len) {
	int ret;
	int s;

	s=*getsock;

	if (DEBUG_LEVEL>=100) printf("tcpn_talk_send s: 0x%08X\n",s);

	if (DEBUG_LEVEL>=100) printf("confirm ptr: 0x%08X\n",&confirm);
	if (DEBUG_LEVEL>=100) printf("confirm_len: 0x%08X\n",confirm_len);

	ret=send(s, confirm, confirm_len, 0);
	if (ret < 0) {
		if (DEBUG_LEVEL>=100) printf("Send error\n");
		if (DEBUG_LEVEL>=100) printf("conn timeout\n");
		//shutdown(s,2);
		//closesocket(s);
		return -1;
	};


	*getsock=s;
	

	return 1;
};

