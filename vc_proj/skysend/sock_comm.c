//
// Socket communication
//

#include <stdio.h>
#include <stdlib.h>

#include <winsock.h>  

//int tcpsock;
//int tcpconnected=0;

int sock;
int connected=0;

#define BUF_SIZE 8192

extern unsigned int DEBUG_LEVEL;


////////////////////////////////////////////////
// sockets related                            //
////////////////////////////////////////////////

//unified udp communication, send buffer, and place retrived data into result.
int udp_talk(char *remoteip, unsigned short remoteport, char *buf, int len, char *result){
	int sock, ret, addrlen;
	struct sockaddr_in addr;
	WSADATA wsaDATA;
	char tmpbuf[1024];
	fd_set rfds;
	struct timeval tv;

	tv.tv_sec=5;
	tv.tv_usec=0;

	if (WSAStartup(MAKEWORD(2,0),&wsaDATA)!=0){
		if (DEBUG_LEVEL>=100) printf("WSAStartup error. Error: %d\n",WSAGetLastError());
	};

	sock=socket(PF_INET,SOCK_DGRAM,IPPROTO_UDP);
	if (sock==-1) {
		if (DEBUG_LEVEL>=100) printf("Socket creation error\n");
		return -1;
	};

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr=inet_addr(remoteip);
	addr.sin_port=htons(remoteport);

	ret=sendto(sock, buf, len, 0, (struct sockaddr*)&addr, sizeof(addr));
	if (ret < 0) {
		if (DEBUG_LEVEL>=100) printf("Sendto error\n");
		return -1;
	};

	addrlen=sizeof(addr);
	memset(tmpbuf,0,sizeof(tmpbuf));

    FD_ZERO(&rfds);
	FD_SET(sock, &rfds);
	
	select(sock+1, &rfds, NULL, NULL, &tv);

    if(FD_ISSET(sock, &rfds)){
		if (ret=recvfrom(sock, tmpbuf, 1023, 0, (struct sockaddr*)&addr, &addrlen)){
			memcpy(result, tmpbuf, ret);
		};
		if (ret<0){
			if (DEBUG_LEVEL>=100) printf("Recvfrom error\n");
			return -1;
		};
	}else{ 
			//timeout
			return 0;
	};

	shutdown(sock,2);
	closesocket(sock);
	

	return ret;
};

/*

//
// unified tcp communication, send buffer, and place retrived data into result.
int tcp_talk(char *remoteip, unsigned short remoteport, char *buf, int len, char *result,int need_close) {
	int ret, ret2;
	struct sockaddr_in addr;
	WSADATA wsaDATA;
	char tmpbuf[BUF_SIZE];
	fd_set rfds;
	struct timeval tv;
	unsigned int iMode;
	int nError;

	tv.tv_sec=5;
	tv.tv_usec=0;


	if (tcpconnected==0) {

		if (WSAStartup(MAKEWORD(2,0),&wsaDATA)!=0){
			if(DEBUG_LEVEL>=100) printf("WSAStartup error. Error: %d\n",WSAGetLastError());
			return -1;
		};

		tcpsock=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
		if (tcpsock==-1) {
			if(DEBUG_LEVEL>=100) printf("Socket creation error\n");
			return -1;
		};

		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr=inet_addr(remoteip);
		addr.sin_port=htons(remoteport);

		iMode=1;//non block enable
		ioctlsocket(tcpsock, FIONBIO, &iMode);

		ret=connect(tcpsock, (struct sockaddr*)&addr, sizeof(addr));

		Sleep(3000);

		nError=WSAGetLastError();
		
		if ( (nError!=WSAEWOULDBLOCK) && (nError!=0) ){
			
			if(DEBUG_LEVEL>=100) printf("Connect failed\n");			
			if(DEBUG_LEVEL>=100) printf("ret=0x%08X\n",ret);
			if(DEBUG_LEVEL>=100) printf("nError=0x%08X\n",nError);

			shutdown(tcpsock,2);
			closesocket(tcpsock);
			tcpconnected=0;
			return 0;
		};

		iMode=0;//non block enable
		ioctlsocket(tcpsock, FIONBIO, &iMode);

		tcpconnected=1;
	};
	

	ret=send(tcpsock, buf, len, 0);
	if (ret < 0) {
		
		if(DEBUG_LEVEL>=100) printf("Send error\n");
		if(DEBUG_LEVEL>=100) printf("conn timeout\n");

		shutdown(tcpsock,2);
		closesocket(tcpsock);
		tcpconnected=0;
		return -2;
	};

    
	FD_ZERO(&rfds);
	FD_SET(tcpsock, &rfds);

	ret=0;
	ret2=0;
	do {
		select(tcpsock+1, &rfds, NULL, NULL, &tv);
		if(FD_ISSET(tcpsock, &rfds)){
			memset(tmpbuf,0,sizeof(tmpbuf)-1);
			ret2=recv(tcpsock, tmpbuf, sizeof(tmpbuf)-1, 0);

			if(DEBUG_LEVEL>=100) printf("ret2: %d\n",ret2);

			if (ret2<0){
				if(DEBUG_LEVEL>=100) printf("Recv error\n");
				//shutdown(tcpsock,2);
				//closesocket(tcpsock);
				//tcpconnected=0;
				return -1;
			};

			if ( (ret+ret2) < BUF_SIZE) {
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

	//if (ret==0){
		//timeout
		//return -2;
		//return 
	//};

	if (need_close) {
		shutdown(tcpsock,2);
		closesocket(tcpsock);
		tcpconnected=0;
	};
	

	return ret;
};

*/




//unified tcp communication, send buffer, and place retrived data into result.
int tcp_talk(char *remoteip, unsigned short remoteport, char *buf, int len, char *result,int need_close) {
	int ret;
	struct sockaddr_in addr;
	WSADATA wsaDATA;
	char tmpbuf[BUF_SIZE];
	int cnt=0;
	int cnt2=0;
	


	if (connected==0) {

		if (WSAStartup(MAKEWORD(2,0),&wsaDATA)!=0){
			if(DEBUG_LEVEL>=100) printf("WSAStartup error. Error: %d\n",WSAGetLastError());
		};

		sock=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
		if (sock==-1) {
			if (DEBUG_LEVEL>=100) printf("Socket creation error\n");
			return -1;
		};

		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr=inet_addr(remoteip);
		addr.sin_port=htons(remoteport);

		ret=connect(sock, (struct sockaddr*)&addr, sizeof(addr));
		if (ret < 0) {
			if (DEBUG_LEVEL>=100) printf("Connect failed\n");
			return -1;
		};

		connected=1;
	};
	

	ret=send(sock, buf, len, 0);
	if (ret < 0) {
		if (DEBUG_LEVEL>=100) printf("Send error\n");
		return -1;
	};

	memset(tmpbuf,0,sizeof(tmpbuf));
	cnt=recv(sock, tmpbuf, sizeof(tmpbuf), 0);
	memcpy(result,tmpbuf,cnt);
	if (cnt<=5){
		memset(tmpbuf,0,sizeof(tmpbuf));
		cnt2=recv(sock, tmpbuf, sizeof(tmpbuf), 0);
		memcpy(result+cnt,tmpbuf,cnt2);
		cnt=cnt+cnt2;
	};


	if (cnt<0){
		if (DEBUG_LEVEL>=100) printf("Recv error\n");
		return -1;
	};


	if (need_close) {
		shutdown(sock,2);
		closesocket(sock);
		connected=0;
	};
	

	return cnt;
};

