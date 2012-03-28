//
// tcp1socket communication
//

#include <stdio.h>
#include <stdlib.h>

#include <winsock.h>  


int tcp1sock;
int tcp1connected=0;

#define BUF_SIZE 8192

extern unsigned int DEBUG_LEVEL;
extern int tcp2sock;
extern int tcp2connected;


////////////////////////////////////////////////
// tcp1sockets related                            //
////////////////////////////////////////////////

//unified udp communication, send buffer, and place retrived data into result.
int udp1_talk(char *remoteip, unsigned short remoteport, char *buf, int len, char *result){
	int tcp1sock, ret, addrlen;
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

	tcp1sock=socket(PF_INET,SOCK_DGRAM,IPPROTO_UDP);
	if (tcp1sock==-1) {
		if (DEBUG_LEVEL>=100) printf("socket creation error\n");
		return -1;
	};

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr=inet_addr(remoteip);
	addr.sin_port=htons(remoteport);

	ret=sendto(tcp1sock, buf, len, 0, (struct sockaddr*)&addr, sizeof(addr));
	if (ret < 0) {
		if (DEBUG_LEVEL>=100) printf("Sendto error\n");
		return -1;
	};

	addrlen=sizeof(addr);
	memset(tmpbuf,0,sizeof(tmpbuf));

    FD_ZERO(&rfds);
	FD_SET(tcp1sock, &rfds);
	
	select(tcp1sock+1, &rfds, NULL, NULL, &tv);

    if(FD_ISSET(tcp1sock, &rfds)){
		if (ret=recvfrom(tcp1sock, tmpbuf, 1023, 0, (struct sockaddr*)&addr, &addrlen)){
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

	shutdown(tcp1sock,2);
	closesocket(tcp1sock);
	

	return ret;
};





//unified tcp communication, send buffer, and place retrived data into result.
int tcp1_talk(char *remoteip, unsigned short remoteport, char *buf, int len, char *result,int need_close) {
	int ret;
	struct sockaddr_in addr;
	WSADATA wsaDATA;
	char tmpbuf[BUF_SIZE];
	int cnt=0;
	int cnt2=0;
	

	tcp1sock=tcp2sock;

	tcp1connected=tcp2connected;
	
	printf("tcp1sock=0x%08X\n",tcp1sock);
	printf("tcp1connected=%d\n",tcp1connected);


	if (tcp1connected==0) {

		if (WSAStartup(MAKEWORD(2,0),&wsaDATA)!=0){
			if(DEBUG_LEVEL>=100) printf("WSAStartup error. Error: %d\n",WSAGetLastError());
		};

		tcp1sock=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
		if (tcp1sock==-1) {
			if (DEBUG_LEVEL>=100) printf("socket creation error\n");
			return -1;
		};

		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr=inet_addr(remoteip);
		addr.sin_port=htons(remoteport);

		ret=connect(tcp1sock, (struct sockaddr*)&addr, sizeof(addr));
		if (ret < 0) {
			if (DEBUG_LEVEL>=100) printf("Connect failed\n");
			return -1;
		};

		tcp1connected=1;
	};
	

	ret=send(tcp1sock, buf, len, 0);
	if (ret < 0) {
		if (DEBUG_LEVEL>=100) printf("Send error\n");
		return -1;
	};

	Sleep(1000);

	memset(tmpbuf,0,sizeof(tmpbuf));
	cnt=recv(tcp1sock, tmpbuf, sizeof(tmpbuf), 0);
	memcpy(result,tmpbuf,cnt);
	if (cnt<=5){
		memset(tmpbuf,0,sizeof(tmpbuf));
		cnt2=recv(tcp1sock, tmpbuf, sizeof(tmpbuf), 0);
		memcpy(result+cnt,tmpbuf,cnt2);
		cnt=cnt+cnt2;
	};


	if (cnt<0){
		if (DEBUG_LEVEL>=100) printf("Recv error\n");
		return -1;
	};


	if (need_close) {
		shutdown(tcp1sock,2);
		closesocket(tcp1sock);
		tcp1connected=0;
	};
	

	return cnt;
};



//unified tcp communication, send buffer, and place retrived data into result.
int tcp1_talk_recv(char *result,int need_close) {
	char tmpbuf[BUF_SIZE];
	int cnt=0;
	int cnt2=0;
	

	tcp1sock=tcp2sock;


	memset(tmpbuf,0,sizeof(tmpbuf));
	cnt=recv(tcp1sock, tmpbuf, sizeof(tmpbuf), 0);
	memcpy(result,tmpbuf,cnt);
	if (cnt<=5){
		memset(tmpbuf,0,sizeof(tmpbuf));
		cnt2=recv(tcp1sock, tmpbuf, sizeof(tmpbuf), 0);
		memcpy(result+cnt,tmpbuf,cnt2);
		cnt=cnt+cnt2;
	};


	if (cnt<0){
		if (DEBUG_LEVEL>=100) printf("Recv error\n");
		return -1;
	};


	if (need_close) {
		shutdown(tcp1sock,2);
		closesocket(tcp1sock);
		tcp1connected=0;
	};
	

	return cnt;
};


