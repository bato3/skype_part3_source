//
// Socket communication
//

#include <stdio.h>
#include <stdlib.h>

#include <winsock2.h>  

unsigned int tcpsock;
int tcpconnected=0;


int tcp_talk_init() {

	tcpconnected=0;

	return 0;
};

int tcp_talk_deinit() {

	shutdown(tcpsock,2);
	closesocket(tcpsock);

	tcpconnected=0;

	return 0;
};

//
// unified tcp communication, send buffer, and place retrived data into result.
int tcp_talk(char *remoteip, unsigned short remoteport, char *buf, int len, char *result, int maxlen, int need_close) {
	int ret, ret2;
	struct sockaddr_in addr;
	WSADATA wsaDATA;
	char tmpbuf[8192];
	fd_set rfds;
	struct timeval tv;
	unsigned int iMode;
	int nError;

	tv.tv_sec=1;
	tv.tv_usec=0;


	if (tcpconnected==0) {

		if (WSAStartup(MAKEWORD(2,0),&wsaDATA)!=0){
			//printf("WSAStartup error. Error: %d\n",WSAGetLastError());
			return -1;
		};

		tcpsock=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
		if (tcpsock==-1) {
			//printf("Socket creation error\n");
			return -1;
		};

		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr=inet_addr(remoteip);
		addr.sin_port=htons(remoteport);

		iMode=1;//non block enable
		ioctlsocket(tcpsock, FIONBIO, &iMode);

		ret=connect(tcpsock, (struct sockaddr*)&addr, sizeof(addr));

		Sleep(1000);

		nError=WSAGetLastError();
		
		if ( (nError!=WSAEWOULDBLOCK) && (nError!=0) ){
			//printf("Connect failed\n");
			//printf("ret=0x%08X\n",ret);
			//printf("nError=0x%08X\n",nError);
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
		//printf("Send error\n");
		//printf("conn timeout\n");
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

			printf("ret2: %d\n",ret2);

			if (ret2<0){
				//printf("Recv error\n");
				//shutdown(tcpsock,2);
				//closesocket(tcpsock);
				//tcpconnected=0;
				return -1;
			};

			if ( (ret+ret2) < maxlen) {
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

	if (need_close) {
		shutdown(tcpsock,2);
		closesocket(tcpsock);
		tcpconnected=0;
	};
	

	return ret;
};

