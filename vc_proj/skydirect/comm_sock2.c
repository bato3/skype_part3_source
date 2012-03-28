//
// Socket communication
//

#include <stdio.h>
#include <stdlib.h>

#include <winsock2.h>  

unsigned int tcp2sock;
int tcp2connected=0;


int tcp2_talk_init() {

	printf("tcp2_talk_init called\n");

	tcp2connected=0;

	return 0;
};

int tcp2_talk_deinit() {

	printf("tcp2_talk_deinit called\n");

	shutdown(tcp2sock,2);
	closesocket(tcp2sock);

	tcp2connected=0;

	return 0;
};

//
// tcp2_talk
//
// unified tcp communication, send buffer, and place retrived data into result.
//
int tcp2_talk(char *remoteip, unsigned short remoteport, char *buf, int len, char *result, int maxlen, int need_close) {
	int ret, ret2;
	struct sockaddr_in addr;
	WSADATA wsaDATA;
	char tmpbuf[4096];
	fd_set rfds;
	struct timeval tv;
	unsigned int iMode;
	int nError;

	tv.tv_sec=1;
	tv.tv_usec=0;


	if (tcp2connected==0) {

		if (WSAStartup(MAKEWORD(2,0),&wsaDATA)!=0){
			//printf("WSAStartup error. Error: %d\n",WSAGetLastError());
			return -1;
		};

		tcp2sock=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
		if (tcp2sock==-1) {
			//printf("Socket creation error\n");
			return -1;
		};

		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr=inet_addr(remoteip);
		addr.sin_port=htons(remoteport);

		iMode=1;//non block enable
		ioctlsocket(tcp2sock, FIONBIO, &iMode);

		ret=connect(tcp2sock, (struct sockaddr*)&addr, sizeof(addr));

		Sleep(1000);

		nError=WSAGetLastError();
		
		if ( (nError!=WSAEWOULDBLOCK) && (nError!=0) ){
			//printf("Connect failed\n");
			//printf("ret=0x%08X\n",ret);
			//printf("nError=0x%08X\n",nError);
			iMode=0;//non block enable
			ioctlsocket(tcp2sock, FIONBIO, &iMode);
			shutdown(tcp2sock,2);
			closesocket(tcp2sock);
			tcp2connected=0;
			return 0;
		};

		iMode=0;//non block enable
		ioctlsocket(tcp2sock, FIONBIO, &iMode);

		tcp2connected=1;
	};
	

	ret=send(tcp2sock, buf, len, 0);
	if (ret < 0) {
		//printf("Send error\n");
		//printf("conn timeout\n");
		shutdown(tcp2sock,2);
		closesocket(tcp2sock);
		tcp2connected=0;
		return -2;
	};

    
	FD_ZERO(&rfds);
	FD_SET(tcp2sock, &rfds);

	ret=0;
	ret2=0;
	do {
		select(tcp2sock+1, &rfds, NULL, NULL, &tv);
		if(FD_ISSET(tcp2sock, &rfds)){
			memset(tmpbuf,0,sizeof(tmpbuf)-1);
			ret2=recv(tcp2sock, tmpbuf, sizeof(tmpbuf)-1, 0);

			//printf("ret2: %d\n",ret2);

			if (ret2<0){
				//printf("Recv error\n");
				//shutdown(tcp2sock,2);
				//closesocket(tcp2sock);
				//tcp2connected=0;
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
		shutdown(tcp2sock,2);
		closesocket(tcp2sock);
		tcp2connected=0;
	};
	

	return ret;
};



int tcp2_talk_sock(int *getsock, char *remoteip, unsigned short remoteport, char *buf, int len, char *result, int maxlen, int need_close) {
	int ret, ret2;
	struct sockaddr_in addr;
	WSADATA wsaDATA;
	char tmpbuf[4096];
	fd_set rfds;
	struct timeval tv;
	unsigned int iMode;
	int nError;

	tv.tv_sec=1;
	tv.tv_usec=0;


	if (tcp2connected==0) {

		if (WSAStartup(MAKEWORD(2,0),&wsaDATA)!=0){
			//printf("WSAStartup error. Error: %d\n",WSAGetLastError());
			return -1;
		};

		tcp2sock=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
		if (tcp2sock==-1) {
			//printf("Socket creation error\n");
			return -1;
		};

		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr=inet_addr(remoteip);
		addr.sin_port=htons(remoteport);

		iMode=1;//non block enable
		ioctlsocket(tcp2sock, FIONBIO, &iMode);

		ret=connect(tcp2sock, (struct sockaddr*)&addr, sizeof(addr));

		Sleep(1000);

		nError=WSAGetLastError();
		
		if ( (nError!=WSAEWOULDBLOCK) && (nError!=0) ){
			//printf("Connect failed\n");
			//printf("ret=0x%08X\n",ret);
			//printf("nError=0x%08X\n",nError);
			shutdown(tcp2sock,2);
			closesocket(tcp2sock);
			tcp2connected=0;
			return 0;
		};

		iMode=0;//non block enable
		ioctlsocket(tcp2sock, FIONBIO, &iMode);

		tcp2connected=1;
	};
	

	printf("tcp2sock sock_comm2 tcp_talk_sock: 0x%08X\n",tcp2sock);

	ret=send(tcp2sock, buf, len, 0);
	if (ret < 0) {
		//printf("Send error\n");
		//printf("conn timeout\n");
		shutdown(tcp2sock,2);
		closesocket(tcp2sock);
		tcp2connected=0;
		return -2;
	};

    
	FD_ZERO(&rfds);
	FD_SET(tcp2sock, &rfds);

	ret=0;
	ret2=0;
	do {
		select(tcp2sock+1, &rfds, NULL, NULL, &tv);
		if(FD_ISSET(tcp2sock, &rfds)){
			memset(tmpbuf,0,sizeof(tmpbuf)-1);
			ret2=recv(tcp2sock, tmpbuf, sizeof(tmpbuf)-1, 0);

			//printf("ret2: %d\n",ret2);

			if (ret2<0){
				//printf("Recv error\n");
				//shutdown(tcp2sock,2);
				//closesocket(tcp2sock);
				//tcp2connected=0;
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
		shutdown(tcp2sock,2);
		closesocket(tcp2sock);
		tcp2connected=0;
	};
	
	*getsock=tcp2sock;

	return ret;
};



//
// tcp2_talk_recv
//
// unified tcp communication, place retrived data into result.
//
int tcp2_talk_recv(char *remoteip, unsigned short remoteport, char *result, int maxlen, int need_close) {
	int ret;
	struct sockaddr_in addr;
	WSADATA wsaDATA;
	int cnt=0;
	


	if (tcp2connected==0) {

		if (WSAStartup(MAKEWORD(2,0),&wsaDATA)!=0){
			//printf("WSAStartup error. Error: %d\n",WSAGetLastError());
			return -1;
		};

		tcp2sock=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
		if (tcp2sock==-1) {
			//printf("Socket creation error\n");
			return -1;
		};

		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr=inet_addr(remoteip);
		addr.sin_port=htons(remoteport);

		ret=connect(tcp2sock, (struct sockaddr*)&addr, sizeof(addr));
		if (ret < 0) {
			//printf("Connect failed\n");
			return -1;
		};

		tcp2connected=1;
	};


	cnt=recv(tcp2sock, result, maxlen, 0);


	if (cnt<0){
		//printf("Recv error\n");
		return -1;
	};


	if (need_close) {
		shutdown(tcp2sock,2);
		closesocket(tcp2sock);
		tcp2connected=0;
	};
	

	return cnt;
};


//
// tcp2_talk_recv_sock
//
int tcp2_talk_recv_sock(int *retsock, char *result, int maxlen, int need_close) {
	int cnt=0;
	int cnt2=0;
	int int_sock;

	char tmpbuf[8192];

	//int_sock=*retsock;

	int_sock=tcp2sock;

	printf("int_sock: 0x%08X\n",int_sock);
	printf("tcp2sock: 0x%08X\n",tcp2sock);

	printf("result ptr: 0x%08X\n",&result);
	printf("maxlen: 0x%08X\n",maxlen);

	memset(tmpbuf,0,sizeof(tmpbuf));
	cnt=recv(tcp2sock, tmpbuf, maxlen, 0);
	if (cnt<0){
		printf("Recv error: %d\n",cnt);
		printf("Error: recv, Error code %d\n",WSAGetLastError());
		return -1;
	};

	memcpy(result,tmpbuf,cnt);

	if (cnt<=5){

		memset(tmpbuf,0,sizeof(tmpbuf));
		cnt2=recv(tcp2sock, tmpbuf, maxlen, 0);
		memcpy(result+cnt,tmpbuf,cnt2);
		cnt=cnt+cnt2;

	};


	if (need_close) {
		shutdown(int_sock,2);
		closesocket(int_sock);
		tcp2connected=0;
	};
	

	return cnt;
};

//
// tcp2_talk_send_sock
//
int tcp2_talk_send_sock(char *confirm, unsigned int confirm_len, int need_close) {
	int ret=0;


	printf("tcp2sock: 0x%08X\n",tcp2sock);

	printf("confirm ptr: 0x%08X\n",&confirm);
	printf("confirm_len: 0x%08X\n",confirm_len);

	ret=send(tcp2sock, confirm, confirm_len, 0);
	if (ret < 0) {
		printf("Send error\n");
		printf("conn timeout\n");
		shutdown(tcp2sock,2);
		closesocket(tcp2sock);
		tcp2connected=0;
		return -1;
	};


	if (need_close) {
		shutdown(tcp2sock,2);
		closesocket(tcp2sock);
		tcp2connected=0;
	};
	

	return 1;
};
