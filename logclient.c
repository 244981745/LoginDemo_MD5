#include <stdio.h>
#include <winsock.h>
#include <winsock2.h>
#include "logclient.h"
#include "MD5/MD5.h"
#include "MD5/MD5.c"

int buffDecoder(const unsigned char *buffer, char *Region1, char *Region2, int *flag)
{
	int offset = 2;
	int len	=	0;

	*flag	=	(int)buffer[0];
	
	int i,j;
	i	=	(int)buffer[1];
	
	if( i < 0 )	return -1;
	if( i > 3 )	return -1;
	
	if( i > 0)
	{
		len	=	(int)buffer[offset++];
		for( j = 0; j < len; j++)
			Region1[j]	=	buffer[offset++];
		Region1[j]	=	'\0';
	}
	
	if( i > 1)
	{
		len	=	(int)buffer[offset++];
		for( j = 0; j < len; j++)
			Region2[j]	=	buffer[offset++];
		Region2[j]	=	'\0';
	}
	
	return 0;
}

int userLogOn(SOCKET srvfd, const char *userName, const char *userPwd)
{
	int flag=0,token = 0;
	unsigned char len;
	unsigned char sendBuf[1024];
	unsigned char recvBuf[1024];
	unsigned char region1[256];
	unsigned char region2[256];
	memset((void *)sendBuf, '\0', 1024);
	memset((void *)recvBuf, '\0', 1024);
	memset((void*)region1, '\0', 256);
	memset((void*)region2, '\0', 256);
	
	sendBuf[0]	=	0x1;	// logonflag
	sendBuf[1]	=	0x2;	//section

	len	=	strlen(userName);
	sendBuf[strlen(sendBuf)]	=	len;
	strcat(sendBuf,userName);
	
	len	=	strlen(userPwd);
	sendBuf[strlen(sendBuf)]	=	len;
	strcat(sendBuf,userPwd);

	send(srvfd,sendBuf,strlen(sendBuf),0);
	
	recv(srvfd,recvBuf,1024,0);
	
	buffDecoder(recvBuf,region1,region2,&flag);

	
	int i;
//	for(i = 0; i < 10; i++)
//		printf("%x ",recvBuf[i]);
//	printf("\n");
	if(flag == 0x80) return -1;
	else
	{
		token	=	region1[0]&&0xff;
		token<<8;
		token	|=	region1[1]&&0xff;
		token<<8;
		token	|=	region1[2]&&0xff;
		token<<8;
		token	|=	region1[3]&&0xff;
	}
//	printf("token :%d\n",token);

	return 1;
}

int userLogIn(SOCKET srvfd, const char *userName, const char *userPwd)
{
	int flag=0,token = 0;
	unsigned char len;
	unsigned char sendBuf[1024];
	unsigned char recvBuf[1024];
	unsigned char region1[256];
	unsigned char region2[256];
	unsigned char *md5Pwd;
	
	memset((void *)sendBuf, '\0', 1024);
	memset((void *)recvBuf, '\0', 1024);
	memset((void*)region1, '\0', 256);
	memset((void*)region2, '\0', 256);
	
	sendBuf[0]	=	0x2;	// loginflag
	sendBuf[1]	=	0x2;	//section

	len	=	strlen(userName);
	sendBuf[strlen(sendBuf)]	=	len;
	strcat(sendBuf,userName);
	
	md5Pwd	=	malloc(MD5SIZE);
	memset((void*)md5Pwd, '\0', MD5SIZE);
	
	len	=	strlen(userPwd);
	MD5(userPwd,len,md5Pwd);
	len	=	strlen(md5Pwd);
	sendBuf[strlen(sendBuf)]	=	len;
	strcat(sendBuf,md5Pwd);

	send(srvfd,sendBuf,strlen(sendBuf),0);
	
	recv(srvfd,recvBuf,1024,0);
	
	buffDecoder(recvBuf,region1,region2,&flag);

	
	int i;
	for(i = 0; i < 10; i++)
		printf("%x ",recvBuf[i]);
	printf("\n");
	if(flag == 0x80) return -1;
	else
	{
		token	=	region1[0]&&0xff;
		token<<8;
		token	|=	region1[1]&&0xff;
		token<<8;
		token	|=	region1[2]&&0xff;
		token<<8;
		token	|=	region1[3]&&0xff;
	}
//	printf("token :%d\n",token);

	return 1;
}


int main(int argc, char **argv)
{
	WSADATA	wsadata;
	if( WSAStartup( MAKEWORD(2,2), &wsadata ) != 0 )
	{
		printf("Winsock load faild!\n");
		return -1;
	}
	
	int port		= 9527;
	const char *srvip = "127.0.0.1";
	struct sockaddr_in srvaddr;
    memset(&srvaddr,	sizeof(&srvaddr),	0);
	srvaddr.sin_family = AF_INET;
    srvaddr.sin_addr.S_un.S_addr = inet_addr(srvip);
    srvaddr.sin_port = htons( port );
    
	SOCKET srvfd = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP );
    if(srvfd < 0)
    {
            printf("socket error.\n");
            WSACleanup();
            exit;
    }
    
    //  连接服务器
    if ( connect(srvfd, (struct sockaddr *)&srvaddr, sizeof(struct sockaddr)) == SOCKET_ERROR )
	{
        printf( "connect faild!\n" );
        closesocket(srvfd);
        WSACleanup();
        return -1;
    }
    else
    {
    	printf("connect success.\n");
    }
	int ret = -1; 
	ret	=	userLogIn(srvfd,"user","password");
//	printf("%d\n",ret);

	Sleep(1000);
	closesocket(srvfd);
	WSACleanup();
	
	return 0;
}

