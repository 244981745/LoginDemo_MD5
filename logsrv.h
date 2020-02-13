#ifndef	_GAMESRV_H
#define	_GAMESRV_H

#define	true 1
#define	flase 0

int buffDecoder(const unsigned char *buffer, unsigned char *Region1, unsigned char *Region2, int *flag);
int logOnSrv(SOCKET clientfd, char *UserName, char *UserPwd);


#endif
